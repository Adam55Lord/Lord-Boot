// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Adam55Lord

//! The LXF/LLF loader: the UEFI-hosted equivalent of `run_lord.py` (lxf_tools v3).
//!
//! For every module it
//!   1. reads the file from the ESP and parses/validates it (`lxf.rs`),
//!   2. allocates one `LOADER_CODE` block for the whole image (RVA 0 .. end of the last section) and
//!      copies every mapped section to its RVA (UEFI has no page protection to apply: the W^X rules
//!      of the format are validated, not enforced, in this hosted mode),
//!   3. applies `.reloc` (ABS64 / ABS32 / REL32 / RVA32) for the block's real address,
//!   4. resolves `.impdir`: loads the named `.llf` from the ESP root and writes the export address
//!      into the import's IAT slot,
//!   5. calls `libmain(1)` (dependencies first); a non-zero result aborts the load and runs
//!      `libmain(0)` on everything already initialised.
//!
//! ## ABI seen by LXF code (System V AMD64, as in the format spec; Rust: `extern "sysv64"`)
//!
//! * executable entry: `int entry(long argc, char **argv, char **envp, const LxfBootInfo *info)`
//!   (`rdi, rsi, rdx, rcx`). `argv[0]` is the file name; `eax` is the exit status. The fourth argument
//!   is a Lord Boot extension that ordinary programs ignore.
//! * library main:     `int libmain(long reason, const LxfBootInfo *info)`
//!   (`rdi` = reason: 1 = load, 0 = unload; `rsi` = info; return 0 on success)
//!
//! `LxfBootInfo` (all fields 8-byte aligned, offsets in bytes):
//!
//! | off | field          | meaning                                                  |
//! |-----|----------------|----------------------------------------------------------|
//! |  0  | magic: u64     | `"LXFBOOT\0"` = 0x00544F4F4246584C (LE)                  |
//! | 8   | version: u32   | 2 (1 was the Microsoft-x64 ABI of the old v1 loader)     |
//! | 12  | size: u32      | size of this struct (40)                                 |
//! | 16  | put_str        | `void put_str(const char *s, u64 len)` (**sysv64**)       |
//! | 24  | system_table   | `EFI_SYSTEM_TABLE *`                                     |
//! | 32  | image_handle   | `EFI_HANDLE` of the bootloader                           |
//!
//! Not honoured in hosted mode: `stack_size` (the program runs on the firmware stack) and
//! `preferred_base` (the block is wherever UEFI puts it; ABS32 relocations force it below 2 GiB).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::fmt;
use core::ptr::NonNull;

use uefi::boot::{self, AllocateType, MemoryType};
use uefi::fs::{FileSystem, PathBuf};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CString16, println};

use crate::lxf::{LxfError, LxfImage, RELOC_ABS32};

const PAGE_SIZE: usize = 4096;
const MAX_DEPTH: usize = 16;

pub const BOOTINFO_MAGIC: u64 = u64::from_le_bytes(*b"LXFBOOT\0");
pub const BOOTINFO_VERSION: u32 = 2;

pub type PutStr = extern "sysv64" fn(*const u8, usize);

#[repr(C)]
pub struct LxfBootInfo {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub put_str: PutStr,
    pub system_table: *const c_void,
    pub image_handle: *const c_void,
}

type ExeEntry = extern "sysv64" fn(i64, *const *const u8, *const *const u8, *const LxfBootInfo) -> i32;
type LibMain = extern "sysv64" fn(i64, *const LxfBootInfo) -> i32;

pub enum LoadError {
    Uefi(uefi::Error),
    Fs(String),
    Parse(String, LxfError),
    BadName(String),
    NotAnExecutable,
    /// A kernel (LKF) was named where a program or library is needed.
    NotAProgram(String),
    /// An import names something that is not a library (`.llf`).
    NotALibrary(String),
    /// `libmain(1)` returned non-zero.
    LibMain { name: String, rc: i32 },
    MissingExport { lib: String, func: String },
    TooDeep(String),
    /// Something went wrong while booting a kernel image.
    Kernel(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uefi(e) => write!(f, "UEFI error: {e:?}"),
            Self::Fs(m) => write!(f, "file error: {m}"),
            Self::Parse(n, e) => write!(f, "{n}: invalid Lord file: {e}"),
            Self::BadName(n) => write!(f, "refusing library name {n:?}"),
            Self::NotAnExecutable => write!(f, "file is a library (.llf), not an executable"),
            Self::NotAProgram(n) => write!(f, "{n} is a kernel image (LKF); the bootloader boots kernels from kernel.lkf only"),
            Self::NotALibrary(n) => write!(f, "{n} is imported but is not a library (LLF)"),
            Self::LibMain { name, rc } => write!(f, "{name}: libmain(load) failed with status {rc}"),
            Self::MissingExport { lib, func } => {
                write!(f, "{lib} does not export {func:?}")
            }
            Self::TooDeep(n) => write!(f, "import chain too deep at {n}"),
            Self::Kernel(m) => write!(f, "kernel boot: {m}"),
        }
    }
}

impl From<uefi::Error> for LoadError {
    fn from(e: uefi::Error) -> Self {
        Self::Uefi(e)
    }
}

struct Module {
    name: String,
    image: LxfImage,
    mem: NonNull<u8>,
    pages: usize,
}

impl Module {
    fn base(&self) -> usize {
        self.mem.as_ptr() as usize
    }
}

pub struct Loader {
    fs: FileSystem,
    modules: Vec<Module>,
    /// Indices into `modules`, in the order loading *finished*.
    load_order: Vec<usize>,
    info: Box<LxfBootInfo>,
}

impl Loader {
    pub fn new(put_str: PutStr) -> Result<Self, LoadError> {
        let proto: boot::ScopedProtocol<SimpleFileSystem> =
            boot::get_image_file_system(boot::image_handle())?;
        let st = uefi::table::system_table_raw().map_or(core::ptr::null(), |p| p.as_ptr() as *const c_void);
        let info = Box::new(LxfBootInfo {
            magic: BOOTINFO_MAGIC,
            version: BOOTINFO_VERSION,
            size: size_of::<LxfBootInfo>() as u32,
            put_str,
            system_table: st,
            image_handle: boot::image_handle().as_ptr() as *const c_void,
        });
        Ok(Self {
            fs: FileSystem::new(proto),
            modules: Vec::new(),
            load_order: Vec::new(),
            info,
        })
    }

    /// Load `name` (a program in the ESP root) and everything it imports.
    /// Returns the module index. On failure, modules that were already initialised get `libmain(0)`.
    pub fn load(&mut self, name: &str) -> Result<usize, LoadError> {
        match self.load_inner(name, 0, false) {
            Ok(i) => Ok(i),
            Err(e) => {
                self.unload_all();
                Err(e)
            }
        }
    }

    fn load_inner(&mut self, name: &str, depth: usize, need_library: bool) -> Result<usize, LoadError> {
        // Module cache, keyed by (case-insensitive) file name: FAT is
        // case-insensitive and a library used by two importers maps once.
        if let Some(i) = self.modules.iter().position(|m| m.name.eq_ignore_ascii_case(name)) {
            println!("[loader] {name} already loaded, reusing mapping");
            return Ok(i);
        }
        if depth >= MAX_DEPTH {
            return Err(LoadError::TooDeep(name.into()));
        }

        let bytes = self.read_file(name)?;
        let image = LxfImage::parse(&bytes).map_err(|e| LoadError::Parse(name.into(), e))?;
        drop(bytes);
        if image.is_kernel() {
            return Err(LoadError::NotAProgram(name.into()));
        }
        if need_library && !image.is_library() {
            return Err(LoadError::NotALibrary(name.into()));
        }

        // --- one block for the whole image: RVA 0 .. end of the last mapped section ------------
        let pages = (image.span() as usize).max(PAGE_SIZE) / PAGE_SIZE;
        // ABS32 relocations need an image below 2 GiB.
        let how = if image.relocs.iter().any(|r| r.kind == RELOC_ABS32) {
            AllocateType::MaxAddress(0x7FFF_FFFF)
        } else {
            AllocateType::AnyPages
        };
        let mem = boot::allocate_pages(how, MemoryType::LOADER_CODE, pages)?;
        // SAFETY: we own `pages * PAGE_SIZE` bytes at `mem`; the parser guarantees every mapped
        // section lies inside [0, span) and file_size <= virtual_size.
        unsafe {
            core::ptr::write_bytes(mem.as_ptr(), 0, pages * PAGE_SIZE);
            for (i, s) in image.mapped() {
                let data = image.section_data(i);
                core::ptr::copy_nonoverlapping(data.as_ptr(), mem.as_ptr().add(s.rva as usize), data.len());
            }
        }
        let base = mem.as_ptr() as usize;
        println!("[loader] {name}: {} bytes (RVA 0..{:#x}) mapped at {base:#x}", image.span(), image.span());

        // Register before recursing so a dependency cycle terminates.
        let idx = self.modules.len();
        self.modules.push(Module { name: name.into(), image, mem, pages });

        // --- relocations -----------------------------------------------------------------------
        let patches: Vec<(u32, usize, u64)> = {
            let img = &self.modules[idx].image;
            let mut v = Vec::with_capacity(img.relocs.len());
            for r in &img.relocs {
                v.push(img.reloc_value(r, base as u64).map_err(|e| LoadError::Parse(name.into(), e))?);
            }
            v
        };
        for (rva, width, value) in patches {
            // SAFETY: rva + width lies inside a mapped section, i.e. inside the block (parser).
            unsafe {
                let dst = mem.as_ptr().add(rva as usize);
                core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), dst, width);
            }
            println!("[loader] {name}: reloc rva {rva:#x} ({width} bytes) -> {value:#x}");
        }

        // --- imports ---------------------------------------------------------------------------
        let imports = self.modules[idx].image.imports.clone();
        for imp in imports {
            let what = match &imp.func {
                Some(f) => format!("{f:?}"),
                None => format!("#{}", imp.ordinal),
            };
            println!("[loader] {name} imports {what} from {}", imp.lib);
            let dep_idx = self.load_inner(&imp.lib, depth + 1, true)?;
            let dep = &self.modules[dep_idx];
            let export = match &imp.func {
                Some(f) => dep.image.find_export(f),
                None => dep.image.find_export_ordinal(imp.ordinal),
            }
            .ok_or_else(|| LoadError::MissingExport { lib: imp.lib.clone(), func: what.clone() })?;
            let target = (dep.base() + dep.image.export_rva(export) as usize) as u64;
            // SAFETY: the IAT slot is 8 bytes inside a writable mapped section (parser).
            unsafe {
                (mem.as_ptr().add(imp.iat_rva as usize) as *mut u64).write_unaligned(target);
            }
            println!("[loader]   patched IAT rva {:#x} -> {target:#x}", imp.iat_rva);
        }

        // --- libmain(load) ---------------------------------------------------------------------
        if self.modules[idx].image.has_libmain() {
            let rc = self.call_libmain(idx, 1);
            if rc != 0 {
                return Err(LoadError::LibMain { name: name.into(), rc });
            }
        }

        self.load_order.push(idx);
        Ok(idx)
    }

    /// Reads and parses `name` if it exists in the ESP root (`Ok(None)` if it does not).
    /// Used for the kernel image, which is booted rather than loaded as a module.
    pub fn read_image(&mut self, name: &str) -> Result<Option<LxfImage>, LoadError> {
        let path = CString16::try_from(format!("\\{name}").as_str()).map_err(|_| LoadError::BadName(name.into()))?;
        let exists = self.fs.try_exists(PathBuf::from(path)).map_err(|e| LoadError::Fs(format!("{name}: {e}")))?;
        if !exists {
            return Ok(None);
        }
        let bytes = self.read_file(name)?;
        // Lord Boot loads LKF kernels only. Say so plainly instead of reporting a "bad magic".
        if bytes.starts_with(b"\x7fELF") {
            return Err(LoadError::Kernel(format!(
                "{name} is not an LKF image: only .lkf kernels are supported (pack the linked kernel with tools/lxf/mkkernel.py)"
            )));
        }
        LxfImage::parse(&bytes).map(Some).map_err(|e| LoadError::Parse(name.into(), e))
    }

    fn read_file(&mut self, name: &str) -> Result<Vec<u8>, LoadError> {
        if name.is_empty() || name.contains(['\\', '/', ':']) || name.starts_with('.') {
            return Err(LoadError::BadName(name.into()));
        }
        let path_str = format!("\\{name}");
        let path16 = CString16::try_from(path_str.as_str())
            .map_err(|_| LoadError::BadName(name.into()))?;
        let path = PathBuf::from(path16);
        self.fs.read(path).map_err(|e| LoadError::Fs(format!("{path_str}: {e}")))
    }

    fn call_libmain(&self, idx: usize, reason: i64) -> i32 {
        let m = &self.modules[idx];
        let addr = m.base() + m.image.libmain_rva as usize;
        println!(
            "[loader] calling {}'s libmain({reason} [{}])",
            m.name,
            if reason == 1 { "load" } else { "unload" }
        );
        // SAFETY: libmain_rva validated to lie in an executable section; the code is LXF-provided
        // and expected to follow the documented sysv64 contract.
        let f: LibMain = unsafe { core::mem::transmute(addr) };
        f(reason, &*self.info)
    }

    /// Run the executable at module index `idx`; returns its exit status (`eax`).
    pub fn run_executable(&self, idx: usize) -> Result<u64, LoadError> {
        let m = &self.modules[idx];
        if m.image.is_library() {
            return Err(LoadError::NotAnExecutable);
        }
        let entry = m.base() + m.image.entry_rva as usize;
        // argv = [file name, NULL], envp = [NULL]
        let mut arg0: Vec<u8> = m.name.as_bytes().to_vec();
        arg0.push(0);
        let argv: [*const u8; 2] = [arg0.as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        println!("[loader] jumping to entry {entry:#x}");
        // SAFETY: see `call_libmain`.
        let f: ExeEntry = unsafe { core::mem::transmute(entry) };
        let rc = f(1, argv.as_ptr(), envp.as_ptr(), &*self.info);
        Ok(u64::from(rc as u32))
    }

    /// `libmain(0)` on every initialised module, newest first. Runs once: the list is emptied.
    pub fn unload_all(&mut self) {
        let order = core::mem::take(&mut self.load_order);
        for &idx in order.iter().rev() {
            if self.modules[idx].image.has_libmain() {
                self.call_libmain(idx, 0);
            }
        }
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        for m in self.modules.drain(..) {
            // SAFETY: pages were allocated by `allocate_pages` in `load_inner`.
            let _ = unsafe { boot::free_pages(m.mem, m.pages) };
        }
    }
}
