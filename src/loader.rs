// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Adam55Lord

//! The LXF loader: the UEFI equivalent of `tools/run_lord.py`.
//!
//! For every module it
//!   1. reads the file from the ESP and parses/validates it,
//!   2. copies `.text` into freshly allocated `LOADER_CODE` pages,
//!   3. applies `.reloc` (ABS64: `*slot += runtime_base`),
//!   4. resolves `.idata` by recursively loading the named `.llf` from the
//!      ESP root and writing the export address into the IAT slot,
//!   5. calls `LibraryMain(reason=1)` for libraries that have one.
//!
//! ## ABI seen by LXF code (Microsoft x64 / UEFI calling convention)
//!
//! * executable entry:  `u64 _start(const LxfBootInfo *info)`      (RCX = info)
//! * library main:      `void LibraryMain(u64 reason, const LxfBootInfo *info)`
//!                      (RCX = reason: 1 = load, 0 = unload; RDX = info)
//!
//! `LxfBootInfo` (all fields 8-byte aligned, offsets in bytes):
//!
//! | off | field          | meaning                                         |
//! |-----|----------------|-------------------------------------------------|
//! |  0  | magic: u64     | `"LXFBOOT\0"` = 0x00544F4F4246584C (LE)         |
//! |  8  | version: u32   | 1                                               |
//! | 12  | size: u32      | size of this struct (40)                        |
//! | 16  | put_str        | `void put_str(const char *s, u64 len)` (efiapi) |
//! | 24  | system_table   | `EFI_SYSTEM_TABLE *`                            |
//! | 32  | image_handle   | `EFI_HANDLE` of the bootloader                  |

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

use crate::lxf::{LxfError, LxfImage};

const PAGE_SIZE: usize = 4096;
const MAX_DEPTH: usize = 16;

pub const BOOTINFO_MAGIC: u64 = u64::from_le_bytes(*b"LXFBOOT\0");
pub const BOOTINFO_VERSION: u32 = 1;

pub type PutStr = extern "efiapi" fn(*const u8, usize);

#[repr(C)]
pub struct LxfBootInfo {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub put_str: PutStr,
    pub system_table: *const c_void,
    pub image_handle: *const c_void,
}

type ExeEntry = extern "efiapi" fn(*const LxfBootInfo) -> u64;
type LibMain = extern "efiapi" fn(u64, *const LxfBootInfo);

pub enum LoadError {
    Uefi(uefi::Error),
    Fs(String),
    Parse(String, LxfError),
    BadName(String),
    NotAnExecutable,
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
            Self::Parse(n, e) => write!(f, "{n}: invalid LXF file: {e}"),
            Self::BadName(n) => write!(f, "refusing library name {n:?}"),
            Self::NotAnExecutable => write!(f, "file is a library (.llf), not an executable"),
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

    /// Load `name` (a file in the ESP root) and everything it imports.
    /// Returns the module index.
    pub fn load(&mut self, name: &str) -> Result<usize, LoadError> {
        self.load_inner(name, 0)
    }

    fn load_inner(&mut self, name: &str, depth: usize) -> Result<usize, LoadError> {
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

        // --- map .text into executable memory --------------------------------
        let pages = image.text.len().max(1).div_ceil(PAGE_SIZE);
        let mem = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_CODE, pages)?;
        // SAFETY: we own `pages * PAGE_SIZE` bytes at `mem`.
        unsafe {
            core::ptr::write_bytes(mem.as_ptr(), 0, pages * PAGE_SIZE);
            core::ptr::copy_nonoverlapping(image.text.as_ptr(), mem.as_ptr(), image.text.len());
        }
        let base = mem.as_ptr() as usize;
        println!(
            "[loader] {name}: .text {} bytes mapped at {base:#x}",
            image.text.len()
        );

        // Register before recursing so a dependency cycle terminates.
        let idx = self.modules.len();
        let relocs = image.relocs.clone();
        let imports = image.imports.clone();
        self.modules.push(Module { name: name.into(), image, mem, pages });

        // --- relocations -----------------------------------------------------
        for r in relocs {
            // SAFETY: offset + 8 <= text.len() <= pages * PAGE_SIZE (validated by parser).
            let slot = unsafe { mem.as_ptr().add(r.offset as usize) } as *mut u64;
            let link = unsafe { slot.read_unaligned() };
            let run = link.wrapping_add(base as u64);
            unsafe { slot.write_unaligned(run) };
            println!("[loader] {name}: reloc .text+{:#x}: {link:#x} -> {run:#x}", r.offset);
        }

        // --- imports ---------------------------------------------------------
        for imp in imports {
            println!("[loader] {name} imports {:?} from {}", imp.function, imp.library);
            let dep_idx = self.load_inner(&imp.library, depth + 1)?;
            let dep = &self.modules[dep_idx];
            let export = dep.image.find_export(&imp.function).ok_or_else(|| {
                LoadError::MissingExport { lib: imp.library.clone(), func: imp.function.clone() }
            })?;
            let target = (dep.base() + export.offset as usize) as u64;
            // SAFETY: iat_slot + 8 <= text.len() (validated by parser).
            unsafe {
                (mem.as_ptr().add(imp.iat_slot as usize) as *mut u64).write_unaligned(target);
            }
            println!("[loader]   patched IAT .text+{:#x} -> {target:#x}", imp.iat_slot);
        }

        // --- LibraryMain(load) -----------------------------------------------
        if self.modules[idx].image.has_libmain() {
            self.call_libmain(idx, 1);
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
        // Lord Boot loads LXF images only. Say so plainly instead of reporting a "bad magic".
        if bytes.starts_with(b"\x7fELF") {
            return Err(LoadError::Kernel(format!(
                "{name} is not an LXF image: only .lxf kernels are supported (see docs/19-lxf-boot-protocol.md)"
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

    fn call_libmain(&self, idx: usize, reason: u64) {
        let m = &self.modules[idx];
        let addr = m.base() + m.image.entry_offset as usize;
        println!(
            "[loader] calling {}'s LibraryMain(reason={reason} [{}])",
            m.name,
            if reason == 1 { "load" } else { "unload" }
        );
        // SAFETY: entry_offset validated to lie in .text; the code is LXF-provided
        // and expected to follow the documented efiapi contract.
        let f: LibMain = unsafe { core::mem::transmute(addr) };
        f(reason, &*self.info);
    }

    /// Run the executable at module index `idx`; returns its RAX.
    pub fn run_executable(&self, idx: usize) -> Result<u64, LoadError> {
        let m = &self.modules[idx];
        if m.image.is_library() {
            return Err(LoadError::NotAnExecutable);
        }
        let entry = m.base() + m.image.entry_offset as usize;
        println!("[loader] jumping to entry {entry:#x}");
        // SAFETY: see `call_libmain`.
        let f: ExeEntry = unsafe { core::mem::transmute(entry) };
        Ok(f(&*self.info))
    }

    /// `LibraryMain(0)` on every loaded library, newest first.
    pub fn unload_all(&self) {
        for &idx in self.load_order.iter().rev() {
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
