// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Adam55Lord

//! LXF / LLF / LKF container parser (Lord formats, format version 2, spec `SPEC.md` of lxf_tools v3).
//!
//! This is a strict, bounds-checked `no_std` port of `LordFile.from_bytes()` in `lordfmt.py`: it
//! applies the same rules, so a file the Python tools accept is accepted here and vice versa.
//! All integers are little-endian.
//!
//! ```text
//! [ file header 64 B ][ type extension (LKF 48 B / LDF 40 B) ][ section table n*28 B ][ section data ]
//! ```
//!
//! The bootloader loads **LKF** (kernel images, `kernel.lkf`) and, as a UEFI-hosted test
//! facility, **LXF / LLF** (programs and libraries). Drivers (LDF) are parsed by the kernel's
//! driver loader, not here: [`LxfImage::parse`] refuses them.
//!
//! Metadata sections (`.strtab`, `.edata`, `.impdir`, `.reloc`) are decoded into the structs
//! below; everything that points into the image is validated, so loaders can use it blindly.

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub const MAGIC_LXF: [u8; 4] = *b"LXF\0";
pub const MAGIC_LLF: [u8; 4] = *b"LLF\0";
pub const MAGIC_LKF: [u8; 4] = *b"LKF\0";
pub const MAGIC_LDF: [u8; 4] = *b"LDF\0";

pub const FORMAT_VERSION: u16 = 2;
/// Highest `min_loader` this parser understands.
pub const LOADER_VERSION: u16 = 3;
pub const KERNEL_MIN_LOADER: u16 = 3;

pub const ARCH_X86_64: u16 = 1;

pub const TYPE_EXECUTABLE: u16 = 1;
pub const TYPE_LIBRARY: u16 = 2;
pub const TYPE_KERNEL: u16 = 3;
pub const TYPE_DRIVER: u16 = 4;

pub const FLAG_HAS_ENTRY: u32 = 0x1;
pub const FLAG_HAS_LIBMAIN: u32 = 0x2;
pub const FLAG_HAS_CRC: u32 = 0x4;
const KNOWN_FILE_FLAGS: u32 = FLAG_HAS_ENTRY | FLAG_HAS_LIBMAIN | FLAG_HAS_CRC;

pub const SEC_EXEC: u32 = 0x01;
pub const SEC_WRITE: u32 = 0x02;
pub const SEC_READ: u32 = 0x04;
pub const SEC_METADATA: u32 = 0x10;
pub const SEC_RELRO: u32 = 0x20;
const KNOWN_SEC_FLAGS: u32 = SEC_EXEC | SEC_WRITE | SEC_READ | SEC_METADATA | SEC_RELRO;

pub const RELOC_ABS64: u8 = 1;
pub const RELOC_ABS32: u8 = 2;
pub const RELOC_REL32: u8 = 3;
pub const RELOC_RVA32: u8 = 4;
/// `target_section` value meaning "the image itself" (RVA 0).
const TARGET_IMAGE: u8 = 0xFF;

const IMP_BY_ORDINAL: u32 = 1;

/// Kernel flags (`kflags`).
pub const KF_FIXED_ADDR: u32 = 0x1;
pub const KF_SMP: u32 = 0x2;
pub const KF_DEBUG: u32 = 0x4;
const KNOWN_KERNEL_FLAGS: u32 = KF_FIXED_ADDR | KF_SMP | KF_DEBUG;

/// Kernel boot protocols (`boot_proto`).
pub const BOOT_LORD: u32 = 1;
pub const BOOT_RAW: u32 = 2;

const FILEHDR_SIZE: usize = 64;
const KERNEL_EXT_SIZE: usize = 48;
const SECHDR_SIZE: usize = 28;
const EXPORT_SIZE: usize = 20;
const IMPDESC_SIZE: usize = 8;
const IMPENT_SIZE: usize = 16;
const RELOC_SIZE: usize = 16;
const SYMBOL_SIZE: usize = 12;
const IAT_SLOT_SIZE: u32 = 8;
const CRC_OFFSET: usize = FILEHDR_SIZE - 4;
const MAX_SECTIONS: usize = 254;
/// Upper bound on the size of a file we are willing to parse (64 MiB).
pub const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum LxfError {
    Truncated(&'static str),
    BadMagic([u8; 4]),
    /// A driver (LDF): not loadable by the bootloader.
    Driver,
    Bad(String),
}

impl fmt::Display for LxfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(w) => write!(f, "file truncated while reading {w}"),
            Self::BadMagic(m) => write!(f, "bad magic {m:02x?} (want LXF/LLF/LKF)"),
            Self::Driver => write!(f, "drivers (LDF) are loaded by the kernel, not by the bootloader"),
            Self::Bad(m) => write!(f, "{m}"),
        }
    }
}

fn bad<T>(msg: impl Into<String>) -> Result<T, LxfError> {
    Err(LxfError::Bad(msg.into()))
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub file_offset: u32,
    pub file_size: u32,
    pub rva: u32,
    pub virtual_size: u32,
    pub flags: u32,
}

impl Section {
    pub fn mapped(&self) -> bool {
        self.flags & SEC_METADATA == 0
    }
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    /// Index into [`LxfImage::sections`].
    pub section: usize,
    pub offset: u32,
    #[allow(dead_code)]
    pub size: u32,
    pub ordinal: u32,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub lib: String,
    /// `None` = import by ordinal.
    pub func: Option<String>,
    pub ordinal: u32,
    /// RVA of the 8-byte IAT slot the loader fills in.
    pub iat_rva: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Reloc {
    pub rva: u32,
    pub kind: u8,
    /// Index into [`LxfImage::sections`], `None` = image (RVA 0).
    pub target: Option<usize>,
    pub addend: i64,
}

/// The LKF header extension.
#[derive(Debug, Clone)]
pub struct KernelInfo {
    pub flags: u32,
    pub boot_proto: u32,
    /// `major << 16 | minor << 8 | patch`.
    pub version: u32,
    pub kabi: u32,
    pub cmdline: String,
    pub load_addr: u64,
    pub build_id: [u8; 16],
}

/// A fully parsed and validated LXF/LLF/LKF file (owns the file bytes).
#[derive(Debug)]
pub struct LxfImage {
    pub filetype: u16,
    pub flags: u32,
    pub section_align: u32,
    pub entry_rva: u32,
    pub libmain_rva: u32,
    #[allow(dead_code)]
    pub stack_size: u32,
    #[allow(dead_code)]
    pub preferred_base: u64,
    pub sections: Vec<Section>,
    pub exports: Vec<Export>,
    pub imports: Vec<Import>,
    pub relocs: Vec<Reloc>,
    pub kernel: Option<KernelInfo>,
    data: Vec<u8>,
}

impl LxfImage {
    pub fn is_kernel(&self) -> bool {
        self.filetype == TYPE_KERNEL
    }

    pub fn is_library(&self) -> bool {
        self.filetype == TYPE_LIBRARY
    }

    pub fn has_entry(&self) -> bool {
        self.flags & FLAG_HAS_ENTRY != 0
    }

    pub fn has_libmain(&self) -> bool {
        self.flags & FLAG_HAS_LIBMAIN != 0
    }

    /// The file bytes of section `i` (`file_size` of them; the rest of its memory is zero).
    pub fn section_data(&self, i: usize) -> &[u8] {
        let s = &self.sections[i];
        let o = s.file_offset as usize;
        &self.data[o..o + s.file_size as usize]
    }

    /// Mapped sections only, with their table index.
    pub fn mapped(&self) -> impl Iterator<Item = (usize, &Section)> {
        self.sections.iter().enumerate().filter(|(_, s)| s.mapped())
    }

    /// Bytes of memory the image spans from RVA 0 (page rounded): what a loader that
    /// maps the whole image in one go has to reserve.
    pub fn span(&self) -> u64 {
        let end = self.mapped().map(|(_, s)| u64::from(s.rva) + u64::from(s.virtual_size)).max().unwrap_or(0);
        end.div_ceil(4096) * 4096
    }

    /// Section index and offset of an RVA inside a mapped section.
    pub fn locate(&self, rva: u32) -> Option<(usize, u32)> {
        self.mapped()
            .find(|(_, s)| rva >= s.rva && u64::from(rva) < u64::from(s.rva) + u64::from(s.virtual_size))
            .map(|(i, s)| (i, rva - s.rva))
    }

    pub fn find_export(&self, name: &str) -> Option<&Export> {
        self.exports.binary_search_by(|e| e.name.as_bytes().cmp(name.as_bytes())).ok().map(|i| &self.exports[i])
    }

    pub fn find_export_ordinal(&self, ordinal: u32) -> Option<&Export> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }

    /// RVA of an export.
    pub fn export_rva(&self, e: &Export) -> u32 {
        self.sections[e.section].rva + e.offset
    }

    /// The value a relocation writes for an image placed at `base`:
    /// `(rva of the patch, width in bytes, value)`.
    pub fn reloc_value(&self, r: &Reloc, base: u64) -> Result<(u32, usize, u64), LxfError> {
        let t = i64::from(r.target.map_or(0, |i| self.sections[i].rva)) + r.addend;
        let rva = r.rva;
        match r.kind {
            RELOC_ABS64 => Ok((rva, 8, base.wrapping_add(t as u64))),
            RELOC_ABS32 => {
                let v = base.wrapping_add(t as u64);
                if v > u64::from(u32::MAX) {
                    return bad(alloc::format!("ABS32 relocation at {rva:#x} does not fit: image placed at {base:#x}"));
                }
                Ok((rva, 4, v))
            }
            RELOC_REL32 => {
                let d = t - (i64::from(rva) + 4);
                if i32::try_from(d).is_err() {
                    return bad(alloc::format!("REL32 relocation at {rva:#x} out of range"));
                }
                Ok((rva, 4, d as u32 as u64))
            }
            RELOC_RVA32 => {
                if u32::try_from(t).is_err() {
                    return bad(alloc::format!("RVA32 relocation at {rva:#x} out of range"));
                }
                Ok((rva, 4, t as u64))
            }
            _ => bad("unknown relocation type"),
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, LxfError> {
        if buf.len() < FILEHDR_SIZE {
            return Err(LxfError::Truncated("file header"));
        }
        if buf.len() > MAX_FILE_SIZE {
            return bad("file too large");
        }
        let magic: [u8; 4] = buf[0..4].try_into().unwrap();
        let version = u16_at(buf, 4);
        let arch = u16_at(buf, 6);
        let filetype = u16_at(buf, 8);
        let nsec = u16_at(buf, 10) as usize;
        let header_size = u32_at(buf, 12) as usize;
        let table_off = u32_at(buf, 16) as usize;
        let file_size = u32_at(buf, 20) as usize;
        let file_align = u32_at(buf, 24);
        let section_align = u32_at(buf, 28);
        let entry_rva = u32_at(buf, 32);
        let libmain_rva = u32_at(buf, 36);
        let flags = u32_at(buf, 40);
        let stack_size = u32_at(buf, 44);
        let preferred_base = u64_at(buf, 48);
        let min_loader = u16_at(buf, 56);
        let reserved = u16_at(buf, 58);
        let crc = u32_at(buf, 60);

        let want_type = match magic {
            MAGIC_LXF => TYPE_EXECUTABLE,
            MAGIC_LLF => TYPE_LIBRARY,
            MAGIC_LKF => TYPE_KERNEL,
            MAGIC_LDF => TYPE_DRIVER,
            m => return Err(LxfError::BadMagic(m)),
        };
        if filetype != want_type {
            return bad("magic / file type mismatch");
        }
        if filetype == TYPE_DRIVER {
            return Err(LxfError::Driver);
        }
        if version != FORMAT_VERSION {
            return bad(alloc::format!("unsupported format version {version} (want {FORMAT_VERSION}; rebuild the file with lxf_tools v3)"));
        }
        if arch != ARCH_X86_64 {
            return bad(alloc::format!("unsupported architecture {arch} (want 1 = x86-64)"));
        }
        if min_loader > LOADER_VERSION {
            return bad(alloc::format!("file needs loader >= {min_loader}, this is {LOADER_VERSION}"));
        }
        let want_hdr = FILEHDR_SIZE + if filetype == TYPE_KERNEL { KERNEL_EXT_SIZE } else { 0 };
        if header_size != want_hdr {
            return bad("bad header_size");
        }
        if filetype == TYPE_KERNEL && min_loader < KERNEL_MIN_LOADER {
            return bad("kernel files need min_loader >= 3");
        }
        if file_size != buf.len() {
            return bad(alloc::format!("file_size {file_size} != actual size {}", buf.len()));
        }
        if reserved != 0 {
            return bad("reserved header field set");
        }
        if flags & !KNOWN_FILE_FLAGS != 0 {
            return bad(alloc::format!("unknown header flags {flags:#x}"));
        }
        if !file_align.is_power_of_two() || !section_align.is_power_of_two() || section_align < 0x1000 {
            return bad("bad alignment fields");
        }
        if preferred_base % u64::from(section_align) != 0 {
            return bad("preferred_base not section-aligned");
        }
        if flags & FLAG_HAS_CRC == 0 && crc != 0 {
            return bad("CRC field set but HAS_CRC flag clear");
        }
        if flags & FLAG_HAS_CRC != 0 && crc32_zeroed(buf, CRC_OFFSET) != crc {
            return bad("CRC32 mismatch (file corrupted)");
        }
        if nsec > MAX_SECTIONS {
            return bad("too many sections");
        }
        let table_end = nsec.checked_mul(SECHDR_SIZE).and_then(|n| n.checked_add(table_off));
        if table_off < header_size || table_end.is_none_or(|e| e > file_size) {
            return bad("section table outside file");
        }

        // --- section table -----------------------------------------------------------------
        let mut sections: Vec<Section> = Vec::with_capacity(nsec);
        let mut file_ranges: Vec<(u64, u64, usize)> = Vec::new();
        let mut mem_ranges: Vec<(u64, u64, usize)> = Vec::new();
        file_ranges.push((0, table_end.unwrap() as u64, usize::MAX)); // headers
        for i in 0..nsec {
            let at = table_off + i * SECHDR_SIZE;
            let raw = &buf[at..at + 8];
            let name = parse_name(raw)?;
            let file_offset = u32_at(buf, at + 8);
            let fsize = u32_at(buf, at + 12);
            let rva = u32_at(buf, at + 16);
            let vsize = u32_at(buf, at + 20);
            let sflags = u32_at(buf, at + 24);
            if sflags & !KNOWN_SEC_FLAGS != 0 {
                return bad(alloc::format!("{name}: unknown section flags"));
            }
            if u64::from(file_offset) + u64::from(fsize) > file_size as u64 {
                return bad(alloc::format!("{name}: data outside file"));
            }
            if fsize != 0 {
                if file_offset % file_align != 0 {
                    return bad(alloc::format!("{name}: misaligned file offset"));
                }
                file_ranges.push((u64::from(file_offset), u64::from(file_offset) + u64::from(fsize), i));
            } else if file_offset != 0 {
                return bad(alloc::format!("{name}: empty section with offset"));
            }
            if sflags & SEC_METADATA != 0 {
                if sflags & (SEC_EXEC | SEC_WRITE | SEC_RELRO) != 0 || rva != 0 || vsize != 0 {
                    return bad(alloc::format!("{name}: bad metadata section"));
                }
            } else {
                if sflags & SEC_EXEC != 0 && sflags & SEC_WRITE != 0 {
                    return bad(alloc::format!("{name}: W^X violation"));
                }
                if rva % section_align != 0 {
                    return bad(alloc::format!("{name}: misaligned rva"));
                }
                if vsize < fsize || vsize == 0 {
                    return bad(alloc::format!("{name}: bad virtual_size"));
                }
                if u64::from(rva) + u64::from(vsize) >= 1 << 32 {
                    return bad(alloc::format!("{name}: rva out of range"));
                }
                mem_ranges.push((u64::from(rva), u64::from(rva) + u64::from(vsize), i));
            }
            if sections.iter().any(|s| s.name == name) {
                return bad("duplicate section names");
            }
            sections.push(Section { name, file_offset, file_size: fsize, rva, virtual_size: vsize, flags: sflags });
        }
        for (ranges, what) in [(&mut file_ranges, "file"), (&mut mem_ranges, "memory")] {
            ranges.sort();
            for w in ranges.windows(2) {
                if w[1].0 < w[0].1 {
                    return bad(alloc::format!("{what} ranges overlap"));
                }
            }
        }

        // --- metadata ----------------------------------------------------------------------
        let meta = |name: &str| -> Result<&[u8], LxfError> {
            match sections.iter().find(|s| s.name == name) {
                None => Ok(&[]),
                Some(s) if s.mapped() => bad(alloc::format!("{name} must be a metadata section")),
                Some(s) => Ok(&buf[s.file_offset as usize..(s.file_offset + s.file_size) as usize]),
            }
        };
        let strtab = meta(".strtab")?;
        let mapped_idx = |i: usize, what: &str| -> Result<usize, LxfError> {
            if i < sections.len() && sections[i].mapped() {
                Ok(i)
            } else {
                bad(alloc::format!("{what}: bad section index {i}"))
            }
        };

        // exports
        let d = meta(".edata")?;
        if d.len() % EXPORT_SIZE != 0 {
            return bad("bad .edata size");
        }
        let mut exports: Vec<Export> = Vec::new();
        for e in d.chunks_exact(EXPORT_SIZE) {
            let name = cstr(strtab, u32_at(e, 0))?;
            let si = mapped_idx(e[4] as usize, &name)?;
            let offset = u32_at(e, 8);
            let size = u32_at(e, 12);
            let ordinal = u32_at(e, 16);
            if u64::from(offset) + 1 > u64::from(sections[si].virtual_size) {
                return bad(alloc::format!("export {name}: offset out of range"));
            }
            if let Some(prev) = exports.last() {
                if name.as_bytes() <= prev.name.as_bytes() {
                    return bad(".edata not strictly sorted by name");
                }
            }
            if ordinal == 0 || exports.iter().any(|x| x.ordinal == ordinal) {
                return bad("bad/duplicate export ordinal");
            }
            exports.push(Export { name, section: si, offset, size, ordinal });
        }

        // imports
        let d = meta(".impdir")?;
        let mut imports: Vec<Import> = Vec::new();
        let mut pos = 0usize;
        while pos < d.len() {
            if pos + IMPDESC_SIZE > d.len() {
                return bad("truncated .impdir");
            }
            let lib = cstr(strtab, u32_at(d, pos))?;
            let count = u32_at(d, pos + 4) as usize;
            pos += IMPDESC_SIZE;
            if lib.is_empty() || count.checked_mul(IMPENT_SIZE).is_none_or(|n| pos + n > d.len()) {
                return bad("bad import descriptor");
            }
            for _ in 0..count {
                let noff = u32_at(d, pos);
                let ordinal = u32_at(d, pos + 4);
                let iat = u32_at(d, pos + 8);
                let iflags = u32_at(d, pos + 12);
                pos += IMPENT_SIZE;
                if iflags & !IMP_BY_ORDINAL != 0 {
                    return bad("unknown import flags");
                }
                let func = if iflags & IMP_BY_ORDINAL != 0 {
                    if ordinal == 0 {
                        return bad("ordinal import with ordinal 0");
                    }
                    None
                } else {
                    let f = cstr(strtab, noff)?;
                    if f.is_empty() {
                        return bad("empty import name");
                    }
                    Some(f)
                };
                let holder = sections.iter().find(|s| {
                    s.mapped() && s.rva <= iat && u64::from(iat) + 8 <= u64::from(s.rva) + u64::from(s.virtual_size)
                });
                if !holder.is_some_and(|s| s.flags & SEC_WRITE != 0) {
                    return bad(alloc::format!("IAT slot {iat:#x} not in a writable section"));
                }
                if iat % IAT_SLOT_SIZE != 0 || imports.iter().any(|x| x.iat_rva == iat) {
                    return bad("misaligned/duplicate IAT slot");
                }
                imports.push(Import { lib: lib.clone(), func, ordinal, iat_rva: iat });
            }
        }
        imports.sort_by_key(|i| i.iat_rva);

        // relocations
        let d = meta(".reloc")?;
        if d.len() % RELOC_SIZE != 0 {
            return bad("bad .reloc size");
        }
        let mut relocs: Vec<Reloc> = Vec::new();
        for e in d.chunks_exact(RELOC_SIZE) {
            let rva = u32_at(e, 0);
            let kind = e[4];
            let tgt = e[5];
            let addend = u64_at(e, 8) as i64;
            let width = match kind {
                RELOC_ABS64 => 8,
                RELOC_ABS32 | RELOC_REL32 | RELOC_RVA32 => 4,
                _ => return bad(alloc::format!("unknown relocation type {kind}")),
            };
            let inside = sections.iter().any(|s| {
                s.mapped() && s.rva <= rva && u64::from(rva) + width <= u64::from(s.rva) + u64::from(s.virtual_size)
            });
            if !inside {
                return bad(alloc::format!("relocation at {rva:#x} outside image"));
            }
            let target = if tgt == TARGET_IMAGE { None } else { Some(mapped_idx(tgt as usize, "reloc")?) };
            relocs.push(Reloc { rva, kind, target, addend });
        }

        // symbols (debug info the loader does not use) and devices: only validated
        let d = meta(".symtab")?;
        if d.len() % SYMBOL_SIZE != 0 {
            return bad("bad .symtab size");
        }
        for e in d.chunks_exact(SYMBOL_SIZE) {
            let name = cstr(strtab, u32_at(e, 0))?;
            let si = mapped_idx(e[4] as usize, "symbol")?;
            if u64::from(u32_at(e, 8)) > u64::from(sections[si].virtual_size) {
                return bad(alloc::format!("symbol {name}: offset out of range"));
            }
        }
        if !meta(".devtab")?.is_empty() {
            return bad(".devtab in a non-driver file");
        }

        // --- kernel extension -----------------------------------------------------------------
        let kernel = if filetype == TYPE_KERNEL {
            let x = &buf[FILEHDR_SIZE..header_size];
            let kflags = u32_at(x, 0);
            let boot_proto = u32_at(x, 4);
            let kver = u32_at(x, 8);
            let kabi = u32_at(x, 12);
            let cmd_off = u32_at(x, 16);
            let kres = u32_at(x, 20);
            let load_addr = u64_at(x, 24);
            let build_id: [u8; 16] = x[32..48].try_into().unwrap();
            if kflags & !KNOWN_KERNEL_FLAGS != 0 {
                return bad(alloc::format!("unknown kernel flags {kflags:#x}"));
            }
            if boot_proto != BOOT_LORD && boot_proto != BOOT_RAW {
                return bad(alloc::format!("unknown boot protocol {boot_proto}"));
            }
            if kabi < 1 {
                return bad("kernel kabi must be >= 1");
            }
            if kres != 0 {
                return bad("kernel header reserved field set");
            }
            if load_addr % u64::from(section_align) != 0 {
                return bad("load_addr not section-aligned");
            }
            if kflags & KF_FIXED_ADDR != 0 && load_addr == 0 {
                return bad("FIXED_ADDR without load_addr");
            }
            Some(KernelInfo { flags: kflags, boot_proto, version: kver, kabi, cmdline: cstr(strtab, cmd_off)?, load_addr, build_id })
        } else {
            None
        };

        let img = Self {
            filetype,
            flags,
            section_align,
            entry_rva,
            libmain_rva,
            stack_size,
            preferred_base,
            sections,
            exports,
            imports,
            relocs,
            kernel,
            data: buf.to_vec(),
        };

        // --- entry points ---------------------------------------------------------------------
        let in_exec = |rva: u32, what: &str| -> Result<(), LxfError> {
            match img.locate(rva) {
                Some((i, _)) if img.sections[i].flags & SEC_EXEC != 0 => Ok(()),
                _ => bad(alloc::format!("{what} not in an executable section")),
            }
        };
        let has_entry_kind = matches!(filetype, TYPE_EXECUTABLE | TYPE_KERNEL);
        if flags & FLAG_HAS_ENTRY != 0 {
            if !has_entry_kind {
                return bad("library with entry point");
            }
            in_exec(entry_rva, "entry")?;
        } else if has_entry_kind {
            return bad("executable/kernel without entry point");
        }
        if flags & FLAG_HAS_LIBMAIN != 0 {
            in_exec(libmain_rva, "libmain")?;
        }
        Ok(img)
    }
}

fn parse_name(raw: &[u8]) -> Result<String, LxfError> {
    let end = raw.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
    let n = &raw[..end];
    if n.is_empty() || !n.iter().all(|&c| (0x21..0x7f).contains(&c)) {
        return bad("section name is empty or not printable ASCII");
    }
    Ok(String::from_utf8_lossy(n).into_owned())
}

/// NUL-terminated UTF-8 string at `off` in `.strtab` (offset 0 = "").
fn cstr(strtab: &[u8], off: u32) -> Result<String, LxfError> {
    if off == 0 {
        return Ok(String::new());
    }
    let off = off as usize;
    if off >= strtab.len() {
        return bad(alloc::format!("string offset {off:#x} outside .strtab"));
    }
    let rest = &strtab[off..];
    let Some(end) = rest.iter().position(|&c| c == 0) else {
        return bad("unterminated string in .strtab");
    };
    core::str::from_utf8(&rest[..end]).map(String::from).or_else(|_| bad("invalid UTF-8 in .strtab"))
}

/// CRC-32 (IEEE, as `zlib.crc32`) of `buf` with the 4 bytes at `zero_at` taken as zero.
fn crc32_zeroed(buf: &[u8], zero_at: usize) -> u32 {
    const T: [u32; 16] = [
        0x0000_0000, 0x1db7_1064, 0x3b6e_20c8, 0x26d9_30ac, 0x76dc_4190, 0x6b6b_51f4, 0x4db2_6158, 0x5005_713c,
        0xedb8_8320, 0xf00f_9344, 0xd6d6_a3e8, 0xcb61_b38c, 0x9b64_c2b0, 0x86d3_d2d4, 0xa00a_e278, 0xbdbd_f21c,
    ];
    let mut crc = !0u32;
    for (i, &b) in buf.iter().enumerate() {
        let b = if (zero_at..zero_at + 4).contains(&i) { 0 } else { b };
        crc ^= u32::from(b);
        crc = (crc >> 4) ^ T[(crc & 15) as usize];
        crc = (crc >> 4) ^ T[(crc & 15) as usize];
    }
    !crc
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
