// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Adam55Lord

//! LXF / LLF container parser.
//!
//! This is a strict, bounds-checked `no_std` port of `tools/lordfmt.py`.
//! All integers are little-endian.
//!
//! ```text
//! FileHeader   magic[4] version:u16 arch:u16 filetype:u16 num_sections:u16
//!              entry_offset:u32 flags:u32                          (20 bytes)
//! SectionHdr   name[8] file_offset:u32 size:u32 flags:u32          (20 bytes) x num_sections
//! .edata       { name[32] offset:u32 size:u32 }                    (40 bytes) entries
//! .idata       { lib[32] func[32] iat_slot_offset:u32 }            (68 bytes) entries
//! .reloc       { offset:u32 type:u8 pad[3] }                       ( 8 bytes) entries
//! ```
//!
//! Every offset that points *into `.text`* (entry, exports, IAT slots,
//! relocations) is validated here so the loader can use them blindly.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub const MAGIC_LXF: [u8; 4] = *b"LXF\0";
pub const MAGIC_LLF: [u8; 4] = *b"LLF\0";

pub const VERSION: u16 = 1;
pub const TYPE_EXECUTABLE: u16 = 1;
pub const TYPE_LIBRARY: u16 = 2;
pub const ARCH_X86_64: u16 = 1;

/// File-header flag: for libraries, `entry_offset` is a valid `LibraryMain`.
pub const FLAG_HAS_LIBMAIN: u32 = 0x1;
/// File-header flag: an executable that is an OS kernel image (see `.kseg`).
pub const FLAG_KERNEL: u32 = 0x2;

/// `.kseg` segment permissions.
pub const KSEG_R: u32 = 1;
pub const KSEG_W: u32 = 2;
pub const KSEG_X: u32 = 4;

pub const RELOC_TYPE_ABS64: u8 = 1;

const FILEHDR_SIZE: usize = 20;
const SECHDR_SIZE: usize = 20;
const EXPORT_SIZE: usize = 40;
const IMPORT_SIZE: usize = 68;
const RELOC_SIZE: usize = 8;
const NAME_LEN: usize = 32;
const KSEG_SIZE: usize = 24;

/// Upper bound on `.text` we are willing to load (16 MiB).
pub const MAX_TEXT_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum LxfError {
    Truncated(&'static str),
    BadMagic([u8; 4]),
    BadVersion(u16),
    BadArch(u16),
    BadFileType(u16),
    MagicTypeMismatch,
    NoText,
    TextTooLarge(usize),
    SectionOutOfBounds(String),
    BadTableSize(&'static str),
    OffsetOutOfText { what: &'static str, offset: u32 },
    UnsupportedReloc(u8),
    /// A kernel image (FLAG_KERNEL) that is malformed.
    BadKernel(&'static str),
}

impl fmt::Display for LxfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(w) => write!(f, "file truncated while reading {w}"),
            Self::BadMagic(m) => write!(f, "bad magic {m:02x?} (want \"LXF\\0\" or \"LLF\\0\")"),
            Self::BadVersion(v) => write!(f, "unsupported format version {v}"),
            Self::BadArch(a) => write!(f, "unsupported architecture {a} (want 1 = x86_64)"),
            Self::BadFileType(t) => write!(f, "unknown file type {t}"),
            Self::MagicTypeMismatch => write!(f, "magic / file type mismatch"),
            Self::NoText => write!(f, "no .text section"),
            Self::TextTooLarge(n) => write!(f, ".text too large ({n} bytes)"),
            Self::SectionOutOfBounds(n) => write!(f, "section {n} lies outside the file"),
            Self::BadTableSize(n) => write!(f, "{n} size is not a multiple of its entry size"),
            Self::OffsetOutOfText { what, offset } => {
                write!(f, "{what} offset 0x{offset:x} is outside .text")
            }
            Self::UnsupportedReloc(t) => write!(f, "unsupported relocation type {t}"),
            Self::BadKernel(w) => write!(f, "invalid kernel image: {w}"),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[allow(dead_code)]
pub struct Export {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub library: String,
    pub function: String,
    /// Offset in `.text` of the 8-byte IAT cell the loader must fill in.
    pub iat_slot: u32,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
#[allow(dead_code)]
pub struct Reloc {
    pub offset: u32,
    pub kind: u8,
}

/// One loadable kernel segment (an entry of `.kseg`).
#[derive(Debug, Clone, Copy)]
pub struct Segment {
    pub vaddr: u64,
    /// Start of the segment's bytes inside `.text`.
    pub offset: u32,
    pub filesz: u32,
    pub memsz: u32,
    pub flags: u32,
}

/// A fully parsed and validated LXF/LLF file (owns its `.text` bytes).
#[derive(Debug)]
pub struct LxfImage {
    pub filetype: u16,
    pub flags: u32,
    pub entry_offset: u32,
    pub text: Vec<u8>,
    pub exports: Vec<Export>,
    pub imports: Vec<Import>,
    pub relocs: Vec<Reloc>,
    /// Kernel images only (empty otherwise).
    pub segments: Vec<Segment>,
}

impl LxfImage {
    pub fn is_kernel(&self) -> bool {
        self.filetype == TYPE_EXECUTABLE && self.flags & FLAG_KERNEL != 0
    }

    /// Virtual address of the entry point of a kernel image.
    pub fn kernel_entry(&self) -> Option<u64> {
        let e = u64::from(self.entry_offset);
        self.segments.iter().find_map(|s| {
            let (o, n) = (u64::from(s.offset), u64::from(s.filesz));
            (s.flags & KSEG_X != 0 && e >= o && e < o + n).then(|| s.vaddr + (e - o))
        })
    }

    pub fn is_library(&self) -> bool {
        self.filetype == TYPE_LIBRARY
    }

    pub fn has_libmain(&self) -> bool {
        self.is_library() && self.flags & FLAG_HAS_LIBMAIN != 0
    }

    pub fn find_export(&self, name: &str) -> Option<&Export> {
        self.exports.iter().find(|e| e.name == name)
    }

    pub fn parse(buf: &[u8]) -> Result<Self, LxfError> {
        if buf.len() < FILEHDR_SIZE {
            return Err(LxfError::Truncated("file header"));
        }
        let magic: [u8; 4] = buf[0..4].try_into().unwrap();
        let version = u16_at(buf, 4);
        let arch = u16_at(buf, 6);
        let filetype = u16_at(buf, 8);
        let num_sections = u16_at(buf, 10) as usize;
        let entry_offset = u32_at(buf, 12);
        let flags = u32_at(buf, 16);

        if magic != MAGIC_LXF && magic != MAGIC_LLF {
            return Err(LxfError::BadMagic(magic));
        }
        if version != VERSION {
            return Err(LxfError::BadVersion(version));
        }
        if arch != ARCH_X86_64 {
            return Err(LxfError::BadArch(arch));
        }
        if filetype != TYPE_EXECUTABLE && filetype != TYPE_LIBRARY {
            return Err(LxfError::BadFileType(filetype));
        }
        if (magic == MAGIC_LXF) != (filetype == TYPE_EXECUTABLE) {
            return Err(LxfError::MagicTypeMismatch);
        }

        // Section table.
        let table_end = num_sections
            .checked_mul(SECHDR_SIZE)
            .and_then(|n| n.checked_add(FILEHDR_SIZE))
            .filter(|&end| end <= buf.len())
            .ok_or(LxfError::Truncated("section table"))?;
        let _ = table_end;

        let mut text: Option<&[u8]> = None;
        let mut edata: Option<&[u8]> = None;
        let mut idata: Option<&[u8]> = None;
        let mut reloc: Option<&[u8]> = None;
        let mut kseg: Option<&[u8]> = None;

        for i in 0..num_sections {
            let at = FILEHDR_SIZE + i * SECHDR_SIZE;
            let raw_name = &buf[at..at + 8];
            let file_offset = u32_at(buf, at + 8) as usize;
            let size = u32_at(buf, at + 12) as usize;
            // (section flags at at+16 are informational for this loader)

            let name = trim_nul(raw_name);
            let data = file_offset
                .checked_add(size)
                .filter(|&end| end <= buf.len())
                .map(|end| &buf[file_offset..end])
                .ok_or_else(|| {
                    LxfError::SectionOutOfBounds(String::from_utf8_lossy(name).into_owned())
                })?;

            // First section with a given name wins, like LordFile.section().
            match name {
                b".text" if text.is_none() => text = Some(data),
                b".edata" if edata.is_none() => edata = Some(data),
                b".idata" if idata.is_none() => idata = Some(data),
                b".reloc" if reloc.is_none() => reloc = Some(data),
                b".kseg" if kseg.is_none() => kseg = Some(data),
                _ => {}
            }
        }

        let text = text.ok_or(LxfError::NoText)?;
        if text.len() > MAX_TEXT_SIZE {
            return Err(LxfError::TextTooLarge(text.len()));
        }
        let text_len = text.len() as u64;
        let in_text = |what: &'static str, off: u32, width: u64| -> Result<(), LxfError> {
            if u64::from(off) + width <= text_len {
                Ok(())
            } else {
                Err(LxfError::OffsetOutOfText { what, offset: off })
            }
        };

        // Entry point (executables always; libraries only with LibraryMain).
        let entry_is_code = filetype == TYPE_EXECUTABLE || flags & FLAG_HAS_LIBMAIN != 0;
        if entry_is_code {
            in_text("entry", entry_offset, 1)?;
        }

        let mut exports = Vec::new();
        if let Some(d) = edata.filter(|d| !d.is_empty()) {
            if d.len() % EXPORT_SIZE != 0 {
                return Err(LxfError::BadTableSize(".edata"));
            }
            for e in d.chunks_exact(EXPORT_SIZE) {
                let offset = u32_at(e, 32);
                let size = u32_at(e, 36);
                in_text("export", offset, 1)?;
                exports.push(Export {
                    name: cstr(&e[..NAME_LEN]),
                    offset,
                    size,
                });
            }
        }

        let mut imports = Vec::new();
        if let Some(d) = idata.filter(|d| !d.is_empty()) {
            if d.len() % IMPORT_SIZE != 0 {
                return Err(LxfError::BadTableSize(".idata"));
            }
            for e in d.chunks_exact(IMPORT_SIZE) {
                let iat_slot = u32_at(e, 64);
                in_text("IAT slot", iat_slot, 8)?;
                imports.push(Import {
                    library: cstr(&e[..NAME_LEN]),
                    function: cstr(&e[NAME_LEN..2 * NAME_LEN]),
                    iat_slot,
                });
            }
        }

        let mut relocs = Vec::new();
        if let Some(d) = reloc.filter(|d| !d.is_empty()) {
            if d.len() % RELOC_SIZE != 0 {
                return Err(LxfError::BadTableSize(".reloc"));
            }
            for e in d.chunks_exact(RELOC_SIZE) {
                let offset = u32_at(e, 0);
                let kind = e[4];
                if kind != RELOC_TYPE_ABS64 {
                    return Err(LxfError::UnsupportedReloc(kind));
                }
                in_text("relocation", offset, 8)?;
                relocs.push(Reloc { offset, kind });
            }
        }

        let mut segments = Vec::new();
        if filetype == TYPE_EXECUTABLE && flags & FLAG_KERNEL != 0 {
            if !relocs.is_empty() || !imports.is_empty() {
                return Err(LxfError::BadKernel("kernel images carry no .reloc / .idata"));
            }
            let d = kseg.filter(|d| !d.is_empty()).ok_or(LxfError::BadKernel("no .kseg"))?;
            if d.len() % KSEG_SIZE != 0 {
                return Err(LxfError::BadTableSize(".kseg"));
            }
            for e in d.chunks_exact(KSEG_SIZE) {
                segments.push(Segment {
                    vaddr: u64_at(e, 0),
                    offset: u32_at(e, 8),
                    filesz: u32_at(e, 12),
                    memsz: u32_at(e, 16),
                    flags: u32_at(e, 20),
                });
            }
            validate_segments(&segments, text.len())?;
        } else if flags & FLAG_KERNEL != 0 {
            return Err(LxfError::BadKernel("FLAG_KERNEL on a library"));
        }

        let img = Self {
            filetype,
            flags,
            entry_offset,
            text: text.to_vec(),
            exports,
            imports,
            relocs,
            segments,
        };
        if img.is_kernel() && img.kernel_entry().is_none() {
            return Err(LxfError::BadKernel("entry point is not inside an executable segment"));
        }
        Ok(img)
    }
}

/// Same rules as `validate_segments()` in tools/lxf/lordfmt.py.
fn validate_segments(segs: &[Segment], text_len: usize) -> Result<(), LxfError> {
    use LxfError::BadKernel as Bad;
    if segs.is_empty() {
        return Err(Bad("no segments"));
    }
    if segs.len() > 16 {
        return Err(Bad("too many segments"));
    }
    for s in segs {
        if s.vaddr % 4096 != 0 || s.offset % 4096 != 0 {
            return Err(Bad("segment not 4 KiB aligned"));
        }
        if s.vaddr < 0xFFFF_8000_0000_0000 {
            return Err(Bad("segment not in the higher half"));
        }
        if s.memsz == 0 || s.filesz > s.memsz {
            return Err(Bad("segment sizes"));
        }
        if u64::from(s.offset) + u64::from(s.filesz) > text_len as u64 {
            return Err(Bad("segment bytes lie outside .text"));
        }
        if s.flags & KSEG_W != 0 && s.flags & KSEG_X != 0 {
            return Err(Bad("segment is writable and executable (W^X)"));
        }
        if s.vaddr.checked_add(u64::from(s.memsz)).is_none() {
            return Err(Bad("segment wraps the address space"));
        }
    }
    for (i, a) in segs.iter().enumerate() {
        for b in &segs[i + 1..] {
            let (a0, a1) = (a.vaddr, a.vaddr + u64::from(a.memsz));
            let (b0, b1) = (b.vaddr, b.vaddr + u64::from(b.memsz));
            if a0 < b1 && b0 < a1 {
                return Err(Bad("segments overlap in memory"));
            }
            let (a0, a1) = (u64::from(a.offset), u64::from(a.offset) + u64::from(a.filesz));
            let (b0, b1) = (u64::from(b.offset), u64::from(b.offset) + u64::from(b.filesz));
            if a.filesz != 0 && b.filesz != 0 && a0 < b1 && b0 < a1 {
                return Err(Bad("segments overlap inside .text"));
            }
        }
    }
    Ok(())
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

fn trim_nul(b: &[u8]) -> &[u8] {
    let end = b.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
    &b[..end]
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}
