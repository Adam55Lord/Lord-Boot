// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Adam55Lord

//! x86-64 4-level page-table builder for the kernel hand-off.
//!
//! It runs *after* `ExitBootServices`, when there is no allocator, so every table
//! comes from a pool of pages reserved beforehand (`Pool`). Under UEFI physical
//! memory is identity mapped, so a table's physical address is also the pointer
//! we write through.

const PRESENT: u64 = 1 << 0;
const WRITE: u64 = 1 << 1;
const PWT: u64 = 1 << 3;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const HUGE: u64 = 1 << 7; // PS in a PD entry
const PAT_4K: u64 = 1 << 7; // PAT bit in a PT entry
const NX: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

pub const PAGE: u64 = 4096;
pub const HUGE_PAGE: u64 = 2 * 1024 * 1024;

/// What a leaf mapping may do.
#[derive(Clone, Copy)]
pub enum Perm {
    /// read-only, no-execute
    R,
    /// read/write, no-execute
    Rw,
    /// read + execute
    Rx,
    /// read/write, no-execute, write-combining under the kernel's PAT layout
    /// (PAT index 5 = PAT+PWT; write-through under the firmware's default PAT, which is safe)
    RwWc,
}

impl Perm {
    fn bits(self) -> u64 {
        // Pre-set A/D so the CPU never has to write the tables back.
        let base = PRESENT | ACCESSED;
        match self {
            Perm::R => base | NX,
            Perm::Rw => base | WRITE | DIRTY | NX,
            Perm::Rx => base,
            Perm::RwWc => base | WRITE | DIRTY | NX | PWT | PAT_4K,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PtError {
    /// The reserved pool ran out (the estimate in `kboot.rs` was too small).
    PoolExhausted,
    /// A leaf would replace or sit under an existing mapping.
    Conflict,
}

/// Pages reserved for page tables; handed out zeroed, never freed.
pub struct Pool {
    next: u64,
    end: u64,
}

impl Pool {
    /// # Safety
    /// `[base, base + pages*4096)` must be owned memory, identity mapped.
    pub unsafe fn new(base: u64, pages: u64) -> Self {
        Self { next: base, end: base + pages * PAGE }
    }

    fn take(&mut self) -> Result<*mut u64, PtError> {
        if self.next + PAGE > self.end {
            return Err(PtError::PoolExhausted);
        }
        let p = self.next as *mut u64;
        self.next += PAGE;
        // SAFETY: owned page, see `new`.
        unsafe { core::ptr::write_bytes(p as *mut u8, 0, PAGE as usize) };
        Ok(p)
    }
}

pub struct Mapper<'a> {
    pub pml4: *mut u64,
    pool: &'a mut Pool,
}

impl<'a> Mapper<'a> {
    pub fn new(pool: &'a mut Pool) -> Result<Self, PtError> {
        let pml4 = pool.take()?;
        Ok(Self { pml4, pool })
    }

    pub fn pml4_phys(&self) -> u64 {
        self.pml4 as u64
    }

    /// Next-level table behind `table[idx]`, creating it if absent.
    fn descend(&mut self, table: *mut u64, idx: usize) -> Result<*mut u64, PtError> {
        // SAFETY: `table` is a live 512-entry table and idx < 512.
        unsafe {
            let e = table.add(idx).read();
            if e & PRESENT != 0 {
                if e & HUGE != 0 && table != self.pml4 {
                    // (PS in a PML4/PDPT entry is not used by this builder either)
                    return Err(PtError::Conflict);
                }
                return Ok((e & ADDR_MASK) as *mut u64);
            }
            let t = self.pool.take()?;
            table.add(idx).write(t as u64 | PRESENT | WRITE);
            Ok(t)
        }
    }

    fn walk_to_pd(&mut self, virt: u64) -> Result<*mut u64, PtError> {
        let pdpt = self.descend(self.pml4, ((virt >> 39) & 511) as usize)?;
        self.descend(pdpt, ((virt >> 30) & 511) as usize)
    }

    pub fn map_4k(&mut self, virt: u64, phys: u64, perm: Perm) -> Result<(), PtError> {
        let pd = self.walk_to_pd(virt)?;
        let pdi = ((virt >> 21) & 511) as usize;
        let pt = self.descend(pd, pdi)?;
        let pti = ((virt >> 12) & 511) as usize;
        // SAFETY: pt is a live table, pti < 512.
        unsafe {
            if pt.add(pti).read() & PRESENT != 0 {
                return Err(PtError::Conflict);
            }
            pt.add(pti).write((phys & ADDR_MASK) | perm.bits());
        }
        Ok(())
    }

    pub fn map_2m(&mut self, virt: u64, phys: u64, perm: Perm) -> Result<(), PtError> {
        let pd = self.walk_to_pd(virt)?;
        let pdi = ((virt >> 21) & 511) as usize;
        // SAFETY: pd is a live table, pdi < 512.
        unsafe {
            if pd.add(pdi).read() & PRESENT != 0 {
                return Err(PtError::Conflict);
            }
            // PAT bit of a huge page is bit 12, not bit 7: only plain perms here.
            debug_assert!(!matches!(perm, Perm::RwWc));
            pd.add(pdi).write((phys & ADDR_MASK) | perm.bits() | HUGE);
        }
        Ok(())
    }

    /// Maps `[phys, phys+len)` at `virt_base + phys` (page-aligned arguments):
    /// 2 MiB pages where both addresses allow, 4 KiB pages at the edges.
    pub fn map_direct(&mut self, virt_base: u64, phys: u64, len: u64, perm: Perm) -> Result<(), PtError> {
        let end = phys + len;
        let mut p = phys;
        while p < end {
            if p % HUGE_PAGE == 0 && end - p >= HUGE_PAGE {
                self.map_2m(virt_base + p, p, perm)?;
                p += HUGE_PAGE;
            } else {
                self.map_4k(virt_base + p, p, perm)?;
                p += PAGE;
            }
        }
        Ok(())
    }

    /// Maps `[virt, virt+len)` onto `[phys, ...)` with 4 KiB pages.
    pub fn map_range_4k(&mut self, virt: u64, phys: u64, len: u64, perm: Perm) -> Result<(), PtError> {
        let mut off = 0;
        while off < len {
            self.map_4k(virt + off, phys + off, perm)?;
            off += PAGE;
        }
        Ok(())
    }
}
