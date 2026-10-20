// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Adam55Lord

//! Booting an LXF **kernel image** (`FLAG_KERNEL`): the part that makes this a real
//! bootloader rather than a program runner.
//!
//! ```text
//!  while UEFI boot services are alive           after ExitBootServices (no allocator!)
//!  ------------------------------------         ------------------------------------------
//!  copy each .kseg segment to physical RAM      convert the UEFI memory map -> MemEntry[]
//!  find the framebuffer (GOP), RSDP, CPUs       build page tables from the reserved pool:
//!  reserve: page-table pool, stack, boot info,    kernel segments at their virtual address (W^X)
//!           AP start-up pages                     all RAM at HHDM_OFFSET + phys (RW, NX)
//!  exit boot services                             framebuffer (write-combining)
//!                                                 identity map of the hand-off stub only
//!                                               lordboot_handoff: EFER.NXE, CR0.WP, CR3, GDT, jmp kernel
//! ```
//!
//! The protocol itself is specified in `src/protocol.rs` (a byte-identical copy lives in the kernel package)
//! and `docs/19-lxf-boot-protocol.md`.

use alloc::string::String;
use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::convert::Infallible;

use uefi::boot::{self, AllocateType, MemoryType};
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::table::cfg::ConfigTableEntry;
use uefi::{println, system};

use crate::loader::LoadError;
use crate::lxf::{LxfImage, KSEG_R, KSEG_W, KSEG_X};
use crate::protocol::{self as proto, CpuEntry, FbInfo, KernelBoot, MemEntry};
use crate::pt::{Mapper, Perm, Pool, PtError, PAGE};

/// UEFI memory types in the OS-reserved range, so the final memory map tells the
/// kernel exactly which memory is its image and which is the loader's.
const MEM_KERNEL: MemoryType = MemoryType::custom(0x8000_0001);
const MEM_BOOT: MemoryType = MemoryType::custom(0x8000_0002);

const STACK_PAGES: u64 = 16; // 64 KiB, the default size for the kernel boot stack
const MEMMAP_CAP: usize = 1024;
const MEMMAP_PAGES: u64 = (MEMMAP_CAP * size_of::<MemEntry>()).div_ceil(PAGE as usize) as u64;
const MAX_CPUS: usize = 256;

fn kerr(msg: impl Into<String>) -> LoadError {
    LoadError::Kernel(msg.into())
}

fn pages_for(bytes: u64) -> u64 {
    bytes.div_ceil(PAGE)
}

/// Allocates zeroed pages; returns the physical (= identity) address.
fn alloc_pages(how: AllocateType, ty: MemoryType, pages: u64) -> Result<u64, LoadError> {
    let p = boot::allocate_pages(how, ty, pages as usize)?;
    // SAFETY: freshly allocated, `pages * 4096` bytes are ours.
    unsafe { core::ptr::write_bytes(p.as_ptr(), 0, (pages * PAGE) as usize) };
    Ok(p.as_ptr() as u64)
}

// ---------------------------------------------------------------------------
// Memory map classification
// ---------------------------------------------------------------------------

fn classify(ty: MemoryType) -> u32 {
    use proto::kind::*;
    match ty {
        MemoryType::CONVENTIONAL | MemoryType::BOOT_SERVICES_CODE | MemoryType::BOOT_SERVICES_DATA => USABLE,
        MemoryType::LOADER_CODE | MemoryType::LOADER_DATA | MEM_BOOT => BOOTLOADER_RECLAIMABLE,
        MEM_KERNEL => KERNEL_AND_MODULES,
        MemoryType::RUNTIME_SERVICES_CODE | MemoryType::RUNTIME_SERVICES_DATA => RESERVED_MAPPED,
        MemoryType::ACPI_RECLAIM => ACPI_RECLAIMABLE,
        MemoryType::ACPI_NON_VOLATILE => ACPI_NVS,
        MemoryType::UNUSABLE => BAD_MEMORY,
        _ => RESERVED, // MMIO, PAL code, persistent memory, unknown
    }
}

/// Kinds that get a read/write, no-execute mapping in the HHDM.
fn hhdm_mapped(kind: u32) -> bool {
    use proto::kind::*;
    matches!(
        kind,
        USABLE | ACPI_RECLAIMABLE | ACPI_NVS | BOOTLOADER_RECLAIMABLE | KERNEL_AND_MODULES | RESERVED_MAPPED
    )
}

/// Appends a range, trimming overlap with the previous one and merging equal neighbours.
fn push_range(out: &mut [MemEntry], n: &mut usize, dropped: &mut u64, mut base: u64, mut len: u64, kind: u32) {
    if len == 0 {
        return;
    }
    if *n > 0 {
        let end = out[*n - 1].base + out[*n - 1].length;
        if base < end {
            let trim = end - base;
            if trim >= len {
                return;
            }
            base += trim;
            len -= trim;
        }
        let last = &mut out[*n - 1];
        if last.kind == kind && last.base + last.length == base {
            last.length += len;
            return;
        }
    }
    if *n == out.len() {
        *dropped += 1;
        return;
    }
    out[*n] = MemEntry { base, length: len, kind, _pad: 0 };
    *n += 1;
}

/// Inserts a range in address order only if it overlaps nothing (used for the framebuffer).
fn insert_free(out: &mut [MemEntry], n: &mut usize, base: u64, len: u64, kind: u32) -> bool {
    let end = base + len;
    let idx = out[..*n].iter().position(|e| e.base >= base).unwrap_or(*n);
    if idx > 0 && out[idx - 1].base + out[idx - 1].length > base {
        return false;
    }
    if idx < *n && end > out[idx].base {
        return false;
    }
    if *n == out.len() {
        return false;
    }
    let mut i = *n;
    while i > idx {
        out[i] = out[i - 1];
        i -= 1;
    }
    out[idx] = MemEntry { base, length: len, kind, _pad: 0 };
    *n += 1;
    true
}

// ---------------------------------------------------------------------------
// Firmware queries (boot services still alive)
// ---------------------------------------------------------------------------

struct Fb {
    phys: u64,
    size: u64,
    info: FbInfo,
}

fn query_framebuffer() -> Option<Fb> {
    let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut gop = boot::open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
    let mi = gop.current_mode_info();
    let (w, h) = mi.resolution();
    let (r, g, b) = match mi.pixel_format() {
        PixelFormat::Rgb => ((8, 0), (8, 8), (8, 16)),
        PixelFormat::Bgr => ((8, 16), (8, 8), (8, 0)),
        PixelFormat::Bitmask => {
            let m = mi.pixel_bitmask()?;
            let f = |mask: u32| (mask.count_ones() as u8, mask.trailing_zeros() as u8);
            (f(m.red), f(m.green), f(m.blue))
        }
        PixelFormat::BltOnly => return None, // no linear framebuffer
    };
    let mut fb = gop.frame_buffer();
    let (base, size) = (fb.as_mut_ptr() as u64, fb.size() as u64);
    if base == 0 || size == 0 {
        return None;
    }
    Some(Fb {
        phys: base,
        size,
        info: FbInfo {
            address: 0, // filled in once the HHDM is chosen
            width: w as u32,
            height: h as u32,
            pitch: (mi.stride() * 4) as u32,
            bpp: 32,
            _pad0: 0,
            red_size: r.0,
            red_shift: r.1,
            green_size: g.0,
            green_shift: g.1,
            blue_size: b.0,
            blue_shift: b.1,
            _pad1: [0; 2],
        },
    })
}

fn query_rsdp() -> Option<u64> {
    system::with_config_table(|tables| {
        let find = |guid| tables.iter().find(|t| t.guid == guid).map(|t| t.address as u64);
        find(ConfigTableEntry::ACPI2_GUID).or_else(|| find(ConfigTableEntry::ACPI_GUID))
    })
}

/// Reads `[phys, phys+len)` (identity mapped while boot services are alive).
///
/// # Safety
/// The range must be readable memory.
unsafe fn phys_bytes<'a>(phys: u64, len: usize) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(phys as *const u8, len) }
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Finds a table by signature through RSDP -> XSDT/RSDT and returns its bytes.
fn find_acpi_table(rsdp: u64, sig: &[u8; 4]) -> Option<&'static [u8]> {
    // SAFETY: firmware-provided ACPI structures, identity mapped; lengths are checked
    // against sane bounds before use.
    unsafe {
        let r = phys_bytes(rsdp, 20);
        if &r[0..8] != b"RSD PTR " {
            return None;
        }
        let revision = r[15];
        let (root, wide) = if revision >= 2 {
            let x = le64(phys_bytes(rsdp, 36), 24);
            if x != 0 { (x, true) } else { (u64::from(le32(r, 16)), false) }
        } else {
            (u64::from(le32(r, 16)), false)
        };
        if root == 0 {
            return None;
        }
        let hdr = phys_bytes(root, 36);
        let len = le32(hdr, 4) as usize;
        if !(36..=1 << 20).contains(&len) {
            return None;
        }
        let tbl = phys_bytes(root, len);
        let step = if wide { 8 } else { 4 };
        let mut at = 36;
        while at + step <= len {
            let addr = if wide { le64(tbl, at) } else { u64::from(le32(tbl, at)) };
            at += step;
            if addr == 0 {
                continue;
            }
            let h = phys_bytes(addr, 8);
            if &h[0..4] == sig {
                let l = le32(h, 4) as usize;
                if (36..=1 << 22).contains(&l) {
                    return Some(phys_bytes(addr, l));
                }
            }
        }
        None
    }
}

/// Enabled logical CPUs from the ACPI MADT (xAPIC ids only: the kernel is xAPIC-only).
fn query_cpus(rsdp: u64) -> Vec<CpuEntry> {
    let mut cpus: Vec<CpuEntry> = Vec::new();
    let Some(madt) = find_acpi_table(rsdp, b"APIC") else { return cpus };
    let mut at = 44; // header (36) + local APIC address (4) + flags (4)
    while at + 2 <= madt.len() {
        let (ty, len) = (madt[at], madt[at + 1] as usize);
        if len < 2 || at + len > madt.len() {
            break;
        }
        let e = &madt[at..at + len];
        let entry = match ty {
            0 if len >= 8 && le32(e, 4) & 0b11 != 0 => Some(CpuEntry { lapic_id: u32::from(e[3]), processor_id: u32::from(e[2]) }),
            9 if len >= 16 && le32(e, 8) & 0b11 != 0 && le32(e, 4) < 255 => {
                Some(CpuEntry { lapic_id: le32(e, 4), processor_id: le32(e, 12) })
            }
            _ => None,
        };
        if let Some(c) = entry {
            if cpus.len() < MAX_CPUS && !cpus.iter().any(|x| x.lapic_id == c.lapic_id) {
                cpus.push(c);
            }
        }
        at += len;
    }
    cpus
}

fn bsp_lapic_id() -> u32 {
    // `__cpuid` is a safe fn on newer Rust but `unsafe` on the minimum supported 1.85,
    // so the block is kept and the lint is silenced.
    // SAFETY: CPUID leaf 1 exists on every x86-64 CPU.
    #[allow(unused_unsafe)]
    unsafe {
        core::arch::x86_64::__cpuid(1).ebx >> 24
    }
}

// ---------------------------------------------------------------------------
// After ExitBootServices: no allocator, no console. COM1 only.
// ---------------------------------------------------------------------------

fn com1_write(s: &str) {
    for b in s.bytes() {
        // SAFETY: legacy UART ports; a missing UART just reads 0xFF, the spin is bounded.
        unsafe {
            let mut spins = 0u32;
            loop {
                let lsr: u8;
                asm!("in al, dx", out("al") lsr, in("dx") 0x3FDu16, options(nomem, nostack, preserves_flags));
                if lsr & 0x20 != 0 || spins > 100_000 {
                    break;
                }
                spins += 1;
            }
            asm!("out dx, al", in("dx") 0x3F8u16, in("al") b, options(nomem, nostack, preserves_flags));
        }
    }
}

fn fatal(msg: &str) -> ! {
    com1_write("\r\n[lord-boot] FATAL after ExitBootServices: ");
    com1_write(msg);
    com1_write("\r\n");
    loop {
        // SAFETY: nothing else can run; stop this CPU.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

fn pt_fatal(e: PtError, what: &str) -> ! {
    com1_write("[lord-boot] page tables: ");
    com1_write(what);
    com1_write(match e {
        PtError::PoolExhausted => ": reserved page-table pool exhausted\r\n",
        PtError::Conflict => ": conflicting mapping\r\n",
    });
    fatal("cannot build the kernel's address space")
}

// ---------------------------------------------------------------------------
// The hand-off stub
// ---------------------------------------------------------------------------

/// Read by `lordboot_handoff` before it switches page tables (it lives in firmware memory).
#[repr(C)]
struct HandoffArgs {
    pml4_phys: u64,   // +0
    stack_top: u64,   // +8   virtual
    entry: u64,       // +16  virtual
    info: u64,        // +24  virtual, passed in RDI
    gdtr_virt: u64,   // +32  virtual address of the 10-byte GDT pseudo-descriptor
}

unsafe extern "efiapi" {
    fn lordboot_handoff(args: *const HandoffArgs) -> !;
    static lordboot_handoff_start: u8;
    static lordboot_handoff_end: u8;
}

// MS x64 ABI: RCX = &HandoffArgs. Runs on identity-mapped pages that the new PML4
// also maps at the same addresses; the kernel removes that slot-0 mapping afterwards.
global_asm!(
    ".text",
    ".balign 16",
    ".global lordboot_handoff_start",
    "lordboot_handoff_start:",
    ".global lordboot_handoff",
    "lordboot_handoff:",
    "    cli",
    "    cld",
    "    mov r10, [rcx + 0]",  // new PML4 (physical)
    "    mov r12, [rcx + 8]",  // stack top (not RDX: rdmsr clobbers EDX:EAX)
    "    mov r8,  [rcx + 16]", // kernel entry
    "    mov r9,  [rcx + 24]", // boot info
    "    mov r11, [rcx + 32]", // GDT pseudo-descriptor
    // EFER.NXE: the kernel's page tables use the NX bit.
    "    mov ecx, 0xC0000080",
    "    rdmsr",
    "    or eax, 0x800",
    "    wrmsr",
    // CR0.WP: supervisor writes honour read-only pages (W^X means something).
    "    mov rax, cr0",
    "    or rax, 0x10000",
    "    mov cr0, rax",
    // Switch address space. We keep running because this code is identity mapped there too.
    "    mov cr3, r10",
    "    mov rsp, r12",
    "    lgdt [r11]",
    // Reload CS with a far return, then the data segments.
    "    lea rax, [rip + 2f]",
    "    push 0x08",
    "    push rax",
    "    retfq",
    "2:",
    "    mov ax, 0x10",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ss, ax",
    "    xor eax, eax",
    "    mov fs, ax",
    "    mov gs, ax",
    // Empty IDT: a fault before the kernel installs its own is a deterministic triple fault.
    "    push 0",
    "    push 0",
    "    lidt [rsp]",
    "    add rsp, 16",
    "    xor ebp, ebp",
    "    mov rdi, r9",
    "    jmp r8",
    ".global lordboot_handoff_end",
    "lordboot_handoff_end:",
);

// ---------------------------------------------------------------------------
// The boot path
// ---------------------------------------------------------------------------

/// Loads and starts the kernel. Only returns on error (before boot services end).
pub fn boot_kernel(img: &LxfImage) -> Result<Infallible, LoadError> {
    let entry_virt = img.kernel_entry().ok_or_else(|| kerr("kernel has no entry point"))?;

    // 1. Kernel image in physical memory: segments back to back, each page aligned.
    let total_pages: u64 = img.segments.iter().map(|s| pages_for(u64::from(s.memsz))).sum();
    let kernel_phys = alloc_pages(AllocateType::AnyPages, MEM_KERNEL, total_pages)?;
    let mut seg_phys = Vec::with_capacity(img.segments.len());
    let mut cursor = kernel_phys;
    for s in &img.segments {
        let (o, n) = (s.offset as usize, s.filesz as usize);
        // SAFETY: validated by the parser: o+n <= text.len(); destination inside our allocation.
        unsafe { core::ptr::copy_nonoverlapping(img.text[o..o + n].as_ptr(), cursor as *mut u8, n) };
        seg_phys.push(cursor);
        cursor += pages_for(u64::from(s.memsz)) * PAGE;
    }
    for (s, p) in img.segments.iter().zip(&seg_phys) {
        println!("[kboot] segment {:#018x} {}{}{} {:>7} bytes (+{} bss) -> phys {:#x}",
            s.vaddr,
            if s.flags & KSEG_R != 0 { 'r' } else { '-' },
            if s.flags & KSEG_W != 0 { 'w' } else { '-' },
            if s.flags & KSEG_X != 0 { 'x' } else { '-' },
            s.filesz, s.memsz - s.filesz, p);
    }
    println!("[kboot] entry {entry_virt:#018x}");

    // 2. Facts from the firmware.
    let fb = query_framebuffer();
    let rsdp = query_rsdp();
    let cpus = rsdp.map(query_cpus).unwrap_or_default();
    match &fb {
        Some(f) => println!("[kboot] framebuffer {}x{} pitch {} at {:#x}", f.info.width, f.info.height, f.info.pitch, f.phys),
        None => println!("[kboot] no linear framebuffer (serial only)"),
    }
    println!("[kboot] ACPI RSDP {}, {} CPU(s) in the MADT, BSP lapic id {}",
        rsdp.map_or(String::from("missing"), |r| alloc::format!("{r:#x}")), cpus.len(), bsp_lapic_id());

    // 3. Size the page-table pool from the current memory map (+ margin: it changes a little
    //    when we allocate and again at ExitBootServices).
    let (n_desc, max_ram) = {
        let map = boot::memory_map(MemoryType::LOADER_DATA)?;
        let mut max = 0u64;
        for d in map.entries() {
            if hhdm_mapped(classify(d.ty)) {
                max = max.max(d.phys_start + d.page_count * PAGE);
            }
        }
        (map.len() as u64, max)
    };
    let fb_pages = fb.as_ref().map_or(0, |f| pages_for(f.size) + 1);
    let pool_pages = 32
        + 2 * (n_desc + 64)
        + (max_ram >> 30)
        + (total_pages >> 9)
        + (fb_pages >> 9)
        + 2 * img.segments.len() as u64;

    // 4. Everything that must outlive boot services, as MEM_BOOT (the kernel never frees it).
    let pool_phys = alloc_pages(AllocateType::AnyPages, MEM_BOOT, pool_pages)?;
    let stack_phys = alloc_pages(AllocateType::AnyPages, MEM_BOOT, STACK_PAGES)?;
    // boot info (1) + memory map + CPU list (1) + GDT/IDT scratch (1)
    let info_pages = 1 + MEMMAP_PAGES + 1 + 1;
    let info_phys = alloc_pages(AllocateType::AnyPages, MEM_BOOT, info_pages)?;
    let memmap_phys = info_phys + PAGE;
    let cpus_phys = memmap_phys + MEMMAP_PAGES * PAGE;
    let gdt_phys = cpus_phys + PAGE;

    // AP start-up: one page below 1 MiB for the trampoline, three below 4 GiB for the AP page
    // tables. Optional: without them the kernel runs on the boot CPU only.
    let ap_page = alloc_pages(AllocateType::MaxAddress(0x9F000), MEM_BOOT, 1).ok();
    let ap_tables = alloc_pages(AllocateType::MaxAddress(0xFFFF_F000), MEM_BOOT, 3).ok();
    let (ap_boot_phys, ap_pml4_phys) = match (ap_page, ap_tables) {
        (Some(page), Some(t)) => {
            // SAFETY: three zeroed pages we own: PML4, PDPT, PD.
            unsafe {
                let (pml4, pdpt, pd) = (t as *mut u64, (t + PAGE) as *mut u64, (t + 2 * PAGE) as *mut u64);
                pml4.write((t + PAGE) | 0b11);
                pdpt.write((t + 2 * PAGE) | 0b11);
                pd.write(0b11 | (1 << 7)); // 2 MiB identity page at physical 0
            }
            (page, t)
        }
        _ => (0, 0),
    };
    if ap_boot_phys == 0 {
        println!("[kboot] warning: no low memory for the AP trampoline; the kernel will run on one CPU");
    }

    // Tiny GDT for the hand-off: null, 64-bit code (0x08), data (0x10).
    // SAFETY: gdt_phys is our zeroed page.
    unsafe {
        let g = gdt_phys as *mut u64;
        g.add(1).write(0x00AF_9A00_0000_FFFF); // L=1 code, DPL0
        g.add(2).write(0x00CF_9200_0000_FFFF); // data, DPL0
        let ptr = (gdt_phys + 64) as *mut u8;
        (ptr as *mut u16).write(3 * 8 - 1);
        (ptr.add(2) as *mut u64).write_unaligned(proto::HHDM_OFFSET + gdt_phys);
    }

    // Boot services, watchdog: nothing will pet it from here on.
    let _ = boot::set_watchdog_timer(0, 0x10000, None);

    println!("[kboot] leaving UEFI boot services; control passes to the kernel");

    // ===== point of no return: no allocation, no console from here ======================
    // SAFETY: we own everything we touch and never use boot services afterwards.
    let mut map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    map.sort();

    // 5. Memory map for the kernel.
    // SAFETY: memmap_phys points at MEMMAP_PAGES zeroed pages we own.
    let out = unsafe { core::slice::from_raw_parts_mut(memmap_phys as *mut MemEntry, MEMMAP_CAP) };
    let (mut n, mut dropped) = (0usize, 0u64);
    for d in map.entries() {
        push_range(out, &mut n, &mut dropped, d.phys_start, d.page_count * PAGE, classify(d.ty));
    }
    let hhdm = proto::HHDM_OFFSET;
    let mut fb_mapped_by_hhdm = false;
    if let Some(f) = &fb {
        let base = f.phys & !(PAGE - 1);
        let len = pages_for(f.size + (f.phys - base)) * PAGE;
        if !insert_free(out, &mut n, base, len, proto::kind::FRAMEBUFFER) {
            // The range overlaps something already described (e.g. it is RAM): it is
            // reachable through the HHDM when that kind is mapped, otherwise not at all.
            fb_mapped_by_hhdm = out[..n]
                .iter()
                .any(|e| e.base <= base && base + len <= e.base + e.length && hhdm_mapped(e.kind));
        }
    }

    // 6. Page tables.
    // SAFETY: pool_phys is our pool.
    let mut pool = unsafe { Pool::new(pool_phys, pool_pages) };
    let mut m = match Mapper::new(&mut pool) {
        Ok(m) => m,
        Err(e) => pt_fatal(e, "PML4"),
    };
    // 6a. Kernel segments at the virtual addresses the kernel was linked for.
    for (s, &p) in img.segments.iter().zip(&seg_phys) {
        let perm = match (s.flags & KSEG_W != 0, s.flags & KSEG_X != 0) {
            (_, true) => Perm::Rx,
            (true, _) => Perm::Rw,
            _ => Perm::R,
        };
        if let Err(e) = m.map_range_4k(s.vaddr, p, pages_for(u64::from(s.memsz)) * PAGE, perm) {
            pt_fatal(e, "kernel segment");
        }
    }
    // 6b. The higher-half direct map.
    for e in out[..n].iter().filter(|e| hhdm_mapped(e.kind)) {
        if let Err(err) = m.map_direct(hhdm, e.base, e.length, Perm::Rw) {
            pt_fatal(err, "HHDM");
        }
    }
    // 6c. Framebuffer: write-combining, unless it already is plain RAM in the HHDM.
    let mut fb_info = FbInfo {
        address: 0, width: 0, height: 0, pitch: 0, bpp: 0, _pad0: 0,
        red_size: 0, red_shift: 0, green_size: 0, green_shift: 0, blue_size: 0, blue_shift: 0, _pad1: [0; 2],
    };
    if let Some(f) = &fb {
        let base = f.phys & !(PAGE - 1);
        let len = pages_for(f.size + (f.phys - base)) * PAGE;
        if !fb_mapped_by_hhdm {
            if let Err(e) = m.map_range_4k(hhdm + base, base, len, Perm::RwWc) {
                pt_fatal(e, "framebuffer");
            }
        }
        fb_info = f.info;
        fb_info.address = hhdm + f.phys;
    }
    // 6d. Identity map of the stub only (R-X); the kernel drops PML4 slot 0 on entry.
    // SAFETY: linker-provided symbols delimiting the stub.
    let (s0, s1) = (
        core::ptr::addr_of!(lordboot_handoff_start) as u64 & !(PAGE - 1),
        core::ptr::addr_of!(lordboot_handoff_end) as u64,
    );
    if let Err(e) = m.map_range_4k(s0, s0, pages_for(s1 - s0) * PAGE, Perm::Rx) {
        pt_fatal(e, "hand-off stub");
    }
    let pml4_phys = m.pml4_phys();

    // 7. The boot info for the kernel.
    let cpu_dst = cpus_phys as *mut CpuEntry;
    for (i, c) in cpus.iter().enumerate() {
        // SAFETY: cpus.len() <= MAX_CPUS (256) * 8 bytes <= one page.
        unsafe { cpu_dst.add(i).write(*c) };
    }
    let mut flags = 0;
    if fb.is_some() {
        flags |= proto::FLAG_FRAMEBUFFER;
    }
    if rsdp.is_some() {
        flags |= proto::FLAG_RSDP;
    }
    if !cpus.is_empty() {
        flags |= proto::FLAG_SMP;
    }
    if ap_boot_phys != 0 {
        flags |= proto::FLAG_AP_BOOT;
    }
    let mut name = [0u8; 32];
    let nm = b"Lord Boot";
    name[..nm.len()].copy_from_slice(nm);
    let mut ver = [0u8; 16];
    let v = env!("CARGO_PKG_VERSION").as_bytes();
    ver[..v.len().min(15)].copy_from_slice(&v[..v.len().min(15)]);

    // SAFETY: info_phys is our zeroed page, large enough for KernelBoot.
    unsafe {
        (info_phys as *mut KernelBoot).write(KernelBoot {
            magic: proto::MAGIC,
            version: proto::VERSION,
            size: size_of::<KernelBoot>() as u32,
            flags,
            hhdm_offset: hhdm,
            pml4_phys,
            kernel_phys,
            kernel_size: total_pages * PAGE,
            memmap: hhdm + memmap_phys,
            memmap_len: n as u64,
            memmap_dropped: dropped,
            fb: fb_info,
            rsdp_phys: rsdp.unwrap_or(0),
            cpus: hhdm + cpus_phys,
            cpu_count: cpus.len() as u64,
            bsp_lapic_id: bsp_lapic_id(),
            _pad2: 0,
            ap_boot_phys,
            ap_pml4_phys,
            loader_name: name,
            loader_version: ver,
        });
    }

    let args = HandoffArgs {
        pml4_phys,
        stack_top: hhdm + stack_phys + STACK_PAGES * PAGE,
        entry: entry_virt,
        info: hhdm + info_phys,
        gdtr_virt: hhdm + gdt_phys + 64,
    };
    // SAFETY: all addresses above are mapped in the new tables; the stub is identity mapped there.
    unsafe { lordboot_handoff(&args) }
}
