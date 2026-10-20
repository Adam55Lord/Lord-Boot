// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Adam55Lord

//! Lord Boot — the UEFI bootloader of Lord Core. It loads the kernel from `\kernel.lxf`
//! (Lord eXecutable Format, the only kernel format it accepts) on the EFI System Partition
//! and boots it; without a kernel it runs `\hello.lxf` as a UEFI-hosted test program.

#![no_std]
#![no_main]

extern crate alloc;

mod kboot;
mod loader;
mod lxf;
mod pt;

/// The boot protocol. A byte-identical copy of the kernel's `src/boot/lord_boot/protocol.rs`
/// (kept in sync with `tests/check-protocol-sync.sh`).
mod protocol;

use core::time::Duration;

use uefi::prelude::*;
use uefi::{boot, println, system};

use loader::Loader;

/// The kernel image this bootloader boots (path relative to the ESP root). If it is
/// missing the loader falls back to running [`BOOT_PROGRAM`] as a UEFI-hosted program.
const KERNEL_IMAGE: &str = "kernel.lxf";

/// The program started when there is no kernel image (path relative to the ESP root).
const BOOT_PROGRAM: &str = "hello.lxf";

/// Console output service handed to LXF programs (`LxfBootInfo.put_str`).
///
/// Takes ASCII/UTF-8 bytes, converts to UCS-2 (non-ASCII becomes `?`) and
/// turns bare `\n` into `\r\n`, which the UEFI text console requires.
extern "efiapi" fn put_str(ptr: *const u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: the caller promises `ptr` points at `len` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };

    let mut buf = [0u16; 129];
    let mut n = 0;
    let mut prev_cr = false;
    let flush = |buf: &mut [u16; 129], n: &mut usize| {
        if *n == 0 {
            return;
        }
        buf[*n] = 0;
        if let Ok(s) = uefi::CStr16::from_u16_with_nul(&buf[..=*n]) {
            system::with_stdout(|out| {
                let _ = out.output_string_lossy(s);
            });
        }
        *n = 0;
    };
    for &b in bytes {
        // Worst case one input byte expands to two code units.
        if n + 2 > 128 {
            flush(&mut buf, &mut n);
        }
        match b {
            b'\n' => {
                if !prev_cr {
                    buf[n] = u16::from(b'\r');
                    n += 1;
                }
                buf[n] = u16::from(b'\n');
                n += 1;
            }
            0x20..=0x7e | b'\r' | b'\t' => {
                buf[n] = u16::from(b);
                n += 1;
            }
            _ => {
                buf[n] = u16::from(b'?');
                n += 1;
            }
        }
        prev_cr = b == b'\r';
    }
    flush(&mut buf, &mut n);
}

fn wait_for_key() {
    println!();
    println!("Press any key to exit...");
    let event = system::with_stdin(|i| i.wait_for_key_event());
    if let Ok(ev) = event {
        let mut events = [ev];
        let _ = boot::wait_for_event(&mut events);
        let _ = system::with_stdin(|i| i.read_key());
    } else {
        boot::stall(Duration::from_secs(5));
    }
}

fn run() -> Result<u64, loader::LoadError> {
    let mut loader = Loader::new(put_str)?;

    // A kernel image is booted, not run: on success this never returns.
    if let Some(image) = loader.read_image(KERNEL_IMAGE)? {
        if !image.is_kernel() {
            return Err(loader::LoadError::Kernel(alloc::format!(
                "{KERNEL_IMAGE} is not a kernel image (FLAG_KERNEL missing); name programs hello.lxf instead"
            )));
        }
        println!("[kboot] {KERNEL_IMAGE}: LXF kernel image, {} segment(s)", image.segments.len());
        kboot::boot_kernel(&image)?;
        unreachable!("boot_kernel only returns on error");
    }

    let idx = loader.load(BOOT_PROGRAM)?;
    println!();
    println!("---------------- {BOOT_PROGRAM} output ----------------");
    let rc = loader.run_executable(idx)?;
    println!("---------------------------------------------------");
    loader.unload_all();
    Ok(rc)
}

#[entry]
fn main() -> Status {
    let _ = system::with_stdout(|o| o.clear());
    println!("Lord Boot v{} (UEFI, x86_64)", env!("CARGO_PKG_VERSION"));
    println!();

    let status = match run() {
        Ok(rc) => {
            println!("[loader] {BOOT_PROGRAM} returned {rc:#x}");
            Status::SUCCESS
        }
        Err(e) => {
            println!("[loader] FATAL: {e}");
            Status::LOAD_ERROR
        }
    };
    wait_for_key();
    status
}
