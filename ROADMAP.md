# Lord Boot: what is missing for a bootloader of a fully working operating system

Written against this directory's source (about 1,800 lines of Rust). "What exists" was checked in the code; every item
under "What is missing" was searched for and not found. Sizes: **S** days, **M** 1-3 weeks, **L** 1-2 months.

## 1. What exists

* A UEFI application for **x86-64 only**, installed as `EFI/BOOT/BOOTX64.EFI`.
* **Kernel mode** (`src/kboot.rs`, `src/pt.rs`): reads `\kernel.lxf` from the volume it was started from, validates it strictly
  (`src/lxf.rs`), maps the segments with W^X permissions at the addresses the kernel was linked for (`.kseg`), builds a higher-half direct
  map, collects the memory map, the GOP framebuffer (the mode the firmware already set), the ACPI RSDP and the CPU list (from the MADT),
  reserves a page for the AP start-up code, exits boot services and jumps to the kernel (boot protocol v1, `src/protocol.rs`).
* **Program mode** (`src/loader.rs`): without a `kernel.lxf` it runs `\hello.lxf` as a UEFI-hosted program (relocations, imports,
  `LibraryMain`); this is a demo/test feature, not part of booting an OS.

## 2. What is missing

### 2.1 Boot modules / initial RAM disk (M) *needed first*
The loader can load exactly one file. A kernel without disk drivers has nothing to run. Add: load any number of extra files (an `initrd`
archive, `init.lxf`, early drivers) into memory and pass them in a `modules` array: `{phys, size, name[64]}` in the protocol, plus a
`FLAG_MODULES`. Memory type `KERNEL_AND_MODULES` already exists in the protocol. Kernel side: `lord-core/ROADMAP.md` 3.15.
*Done when:* the kernel prints the name and size of each module the bootloader loaded.

### 2.2 Configuration and command line (S-M)
Everything is hard-coded (file names, no options). Add a small `\boot.cfg` (key=value or TOML subset): kernel path, module list, kernel
command line (`debug`, `smp=`, `console=serial`, `root=`), framebuffer mode, timeout. Pass the command line as a string in `KernelBoot`
(protocol field + flag); the kernel parses it in `main.rs`.

### 2.3 Boot menu, fallback and recovery (M)
Add: several entries (normal, debug, recovery, previous kernel), keyboard selection through UEFI text input with a timeout, an automatic
fallback when the new kernel fails to load or to report "boot OK" (boot counter in a UEFI variable), a readable error screen instead of
returning to the firmware.

### 2.4 Relocatable kernel and KASLR (M-L)
The kernel is linked at the fixed address `0xFFFFFFFF80000000`; `.kseg` carries absolute virtual addresses and a kernel image has no
relocations. For KASLR add: a position-independent kernel build, a relocation section in kernel LXF images, a random slide within the top
2 GiB, and the slide reported in `KernelBoot`. Needs 2.5 (random seed).

### 2.5 More information for the kernel (S-M) — protocol version 2
Currently missing from `KernelBoot`:
* **UEFI runtime services**: the kernel cannot reboot/power off through firmware, read the RTC (`GetTime`) or use NVRAM variables. Add
  `SetVirtualAddressMap` into the direct map and pass the runtime-services pointer, plus the EFI memory map entries marked as runtime.
* **Random seed** (`EFI_RNG_PROTOCOL`) for KASLR and the kernel's own random pool.
* **SMBIOS** table pointer; **boot device / partition GUID** (so the kernel can find its own root volume); **boot time**; whether Secure
  Boot is on.
* A **kernel physical address / slide** and the **loader's own region** list (if the kernel is to reclaim it).
Bump `VERSION` in `src/protocol.rs`, keep the layout append-only, update the byte-identical copy in the kernel (`lord-core/src/boot/lord_boot/protocol.rs`), run `tests/check-protocol-sync.sh`.

### 2.6 Video mode selection (S)
`kboot.rs` takes whatever GOP mode is active. Add: enumerate modes, pick the best match for a configured resolution (or the native one),
support 32-bit pixel formats only as now but report others cleanly; a text-only fallback when no GOP exists (serial only boot).

### 2.7 Loading from anywhere (M)
Only the file system of the image's own volume is read (`get_image_file_system`). Add: subdirectories (`\Lord\kernel.lxf`), other partitions
and disks (enumerate `SimpleFileSystem` handles, match a partition GUID or label), and later non-FAT file systems if the system partition is
not FAT (needs own drivers in the loader).

### 2.8 Integrity and Secure Boot (M-L)
Add: a hash (SHA-256) of kernel and modules checked before running them (hash list in the config or a signed manifest); signing
`BOOTX64.EFI` so it boots with Secure Boot (own key, or through `shim`); measuring kernel/modules into the TPM (`EFI_TCG2`). Today
nothing is verified beyond structural checks of the LXF.

### 2.9 Installation (M)
There is no way to put Lord Boot on a real disk except copying files by hand to a FAT partition. Add an installer tool (host side or an Lord Core
program): create GPT with an ESP, copy `BOOTX64.EFI` (and optionally register a boot entry in UEFI NVRAM, like `efibootmgr`), copy the
kernel and modules; plus a disk-image builder for QEMU (`mkimage.sh`).

### 2.10 Quality: tests and robustness (M)
The package has no tests. Add host-side unit tests for `lxf.rs` (parser and validator are pure code: run with `cargo test` on the host
target) including malformed and hostile images, fuzzing of the LXF parser, a test that the page-table builder (`pt.rs`) maps what it should,
and a QEMU boot test with a deliberately broken `kernel.lxf` (the bootloader must refuse it, not hang). Check memory-map edge cases
(many entries, `memmap_dropped > 0`).

### 2.11 Other targets (L, only if wanted)
Legacy BIOS boot (not supported at all), 32-bit UEFI, `aarch64` UEFI. Each needs its own entry code, page-table builder and protocol
variant; keep them out until x86-64 UEFI is complete.

### 2.12 Smaller items
* **License:** Lord Boot is `MIT OR Apache-2.0`. `src/protocol.rs` is a byte-identical twin of the kernel's copy; the kernel repository is still GPL-2.0-only, so update the SPDX header of the kernel's `protocol.rs` (or relicense the kernel) so both copies stay identical and `tests/check-protocol-sync.sh` keeps passing.
* **Program mode** (`hello.lxf`): decide whether it stays as a developer test tool or is removed from the production binary behind a cargo
  feature.
* **Debug output:** boot-time log goes to the UEFI console only; add serial output and a verbosity setting from the config (2.2).
* **Chain-loading** another OS or EFI application and **network boot** (PXE/HTTP boot): optional.

## 3. Suggested order
1. 2.1 modules (unblocks kernel milestone M3)  2. 2.2 command line  3. 2.5 protocol v2 (runtime services, RNG, boot device)
4. 2.6 video modes  5. 2.10 tests  6. 2.9 installer  7. 2.3 menu/fallback  8. 2.7 loading from anywhere  9. 2.4 KASLR  10. 2.8 Secure Boot.
