# Lord Boot: UEFI bootloader for Lord Core

Rust 2024, `no_std` UEFI application (x86-64).

```sh
./build.sh            # release -> dist/BOOTX64.EFI   (./build.sh --debug for a debug build)
```

Requirements: Rust **1.85+** via rustup (`rust-toolchain.toml` installs the `x86_64-unknown-uefi` target; the `uefi` crate
comes from crates.io, so the first build needs network access).

To boot it, copy `dist/BOOTX64.EFI` into the `lord-docs-tests` package (`bootloader/` folder, next to the kernel from `lord-core`) and run
`./assemble.sh && ./run.sh` there. This is one of three independent packages: `lord-core` (kernel), `lord-boot` (this), `lord-docs-tests`.

## What it does

* **Kernel mode.** If `\kernel.lkf` exists on the ESP it must be an **LKF** (Lord Kernel Format) image, made by
  `tools/lxf/mkkernel.py` of `lord-core` (format: `SPEC.md` of lxf_tools v3). Lord Boot loads **LKF kernels only**: a
  file in any other format (ELF, the old `kernel.lxf`) is refused with an error. It maps every section at `load_addr + rva`
  with W^X page tables (the kernel must be `FIXED_ADDR`, boot protocol `lordboot`), builds a higher-half direct
  map, exits boot services and jumps into the kernel with `rdi = "LORD"` and `rsi` = the boot info block
  (`src/kboot.rs`, `src/pt.rs`). The default command line of the LKF header is passed on. Hand-off contract:
  `docs/19-lxf-boot-protocol.md` (in `lord-docs-tests`).
* **Program mode.** Without `kernel.lkf` it runs `\hello.lxf` (LXF v2, System V ABI, see `src/loader.rs`) as a UEFI-hosted test program. Samples and tests for this are in
  `bootloader-tests/` in `lord-docs-tests`.

## What is missing

See [`ROADMAP.md`](ROADMAP.md): boot modules / RAM disk, command line and config, protocol v2 (runtime services, RNG),
video modes, menu and fallback, KASLR, Secure Boot, installer, tests.

## Layout

| Path | What |
|---|---|
| `src/main.rs` | UEFI entry, console service, mode selection |
| `src/kboot.rs`, `src/pt.rs` | kernel mode: loading, page tables, memory map, hand-off |
| `src/protocol.rs` | the Lord boot protocol structs (LKF `lordboot`). **Byte-identical twin of the kernel's `src/boot/lord_boot/protocol.rs`**: change both together (`tests/check-protocol-sync.sh` in `lord-docs-tests` checks it) |
| `src/lxf.rs`, `src/loader.rs` | strict LXF/LLF/LKF parser (port of `lordfmt.py`, lxf_tools v3); mapping, relocations, imports, `libmain` (program mode) |

## License

Licensed under either of

* Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
* MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option (`SPDX-License-Identifier: MIT OR Apache-2.0`). Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in Lord Boot by you shall be dual licensed as above, without any additional terms or conditions.
