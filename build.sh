#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Adam55Lord
# Builds Lord Boot (UEFI) and copies it to dist/BOOTX64.EFI.
#   ./build.sh            release build (default)
#   ./build.sh --debug    debug build
# To boot it: copy dist/BOOTX64.EFI to lord-docs-tests/bootloader/, then ./assemble.sh && ./run.sh there.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

TARGET=x86_64-unknown-uefi
PDIR=release; CARGO_PROFILE=(--release)
case "${1:-}" in
    "") ;;
    --debug) PDIR=debug; CARGO_PROFILE=() ;;
    -h|--help) sed -n '4,7p' "$0"; exit 0 ;;
    *) echo "error: unknown option '$1' (try --help)" >&2; exit 1 ;;
esac

command -v cargo >/dev/null 2>&1 || { echo "error: cargo not found. Install Rust: https://rustup.rs" >&2; exit 1; }

echo "==> Building Lord Boot ($TARGET, $PDIR)..."
SYSROOT="$(rustc --print sysroot)"
if [ -d "$SYSROOT/lib/rustlib/$TARGET" ]; then
    # Normal rustup toolchain: the UEFI target ships precompiled.
    cargo build "${CARGO_PROFILE[@]}" --target "$TARGET"
else
    # Distro rustc without the UEFI std: build core/alloc from rust-src (needs rust-src + lld).
    RUSTC_BOOTSTRAP=1 CARGO_TARGET_X86_64_UNKNOWN_UEFI_LINKER="${UEFI_LINKER:-lld-link}" \
        cargo build "${CARGO_PROFILE[@]}" --target "$TARGET" \
        -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem
fi

EFI="target/$TARGET/$PDIR/lord-boot.efi"
[ -f "$EFI" ] || { echo "error: $EFI missing after build" >&2; exit 1; }
mkdir -p dist
cp -f "$EFI" dist/BOOTX64.EFI
echo "==> Done: $PWD/dist/BOOTX64.EFI"
echo "    Next: copy it to lord-docs-tests/bootloader/, then run ./assemble.sh and ./run.sh there."
