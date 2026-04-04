# Kobo Cross-Compilation Build Guide

## Target Device

- Kobo e-reader, Firmware 4.45.23640
- Kernel: Linux 4.9.77, armv7l (MediaTek SoC)
- glibc: 2.19, with symbol versions up to GLIBC_2.18
- Dynamic linker: `ld-2.11.1.so` (from glibc 2.11, symlinked as `ld-linux-armhf.so.3`)
- KOReader loads native plugins via LuaJIT `ffi.load()`

## The Problem

Rust's default shared library output (`cdylib`) segfaults immediately on `dlopen` on the Kobo. This affects **all** Rust cdylibs — even a zero-dependency, `#![no_std]` crate with a single function crashes. 
The root cause most likely is that LLVM's linker (`lld`) produces ELF shared libraries with features (relocation types, segment layout, etc.) that the Kobo's ancient dynamic linker (`ld-2.11.1.so`) cannot handle.

A plain C `.so` compiled with `arm-linux-gnueabihf-gcc` loads fine, because GNU `ld` (from binutils) produces more conservative ELF output.

## The Solution

Two-stage build:

1. **Compile Rust to a static library (`.a`)** using `cargo build` with `staticlib` crate type. This produces compiled ARM machine code in an archive — no ELF shared library structure involved.

2. **Link into a `.so` using GNU `ld`** (via `arm-linux-gnueabihf-gcc -shared`). GNU `ld` creates the final shared library with ELF structures the Kobo's dynamic linker understands.

Key linker flags:
- `-nostdlib`: Prevents GCC from linking its own C runtime startup files and libc, which would embed the Docker container's newer glibc version requirements (2.29+) into the `.so`.
- `-lgcc`: Statically links compiler intrinsics (64-bit division, soft-float ops, etc. needed on 32-bit ARM). This is a static library with no glibc version dependency.
- `-Wl,--whole-archive ... -Wl,--no-whole-archive`: Forces all symbols from the Rust `.a` to be included (otherwise the linker would discard "unused" symbols since nothing inside the `.so` references them).

Libc symbols (`malloc`, `pthread_create`, `open`, etc.) are left as unresolved references in the `.so` and resolved at runtime by the Kobo's own glibc version.

## Build Commands

### Option A: Makefile (macOS Apple Silicon, no Docker)

Prerequisites:
- Rust ARM target: `rustup target add armv7-unknown-linux-gnueabihf`
- ARM GCC cross-compiler:
  ```bash
  brew tap messense/macos-cross-toolchains
  brew install arm-unknown-linux-gnueabihf
  ```

```bash
# Build .so and copy to plugin folder
make install

# Or just build the .so
make kobo
```

Output: `target/libreadium_lcp.so`, copied to `lcpreader.koplugin/libs/`.

### Option B: Docker

```bash
# Build the Docker image
docker build --no-cache -f Dockerfile.kobo -t lcp-kobo .

# Extract the .so
docker run --rm -v $(pwd)/out:/out lcp-kobo
```

Output: `out/libreadium_lcp.so`. Copy this file to the libs directory in `lcpreader.koplugin` for the lua plugin to load at runtime.


## Deployment

Copy `lcpreader.koplugin` folder to `/mnt/onboard/.adds/koreader/plugins/` on the Kobo.

## RUSTFLAGS

- `-C panic=abort`: Uses abort instead of unwinding on panic, reducing binary size and eliminating unwinding runtime. Also set in the workspace `[profile.release]`.
