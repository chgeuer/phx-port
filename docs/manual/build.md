# Build and release

## Supported build targets

CI builds and tests these native targets:

| Platform | Rust target | GitHub runner |
|---|---|---|
| Linux x64 | `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| macOS x64 | `x86_64-apple-darwin` | `macos-15-intel` |
| macOS ARM64 | `aarch64-apple-darwin` | `macos-15` |

Tagged releases also build `x86_64-pc-windows-msvc`. Public-ingress and PHXP
support target Linux and macOS; Windows retains the port-registry CLI.

## Prerequisites

- Rust 1.88 or newer; the crate and locked dependency graph require it.
- Linux: a C toolchain, `pkg-config`, and OpenSSL development headers.
- macOS: Xcode Command Line Tools.
- `just` is optional; every required command is also shown as Cargo.

Examples:

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

# macOS
xcode-select --install
```

## Build

```bash
git clone https://github.com/chgeuer/phx-port
cd phx-port
cargo build --release --locked
./target/release/phx-port --version
```

Install for one user:

```bash
cargo install --path . --locked
```

Install a reviewed public-server binary:

```bash
sudo install -o root -g root -m 0755 target/release/phx-port \
  /usr/local/bin/phx-port
```

## Required checks

Run these before submitting a change:

```bash
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path samples/rust/Cargo.toml
cargo test \
  --locked \
  --manifest-path integrations/elixir/phx_port_handoff/native/phx_port_handoff_native/Cargo.toml
```

Platform and service-manager tests marked `ignored` require their documented
host privileges. The adversarial harness is described separately in
[the harness guide](../adversarial-public-ingress-harness.md). Do not treat its
smoke profile as production capacity evidence.

## CI

`.github/workflows/rust.yml` runs native builds and tests on all four
Linux/macOS architecture combinations. Each job verifies that the Rust host
target matches the declared matrix target before compiling. This prevents an
ARM artifact from being represented by an x64 cross-build, or vice versa.

Pull requests and pushes to `master` run the matrix. A change is not
cross-platform merely because it compiles on one runner.

## Release

Push a version tag:

```bash
git tag -s v0.2.0 -m "phx-port v0.2.0"
git push origin v0.2.0
```

`.github/workflows/release.yml` builds:

- Linux x64 and ARM64 tarballs containing the binary and `systemd/` units;
- macOS x64 and ARM64 tarballs containing the binary and `launchd/` plists;
- a Windows x64 zip.

Before publishing, verify artifact architecture:

```bash
file phx-port
./phx-port --version
```

Do not replace a production binary without retaining the preceding binary,
configuration checksums, and stable Port Registry snapshot. Use the
[upgrade and rollback procedure](operations.md#upgrade-and-binary-rollback).
