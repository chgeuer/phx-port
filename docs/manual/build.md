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
- Go 1.23 or newer for the `net/http` PHXP adapter.
- Python 3.11 or newer for the FastAPI/Uvicorn PHXP adapter.
- Node.js 20 or newer, Python, `make`, and a C++17 compiler for the Fastify
  adapter's stable N-API addon.
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
just test-frameworks
```

Platform and service-manager tests marked `ignored` require their documented
host privileges. The adversarial harness is described separately in
[the harness guide](../adversarial-public-ingress-harness.md). Do not treat its
smoke profile as production capacity evidence.

## CI

`.github/workflows/rust.yml` runs native builds and tests on all four
Linux/macOS architecture combinations. Each job verifies the Rust host target,
Go host architecture, Python machine, and Node architecture before compiling.
It then tests the Rust daemon and receivers plus the Go, Python, and Node
framework adapters. In particular, the Node native addon is compiled and
exercised on Linux/macOS x64/ARM64 rather than cross-compiled.

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

Release archives intentionally contain the `phx-port` binary and native
service-manager definitions only. Framework integrations remain source
examples in the repository and are validated by CI; they are not separate
runtime artifacts shipped with the daemon.

Before publishing, verify artifact architecture:

```bash
file phx-port
./phx-port --version
```

Do not replace a production binary without retaining the preceding binary,
configuration checksums, and stable Port Registry snapshot. Use the
[upgrade and rollback procedure](operations.md#upgrade-and-binary-rollback).
