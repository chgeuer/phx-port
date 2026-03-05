default:
    @just --list

build:
    cargo build

release:
    cargo build --release

install:
    cargo install --path .

test:
    cargo test

check:
    cargo clippy -- -D warnings

fmt:
    cargo fmt

fmt-check:
    cargo fmt -- --check
