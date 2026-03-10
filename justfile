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

# VS Code extension tasks

vscode-compile:
    cd vscode-extension && npm install --quiet && npm run compile

vscode-package: vscode-compile
    cd vscode-extension && npx @vscode/vsce package --no-dependencies

vscode-install: vscode-package
    code --install-extension vscode-extension/phx-port-*.vsix

vscode-uninstall:
    code --uninstall-extension chgeuer.phx-port
