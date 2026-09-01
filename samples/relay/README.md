# OpenSSL relay sample

This directory is the project identity for the playground's relay-only TLS
backend. `samples/playground.sh` registers its `https` role through the
`phx-port` CLI and starts `openssl s_server` on the resulting stable port.

There is intentionally no PHXP receiver for this project, so connections to
`c.pollmann.rocks` exercise the daemon's ordinary TLS relay fallback.
