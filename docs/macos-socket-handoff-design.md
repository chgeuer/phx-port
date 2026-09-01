# macOS Connected-Socket Handoff Design

## Status

Implemented for the daemon sender, Phoenix/Bandit integration, and Rust sample.
The Darwin descriptor path has been exercised on macOS arm64 with real Unix
and TCP sockets plus end-to-end TLS requests over HTTP/1.1 and HTTP/2. The
.NET receiver and `launchd` service installation remain follow-up work.

This document specifies the macOS port of the optional PHXP connected-socket
handoff path. It is intended to be implementation-ready on a macOS development
machine.

The existing generic TLS relay already remains the compatibility path on
non-Linux platforms. This work adds a Darwin-native handoff path without
changing route discovery, certificate validation, TLS ownership, or fallback
semantics.

The first supported backend is the existing Phoenix/Bandit integration. The
Rust sample should be ported alongside it as a framework-independent reference.
The .NET sample may follow after the Rust and Phoenix paths pass end-to-end
tests; its Linux-specific P/Invoke ABI should not block the initial macOS port.

## Decision summary

macOS can implement the same connected-socket handoff architecture because it
supports:

- `MSG_PEEK` on TCP sockets;
- Unix-domain sockets;
- descriptor passing with `sendmsg(2)`, `recvmsg(2)`, and `SCM_RIGHTS`;
- peer identity inspection with `getpeereid(3)`; and
- importing an existing TCP descriptor into the target runtime.

The current Linux implementation cannot simply be enabled on macOS because
Darwin does not provide the complete Linux API combination it uses:

- `AF_UNIX` does not support `SOCK_SEQPACKET`;
- `SO_PEERCRED` is Linux-specific;
- `accept4(2)` is unavailable;
- `MSG_CMSG_CLOEXEC` is unavailable; and
- `$XDG_RUNTIME_DIR` is not normally defined.

The macOS implementation will therefore use:

| Concern | Linux | macOS |
|---|---|---|
| Control socket | `AF_UNIX/SOCK_SEQPACKET` | `AF_UNIX/SOCK_STREAM` |
| Message boundaries | Kernel-preserved packets | PHXP header length framing |
| Peer identity | `SO_PEERCRED` | `getpeereid` |
| Accepted control FD | `accept4(SOCK_CLOEXEC)` | `accept` then `fcntl(FD_CLOEXEC)` |
| Received client FD | `MSG_CMSG_CLOEXEC` | `recvmsg` then `fcntl(FD_CLOEXEC)` |
| Endpoint root | `$XDG_RUNTIME_DIR` | private short directory below `/tmp` |
| Service management | systemd user unit | out of scope initially; later `launchd` |

Linux behavior and its `SOCK_SEQPACKET` transport remain unchanged.

## Relationship to the existing design

This document extends
[`socket-forwarding-design.md`](socket-forwarding-design.md). The following
existing decisions remain authoritative:

- `phx-port` accepts the original public TCP connection.
- SNI is obtained by peeking at an unconsumed TLS ClientHello.
- The backend, not `phx-port`, terminates TLS and owns all private key material.
- The descriptor refers to the original kernel TCP socket, preserving the
  client peer address and public local address.
- Successful descriptor delivery is the ownership boundary.
- Relay fallback is allowed only before descriptor delivery.
- The backend validates the actual ClientHello independently; PHXP SNI metadata
  is not an authorization fact.
- The ordinary backend HTTPS listener remains responsible for route discovery,
  certificate validation, health checks, and direct diagnostics.

The PHXP v1 binary envelope also remains unchanged. macOS introduces a
different local transport profile, not a new application-level message format.

## Goals

1. Hand the original accepted TCP socket from the macOS `phx-port` daemon to a
   cooperating backend process.
2. Preserve the unconsumed ClientHello, original peer address, and local public
   address.
3. Remove `phx-port` from the connection data path after handoff.
4. Preserve the existing ownership and fallback guarantees under partial
   `SOCK_STREAM` writes and reads.
5. Authenticate both control-channel peers as the same effective user.
6. Keep all control and received descriptors close-on-exec.
7. Keep Linux behavior and protocol interoperability unchanged.
8. Make unsupported or unavailable handoff degrade to the existing relay
   before descriptor delivery.
9. Exercise the standard Bandit/Phoenix and Axum/Hyper request paths rather
   than adding a parallel HTTP implementation.

## Non-goals

- Porting handoff to Windows.
- Replacing the Linux `SOCK_SEQPACKET` control channel.
- Making Linux and macOS receivers connect to one another; PHXP is local IPC.
- Migrating TLS or application state after a handshake has begun.
- Trusting an SNI value sent in PHXP instead of the socket's ClientHello.
- Adding `launchd` service installation in the first implementation.
- Redesigning route discovery or the generic TLS relay.
- Guaranteeing the initial .NET reference receiver works on macOS.
- Supporting sandboxed Mac App Store applications.

## Existing connection flow

The platform-independent portion already has the required semantics:

1. The daemon accepts a TCP connection on its public listener.
2. `tls_client_hello::peek_sni` calls `TcpStream::peek`, leaving all bytes in
   the kernel receive queue.
3. The daemon resolves the hostname to one certificate-verified backend.
4. `handoff::try_transfer` attempts a local descriptor handoff.
5. If handoff is unavailable before delivery, `handle_connection` opens the
   registered backend port and relays encrypted bytes.
6. If handoff succeeds, the backend performs TLS directly on the original TCP
   socket.

Only step 4 needs a platform-specific transport implementation.

## PHXP v1 over a Darwin stream socket

### Why `SOCK_STREAM`

Darwin supports `SCM_RIGHTS` over Unix-domain sockets but does not implement
`AF_UNIX/SOCK_SEQPACKET`. `SOCK_STREAM` supplies reliable, ordered,
connection-oriented delivery and works with peer credential inspection.

Unlike `SOCK_SEQPACKET`, a stream does not preserve calls to `send` as records:

- one write may be returned by several reads;
- several writes may be returned by one read; and
- `sendmsg` may report a positive partial write.

No implementation may assume that one `send`, `sendmsg`, `recv`, or `recvmsg`
corresponds to one PHXP message on macOS.

### Connection lifecycle

PHXP continues to use one control connection for one attempted client handoff:

```text
daemon                                      receiver
  |--- HELLO (40 bytes) ---------------------->|
  |<-- READY (40 bytes) -----------------------|
  |--- HANDOFF (40 + SNI bytes) + SCM_RIGHTS ->|
  |<-- ADOPTED or REJECTED (40 bytes) ---------|
  |--- close ---------------------------------->|
```

There is no pipelining and no second handoff on the same control connection.
This constraint makes stream framing deterministic and bounds all buffering.

### Frame format

The existing PHXP v1 envelope remains the frame:

- bytes 0-3: magic `PHXP`;
- byte 4: protocol version;
- byte 5: message type;
- bytes 6-7: flags;
- bytes 8-39: existing fixed fields;
- bytes 36-37: payload length;
- bytes 40 onward: payload.

The maximum complete frame remains 512 bytes. `HELLO`, `READY`, `ADOPTED`, and
`REJECTED` remain exactly 40 bytes. A `HANDOFF` is exactly
`40 + payload_length` bytes.

The receiver must validate the fixed header before allocating or reading the
declared payload. A length above `MAX_PACKET_LENGTH - HEADER_LENGTH` is an
immediate protocol error.

### Reading ordinary frames

Implement a stream-frame helper shared by the Darwin sender and test receiver:

```text
read_frame(stream):
    read exactly 40 bytes
    validate magic, version, flags, message type, and bounded payload length
    read exactly payload_length additional bytes
    decode exactly the assembled frame
```

EOF before the declared frame length is a protocol failure. Data beyond one
frame is also invalid for the current state because the protocol does not
pipeline messages.

`HELLO`, `READY`, and the final response use this helper.

### Sending the descriptor-bearing frame

The HANDOFF frame and `SCM_RIGHTS` control message must begin in one `sendmsg`
call. At least one ordinary payload byte is required so the ancillary data has
a position in the byte stream.

The daemon algorithm is:

```text
send_handoff(control, client_fd, frame):
    sent = sendmsg(control, frame, SCM_RIGHTS(client_fd))

    if sendmsg failed or sent == 0:
        descriptor was not delivered
        retain client ownership
        return PRE_DELIVERY_FAILURE

    descriptor may now exist in the receiver
    close daemon's client descriptor without shutdown

    if sent < frame.length:
        write all remaining frame bytes without another SCM_RIGHTS message
        if this fails:
            return POST_DELIVERY_FAILURE

    read one complete response frame
    validate its type and connection ID
```

A positive result from the initial `sendmsg` is the irreversible ownership
boundary even when it is smaller than the frame length. The descriptor is
associated with the first successfully transferred data byte. Failure while
sending the remainder must therefore produce `Outcome::Delivered`, never
`Outcome::Unavailable`.

The implementation must not resend `SCM_RIGHTS` while completing a partial
frame; doing so would duplicate the client descriptor a second time.

### Receiving the descriptor-bearing frame

After reading and validating `HELLO` and sending `READY`, the receiver knows
that the next stream bytes must begin the HANDOFF frame. Its first read for
that frame must use `recvmsg` with enough ancillary space for at least two
descriptors:

```text
receive_handoff(control):
    bytes, control_messages, flags = recvmsg(
        data_capacity = MAX_PACKET_LENGTH + 1,
        fd_capacity = 2
    )

    reject MSG_TRUNC or MSG_CTRUNC
    collect every SCM_RIGHTS descriptor
    immediately wrap every raw descriptor in owned RAII storage
    set FD_CLOEXEC on every received descriptor
    require exactly one descriptor

    if fewer than 40 data bytes arrived:
        read exactly enough stream bytes to complete the fixed header

    validate header and payload length

    if fewer than the declared total frame bytes arrived:
        read exactly the remainder

    reject bytes beyond the declared frame
    decode HANDOFF
    validate the descriptor as a connected IPv4 or IPv6 stream socket
```

The first post-`READY` operation must be `recvmsg`, not `read`, because reading
past the byte carrying the ancillary data without supplying a control buffer
could discard the descriptor.

If the descriptor arrives but the frame is incomplete, malformed, or followed
by EOF, the receiver closes the descriptor and the control connection. It may
send `REJECTED` only if it has decoded a valid connection ID. The daemon treats
this as a post-delivery failure and must not relay.

All descriptors found in unexpected ancillary messages must be closed,
including errors involving:

- zero descriptors;
- multiple descriptors;
- ancillary truncation;
- malformed control-message lengths;
- a non-stream descriptor;
- an unconnected stream; or
- a connected non-IP stream.

### Response handling

After adopting or rejecting the descriptor, the receiver sends one complete
40-byte response with a bounded write loop. The daemon reads exactly 40 bytes
and requires:

- PHXP magic and version;
- no payload;
- the expected response envelope;
- the same 16-byte connection ID; and
- a nonzero reason for `REJECTED`.

An acknowledgement loss does not reverse ownership. The backend owns the
connection once descriptor delivery has occurred.

## Ownership state machine

Stream transport introduces partial-write states that must be represented
explicitly.

| State | Daemon owns client FD | Receiver may own client FD | Relay allowed |
|---|---:|---:|---:|
| Before HANDOFF `sendmsg` | yes | no | yes |
| `sendmsg` returned error or zero | yes | no | yes |
| `sendmsg` returned a positive byte count | no, close immediately | yes | no |
| Sending remaining frame bytes | no | yes | no |
| Waiting for response | no | yes | no |
| `ADOPTED` | no | yes | no |
| `REJECTED`, EOF, timeout, malformed response | no | receiver closes if needed | no |

The public `Outcome` behavior remains:

- `Unavailable(TcpStream)` only for a provable pre-delivery failure;
- `Transferred` after a matching `ADOPTED`; and
- `Delivered(String)` for every failure after a positive descriptor-bearing
  `sendmsg`.

Never call `shutdown(2)` on the daemon's client descriptor during transfer.
Dropping or closing only the daemon's descriptor leaves the shared kernel
socket alive for the receiver.

## Platform abstraction

Refactor `src/handoff.rs` into shared orchestration plus platform-specific
control transports instead of duplicating the ownership state machine.

A suggested internal layout is:

```text
src/handoff.rs
  shared Outcome and try_transfer orchestration
  endpoint hash construction
  PHXP request/response validation

src/handoff/linux.rs
  SOCK_SEQPACKET connection
  SO_PEERCRED
  packet send/receive

src/handoff/macos.rs
  SOCK_STREAM connection
  getpeereid
  framed stream send/receive
  explicit FD_CLOEXEC
```

An equivalent module layout is acceptable if these invariants hold:

- message encoding stays in `src/handoff_protocol.rs`;
- Linux and Darwin system calls do not leak into shared code;
- ownership transition logic has one authoritative implementation or a shared
  state abstraction;
- unsupported platforms retain the no-op `Unavailable` implementation; and
- compile-time guards name supported families explicitly:

```rust
#[cfg(any(target_os = "linux", target_os = "macos"))]
```

Do not widen support to every `target_family = "unix"` without platform tests.

## Darwin syscall mapping

### Socket creation

Create control listeners and clients with:

```text
socket(AF_UNIX, SOCK_STREAM, 0)
```

Set close-on-exec on the resulting descriptor. `nix` may expose
`SockFlag::SOCK_CLOEXEC` on the active macOS deployment target; if used, retain
a test that verifies `F_GETFD` contains `FD_CLOEXEC`.

### Accept

Use `nix::sys::socket::accept`, then immediately call:

```rust
fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
```

If setting the flag fails, close the accepted descriptor and reject that
control connection.

### Received descriptor

Darwin has no `MSG_CMSG_CLOEXEC`. Call `recvmsg` without that flag, wrap every
returned raw descriptor immediately, and apply `FD_CLOEXEC` with `fcntl`
before validation or runtime adoption. If setting it fails, close all received
descriptors and reject the handoff.

### Peer identity

Use `nix::unistd::getpeereid`, available under the current `nix` `user`
feature:

```rust
let (peer_euid, _peer_egid) = nix::unistd::getpeereid(&control)?;
if peer_euid != nix::unistd::geteuid() {
    reject_peer();
}
```

Perform this check in both directions:

- the daemon verifies the connected receiver before sending `HELLO`; and
- the receiver verifies the accepted daemon before replying `READY`.

Compare effective UID to effective UID. Directory permissions remain defense
in depth and do not replace peer authentication.

### Timeouts

Retain bounded receive and send timeouts. Timeout errors before descriptor
delivery permit relay. Timeout errors after positive descriptor delivery are
post-delivery failures.

### Connected socket validation

Retain all existing validation:

- `SO_TYPE == SOCK_STREAM`;
- `getpeername` succeeds;
- peer address family is IPv4 or IPv6; and
- runtime wrapping succeeds.

Also capture `peername` and `sockname` before TLS wrapping, as the Phoenix
transport already does.

## Endpoint discovery on macOS

### Requirements

The endpoint must:

- be deterministic from canonical project path and role;
- be discoverable independently by daemon and backend;
- live in a directory writable only by the effective user;
- fit Darwin's shorter `sockaddr_un.sun_path`;
- avoid replacing non-socket filesystem entries;
- refuse to replace a live receiver; and
- be removed only by the process that successfully bound it.

### Path convention

Use this macOS default:

```text
/tmp/phx-port-<euid>/handoff/<sha256>.sock
```

where `<sha256>` is the existing 64-character lowercase digest of:

```text
canonical-project-path NUL role
```

Before binding or connecting, calculate the encoded Unix socket path length
against `libc::sockaddr_un.sun_path.len()`. If the path does not fit, report
handoff as unavailable with an actionable error rather than truncating or
rehashing it.

Support `PHX_PORT_RUNTIME_DIR` as an explicit cross-platform override. Endpoint
resolution order becomes:

1. `PHX_PORT_RUNTIME_DIR`, if nonempty;
2. `$XDG_RUNTIME_DIR` on Linux;
3. `/tmp/phx-port-<euid>` on macOS;
4. unavailable on other platforms.

The override denotes the runtime root. Append `handoff/<sha256>.sock` exactly
once. Keep the existing Linux path stable by treating its XDG root as before:
`$XDG_RUNTIME_DIR/phx-port/handoff/<sha256>.sock`. Shared endpoint helpers must
make this platform-specific prefix explicit and test it.

The short `/tmp` location is intentional. Typical macOS `$TMPDIR` paths under
`/var/folders` can be long enough that adding a 64-character digest exceeds
Darwin's Unix socket path limit.

### Directory hardening

Creating a predictable directory below a shared `/tmp` requires careful
validation:

1. Inspect with `symlink_metadata`; never follow a pre-existing symlink.
2. Create the directory with mode `0700` if it does not exist.
3. Verify it is a directory owned by the effective UID.
4. Verify group and other permission bits are zero.
5. Refuse the handoff endpoint if any check fails.
6. Do not repair ownership or permissions of an unexpected pre-existing path.

The receiver socket remains mode `0600`.

When replacing a stale endpoint:

1. use `symlink_metadata`;
2. require a socket filesystem type;
3. attempt a PHXP connection;
4. refuse removal if a live listener accepts;
5. unlink only a confirmed stale socket; and
6. bind the replacement before claiming endpoint ownership.

The endpoint's deterministic name is not a secret. Security comes from the
private directory, socket mode, live-endpoint checks, and mutual effective-UID
verification.

## Daemon changes

### `src/handoff.rs`

Replace the current Linux-only outer gate with explicit Linux, macOS, and
unsupported implementations.

The macOS sender must:

- derive the macOS endpoint;
- connect with `AF_UNIX/SOCK_STREAM`;
- set timeouts and close-on-exec;
- authenticate the receiver with `getpeereid`;
- frame `HELLO` and `READY`;
- send HANDOFF and one TCP FD using the partial-write algorithm above;
- close its client FD immediately after a positive `sendmsg`;
- read one framed response; and
- map failures to `Unavailable` or `Delivered` according to the ownership
  boundary.

Do not change `proxy::handle_connection` fallback behavior except as needed to
call the newly shared supported-platform implementation.

### `src/handoff_protocol.rs`

Keep the codec and version unchanged. Add small helpers if needed to expose:

- fixed header length;
- checked total frame length from a header;
- message type expectations; and
- tests for partial stream assembly.

Do not embed socket reads or platform APIs in the codec.

### Status and logs

Existing handoff counters remain valid. Error messages should distinguish:

- endpoint unavailable before delivery;
- peer authentication failure before delivery;
- protocol negotiation failure before delivery;
- partial HANDOFF completion failure after descriptor delivery; and
- acknowledgement failure after descriptor delivery.

Do not log raw descriptor numbers.

### Service commands

`proxy install-service` and `proxy uninstall-service` remain Linux/systemd-only
for the initial port. Running `phx-port daemon` directly on macOS must work.
A later design may add a LaunchAgent, but it is independent of descriptor
handoff.

## Phoenix/Bandit integration changes

### Native Rustler receiver

Refactor
`integrations/elixir/phx_port_handoff/native/phx_port_handoff_native/src/lib.rs`
with the same Linux/Darwin transport separation as the daemon.

Shared receiver logic should continue to own:

- PHXP decoding and validation;
- duplicate connection-ID tracking;
- exactly-one-descriptor enforcement;
- connected TCP stream validation;
- receipt lifetime;
- `ADOPTED` and `REJECTED` semantics; and
- listener cleanup.

Darwin-specific code supplies:

- `SOCK_STREAM`;
- framed reads and writes;
- `accept` plus `FD_CLOEXEC`;
- `recvmsg` plus explicit `FD_CLOEXEC`; and
- `getpeereid`.

The blocking accept remains a dirty I/O NIF as today. Closing the broker must
wake or terminate a blocked Darwin accept and allow the supervised listener to
restart. Validate this explicitly; do not assume Linux `shutdown` behavior is
identical.

### Descriptor import

Keep `:gen_tcp.fdopen/2` as the first implementation:

```elixir
:gen_tcp.fdopen(fd, [:binary, active: false, packet: :raw, nodelay: true])
```

The native owner releases the descriptor only once. On `fdopen` failure:

- close the raw descriptor through the native helper;
- send `REJECTED`;
- return an error to Thousand Island; and
- never acknowledge adoption.

After `fdopen`, preserve the existing sequence:

1. return the raw socket from transport `accept/1`;
2. transfer it with `:gen_tcp.controlling_process/2`;
3. send `ADOPTED`;
4. cache peer and local addresses;
5. perform `:ssl.handshake`;
6. enter the normal Bandit connection lifecycle.

OTP 29 and Rustler 0.36.2 remain the supported baseline until macOS tests prove
otherwise. Do not upgrade Rustler as part of this port.

### Elixir endpoint helper

Change `PhxPortHandoff.endpoint_path/2` to use the same runtime-root and
platform-prefix convention as the daemon. Add an explicit
`runtime_dir:`/`handoff_path:` override only if it follows existing public API
style; the environment-level `PHX_PORT_RUNTIME_DIR` override is mandatory.

The daemon, NIF integration, and samples must share test vectors for:

- canonical project path;
- role;
- SHA-256 digest; and
- final Linux and macOS paths.

## Rust sample changes

Remove the unconditional macOS compile error while retaining an error on
unsupported targets.

Port `samples/rust/src/handoff.rs` using the same Darwin transport primitives
and framing rules. Prefer extracting reusable internal helpers over copying a
third subtly different stream implementation, provided this does not force the
sample to depend on unpublished workspace internals.

The adopted TCP descriptor continues through:

```text
std::net::TcpStream
  -> nonblocking
  -> tokio::net::TcpStream
  -> tokio-rustls
  -> Hyper
  -> Axum router
```

The ordinary HTTP and HTTPS listeners remain unchanged.

## .NET sample

The current sample is intentionally Linux-specific:

- `SocketType.Seqpacket`;
- Linux `cmsghdr` constants and structure assumptions;
- `SO_PEERCRED`;
- `statx`;
- `MSG_CMSG_CLOEXEC`; and
- an `OperatingSystem.IsLinux()` guard.

Do not remove that guard until a native macOS implementation has its own:

- Darwin constants and structure layout;
- stream framing;
- `getpeereid` binding;
- `lstat` or managed socket-file validation;
- explicit close-on-exec handling; and
- focused tests on both arm64 and x64 where supported.

The Kestrel `SafeSocketHandle` adaptation is conceptually reusable. This is a
follow-up deliverable, not an acceptance criterion for the initial port.

## Documentation changes

When implementation is complete:

- update the root README from "On Linux" to "On Linux and macOS" for handoff;
- retain a table explaining the different control transports;
- update the Phoenix integration README prerequisites and endpoint paths;
- update the Rust sample README;
- leave the .NET README Linux-only until that receiver is actually ported;
- update the portability and delivery status in
  `docs/socket-forwarding-design.md`; and
- document that system service installation remains Linux-only.

Do not describe macOS handoff as supported before its end-to-end tests pass.

## Testing strategy

### Cross-compilation and platform compilation

On Linux:

- existing unit and end-to-end tests must continue to pass unchanged;
- Linux must still use `SOCK_SEQPACKET`, `SO_PEERCRED`, `accept4`, and
  `MSG_CMSG_CLOEXEC`; and
- unsupported-platform stubs must still compile where CI already checks them.

On macOS:

- build and test the root crate;
- build and test the Phoenix integration NIF;
- build and test the Rust sample; and
- run formatter and linter commands already present in the repository.

Compilation alone is insufficient because descriptor ownership and ancillary
data behavior must be tested on a Darwin kernel.

### Stream framing unit tests

Add deterministic tests for:

1. a 40-byte frame delivered one byte at a time;
2. header and payload split at every possible boundary;
3. several writes coalesced into one read;
4. EOF in the fixed header;
5. EOF in the payload;
6. a declared payload above the protocol limit;
7. bytes beyond the declared frame;
8. a partial positive descriptor-bearing `sendmsg`;
9. failure while sending the post-`sendmsg` remainder;
10. partial `ADOPTED` and `REJECTED` responses; and
11. timeout before and after descriptor delivery.

Where forcing a real partial `sendmsg` is nondeterministic, test the ownership
state machine through an injected send result or a small transport trait. Do
not rely on socket buffer timing to cover this invariant.

### Darwin descriptor transport tests

Using real Unix and TCP sockets:

1. Create a loopback TCP connection.
2. Accept one side in the test daemon.
3. Peek a known payload without consuming it.
4. Transfer the accepted descriptor over the Darwin PHXP stream.
5. Verify exactly one FD arrives.
6. Verify `FD_CLOEXEC` on the accepted control FD and received TCP FD.
7. Verify `peername` and `sockname` match the original connection.
8. Read the complete previously peeked payload through the received FD.
9. Close the sender copy without `shutdown`.
10. Continue bidirectional I/O through the receiver copy.
11. Send and validate `ADOPTED`.

Add negative tests for:

- receiver owned by a different effective UID where CI permits;
- malformed or missing SCM_RIGHTS;
- two descriptors;
- ancillary truncation;
- regular file descriptor instead of a TCP socket;
- unconnected TCP socket;
- Unix stream descriptor instead of IP;
- stale endpoint replacement;
- refusal to replace a regular file or symlink;
- live endpoint collision;
- overlong endpoint path; and
- listener close and same-process restart.

Tests that require another UID may be skipped with an explicit reason when the
runner cannot change identity. Peer-ID success checks are never optional.

### Daemon fallback tests

Prove these outcomes:

| Fault | Expected result |
|---|---|
| No endpoint | relay |
| Connection refused | relay |
| Wrong peer UID | relay |
| Invalid `READY` | relay |
| HANDOFF `sendmsg` fails before sending bytes | relay |
| HANDOFF `sendmsg` sends at least one byte, remainder fails | close, no relay |
| Receiver rejects after FD receipt | close, no relay |
| Acknowledgement times out after FD receipt | close, no relay |
| Matching `ADOPTED` | successful handoff |

Inspect handoff counters as well as request behavior.

### Phoenix integration tests

On macOS with OTP 29:

- native broker starts and publishes the expected endpoint;
- broker shutdown removes only its own endpoint;
- supervised restart can bind the same endpoint;
- `:gen_tcp.fdopen/2` imports the received TCP descriptor;
- `controlling_process/2` succeeds before `ADOPTED`;
- TLS handshake sees the untouched ClientHello;
- SNI certificate selection is performed by `:ssl`;
- HTTP/1.1 reaches the ordinary Phoenix endpoint;
- HTTP/2 reaches the ordinary Phoenix endpoint;
- LiveView WebSocket upgrade remains connected;
- `Plug.Conn.remote_ip` is the original client;
- local socket port is the daemon's public listener port; and
- concurrent handoffs to separate applications do not cross routes.

Repeat request tests through the ordinary assigned HTTPS port to prove the
application configuration is shared rather than forked.

### Rust sample end-to-end tests

On macOS:

- direct HTTP;
- direct HTTPS;
- daemon-routed HTTPS handoff;
- original peer and local addresses in the response;
- HTTP/1.1 and HTTP/2;
- keep-alive requests;
- concurrent requests; and
- closure propagation in both directions.

## Implementation sequence

Implement in tracer-bullet order so each step leaves Linux usable:

1. Add platform-neutral stream frame assembly tests around the PHXP envelope.
2. Introduce shared runtime-root and endpoint derivation with Linux paths
   unchanged and macOS path vectors added.
3. Refactor daemon handoff behind Linux and macOS control-transport modules
   without changing Linux behavior.
4. Implement the Darwin sender, peer authentication, close-on-exec handling,
   and ownership-state tests.
5. Add a minimal Darwin test receiver and prove raw TCP descriptor transfer.
6. Refactor the Rustler receiver into shared and platform-specific portions.
7. Prove `:gen_tcp.fdopen`, TLS, and one Phoenix HTTP/1.1 request.
8. Port the Rust sample as an independent receiver implementation.
9. Run HTTP/2, WebSocket, concurrency, restart, and fallback end-to-end tests.
10. Update support documentation.
11. Consider the .NET receiver and `launchd` integration as separate follow-up
    changes.

Do not start by changing documentation claims or widening all `cfg` gates.
First establish a real Darwin descriptor-transfer test.

## Acceptance criteria

The initial macOS port is complete when all of the following are true:

1. The root crate builds and its existing tests pass on Linux and macOS.
2. Linux continues to use its existing `SOCK_SEQPACKET` PHXP transport.
3. macOS uses `SOCK_STREAM` with bounded, partial-read-safe framing.
4. Both macOS peers verify matching effective UIDs with `getpeereid`.
5. Accepted and received descriptors have `FD_CLOEXEC`.
6. A positive descriptor-bearing `sendmsg` permanently disables relay fallback.
7. The daemon hands an untouched TCP connection to a real macOS receiver.
8. The Phoenix integration imports that descriptor and serves TLS plus
   HTTP/1.1 through the normal Bandit/Phoenix stack.
9. HTTP/2 and LiveView WebSockets pass through the same path.
10. Phoenix observes the original peer and public local socket addresses.
11. Missing or incompatible receivers still use the ordinary relay.
12. Receiver rejection or failure after descriptor delivery closes the
    connection without relay.
13. Listener shutdown and supervised restart leave no live or incorrectly
    removed endpoint.
14. The Rust sample demonstrates the same macOS handoff independently.
15. Documentation accurately distinguishes Linux, macOS, and still-Linux-only
    components.

## Risks and mitigations

### Ancillary data lost on a stream

Risk: ordinary reads consume the byte associated with `SCM_RIGHTS` before a
control buffer is supplied.

Mitigation: after `READY`, the receiver's first HANDOFF read is always
`recvmsg`; no buffered stream wrapper may read ahead.

### Incorrect fallback after a partial send

Risk: `sendmsg` transfers the FD but only part of the frame, and the daemon
mistakenly attempts a relay.

Mitigation: any positive descriptor-bearing `sendmsg` result transitions to
post-delivery ownership immediately and irreversibly.

### Descriptor leaks on malformed ancillary data

Risk: an error path returns before closing one or more raw FDs.

Mitigation: convert every received FD to `OwnedFd` immediately, before count or
protocol validation, and rely on RAII for every return path.

### Descriptor leak across `exec`

Risk: Darwin lacks the atomic Linux receive flag used today.

Mitigation: set `FD_CLOEXEC` immediately after `accept` and `recvmsg`, fail
closed if it cannot be set, and test the flag directly.

### Endpoint path overflow

Risk: Darwin's Unix socket path is shorter than Linux's and common macOS temp
paths are long.

Mitigation: use the short `/tmp/phx-port-<euid>` root, check `sun_path`
capacity before every bind/connect, and support `PHX_PORT_RUNTIME_DIR`.

### Shared `/tmp` attacks

Risk: another local user creates a symlink or directory at the predictable
runtime path.

Mitigation: use no-follow metadata checks, require effective-UID ownership and
mode `0700`, refuse unexpected existing objects, retain socket mode `0600`,
and authenticate both connected peers.

### Runtime descriptor ownership mismatch

Risk: `:gen_tcp.fdopen/2`, Rustler resource cleanup, and Darwin's socket backend
interact differently than on tested Linux/OTP builds.

Mitigation: retain OTP 29 and Rustler 0.36.2, test closure and supervisor
restart on a real Mac, and do not advertise support based on compilation
alone.

## References

- Existing architecture:
  [`socket-forwarding-design.md`](socket-forwarding-design.md)
- Narrative and ownership explanation:
  [`proxying-without-the-proxy.md`](proxying-without-the-proxy.md)
- Apple `socket(2)`:
  <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/socket.2.html>
- Apple `sendmsg(2)`:
  <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/sendmsg.2.html>
- Apple `recvmsg(2)`:
  <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/recvmsg.2.html>
- Apple `getpeereid(3)`:
  <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html>
- Erlang `gen_tcp`:
  <https://www.erlang.org/doc/apps/kernel/gen_tcp.html>
