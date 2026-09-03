# Node.js PHXP v1 + Fastify

This sample receives untouched connected TCP sockets from `phx-port` over the
PHXP v1 Unix control channel and injects them into the same server-side TLS
pipeline used by an ordinary Fastify HTTPS listener.

The native addon is deliberately narrow. It implements Unix control framing,
same-euid authentication, `SCM_RIGHTS`, descriptor validation, bounded broker
threads/queues, and ownership acknowledgements. TLS, HTTP, Fastify hooks,
plugins, routing, and handlers remain JavaScript/framework responsibilities.

## Platforms and requirements

- Node.js 20 or newer.
- A C++17 compiler, Python, `make`, and the normal `node-gyp` toolchain.
- Linux: `AF_UNIX/SOCK_SEQPACKET`.
- macOS: `AF_UNIX/SOCK_STREAM` with explicit bounded PHXP frame accumulation.

The addon uses stable N-API v8 and no C++ wrapper dependency. Linux is covered
by the local automated tests. The source has separate Darwin transport,
`getpeereid`, `SO_NOSIGPIPE`, framing, and path-limit branches; run the same
commands on macOS to perform exact platform validation.

## Install and test

```sh
cd samples/node
npm ci
npm run build:native
npm test
```

`npm ci` invokes the native build through the package install script.

## Endpoint identity

```js
import {
  deriveEndpoint,
  development,
  production,
} from './src/index.js';

const dev = deriveEndpoint(await development(process.cwd()), 'https');
const prod = deriveEndpoint(production('contoso-web'), 'https');
```

Development hashes the canonical project path, a NUL byte, and the role.
Production hashes the explicit logical workload ID, a NUL byte, and the role.
Both use SHA-256.

- Linux development:
  `$XDG_RUNTIME_DIR/phx-port/handoff/<hash>.sock`
- macOS development:
  `/tmp/phx-port-<euid>/handoff/<hash>.sock`
- Production:
  `/run/phx-port/handoff/<hash>.sock`
- Nonempty `PHX_PORT_RUNTIME_DIR`:
  `<override>/handoff/<hash>.sock`

Production on macOS requires `PHX_PORT_RUNTIME_DIR`. `PHX_PORT_WORKLOAD_ID`
does not implicitly select production identity.

The broker verifies private directory ownership/modes, rejects symlinks and
non-socket paths, probes before replacing a stale socket, binds mode `0600`,
checks the bound inode, and only removes the endpoint it owns.

## Fastify integration

```js
import { readFile } from 'node:fs/promises';
import Fastify from 'fastify';
import { attachPHXP, deriveEndpoint, development } from './src/index.js';

const app = Fastify({
  https: {
    cert: await readFile('certificate.pem'),
    key: await readFile('key.pem'),
  },
});

app.addHook('onRequest', async (_request, reply) => {
  reply.header('x-shared-pipeline', 'fastify');
});

app.get('/', async () => ({ ok: true }));

const endpoint = deriveEndpoint(
  await development(process.cwd()),
  'https',
);
const ingress = attachPHXP(app, endpoint);
ingress.on('error', (error) => app.log.error(error));

await app.listen({ host: '127.0.0.1', port: 8443 });

// Shutdown order stops new handoffs before closing Fastify.
await ingress.close();
await app.close();
```

Ordinary loopback connections arrive through Fastify's normal listener.
For PHXP, the broker wraps the received descriptor with the documented
`new net.Socket({ fd })` API and emits that socket into `fastify.server`'s
existing `connection` event. The same Node TLS server then performs the
ClientHello parsing, certificate selection, ALPN, and request dispatch.
There is no native TLS/HTTP implementation and no parallel response path.

This supports HTTP/1.1 and HTTP/2 only insofar as the selected Fastify HTTPS
configuration and its Node server support them. For HTTP/2, configure Fastify
normally with `http2: true` and the desired `allowHTTP1` setting. PHXP does not
add protocol negotiation or broaden Fastify's standard support.

The application receives the real `remoteAddress`/`remotePort` and the
original accepted `localAddress`/`localPort`. There is no PHXP-origin marker on
the socket; application code cannot distinguish ingress unless it separately
inspects ordinary socket metadata.

## Ownership API

`HandoffBroker` emits a synchronous `connection` event:

```js
broker.on('connection', (handoff) => {
  const socket = handoff.wrapSocket();
  pipeline.emit('connection', socket);
  handoff.adopt();
  socket.once('close', handoff.release);
});
```

The required order is:

1. `wrapSocket()` gives JavaScript sole descriptor ownership without `dup`.
2. Inject the socket into the complete framework/TLS pipeline.
3. Call `adopt()` to enqueue `ADOPTED`.
4. Call `release()` when the connection closes, allowing reuse of its ID.

If wrapping or injection fails, call `reject(3)`; it closes whichever layer
currently owns the descriptor and sends `REJECTED`. Returning from the event
without a decision is automatically rejected. Queue saturation, invalid
descriptors, duplicate active IDs, timeouts, and shutdown also close safely.
After `ADOPTED`, native code retains no usable descriptor. A later TLS or
application failure closes the JavaScript socket and never attempts relay
fallback.

## Runnable sample

```sh
PHXP_TLS_CERT=certificate.pem \
PHXP_TLS_KEY=key.pem \
PORT=8443 \
npm start
```

Optional settings:

- `HOST` (default `127.0.0.1`)
- `PHXP_ROLE` (default `https`)
- `PHXP_WORKLOAD_ID` to select production identity
- `PHX_PORT_RUNTIME_DIR` to override the runtime root

The sample route and `onRequest` hook are shared by direct and handed-off TLS
requests.
