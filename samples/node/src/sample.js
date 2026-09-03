import { readFile } from 'node:fs/promises';
import process from 'node:process';
import Fastify from 'fastify';
import { attachPHXP, deriveEndpoint, development, production } from './index.js';

const certificate = process.env.PHXP_TLS_CERT;
const key = process.env.PHXP_TLS_KEY;
if (!certificate || !key) {
  throw new Error('set PHXP_TLS_CERT and PHXP_TLS_KEY to PEM file paths');
}

const app = Fastify({
  logger: true,
  https: {
    cert: await readFile(certificate),
    key: await readFile(key),
  },
});

app.addHook('onRequest', async (_request, reply) => {
  reply.header('x-phxp-pipeline', 'fastify');
});

app.get('/', async (request) => ({
  message: 'hello from the shared Fastify HTTPS pipeline',
  ip: request.ip,
  local: `${request.socket.localAddress}:${request.socket.localPort}`,
}));

const identity = process.env.PHXP_WORKLOAD_ID
  ? production(process.env.PHXP_WORKLOAD_ID)
  : await development(process.cwd());
const endpoint = deriveEndpoint(identity, process.env.PHXP_ROLE ?? 'https');
const ingress = attachPHXP(app, endpoint);
ingress.on('error', (error) => app.log.error(error));

const address = await app.listen({
  host: process.env.HOST ?? '127.0.0.1',
  port: Number(process.env.PORT ?? 8443),
});
app.log.info({ address, handoff: ingress.path }, 'Fastify HTTPS and PHXP are ready');

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, async () => {
    await ingress.close();
    await app.close();
  });
}
