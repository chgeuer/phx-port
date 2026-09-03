import { EventEmitter } from 'node:events';
import { HandoffBroker, REJECT_ADOPTION_FAILED } from './broker.js';

export class FastifyPHXPIngress extends EventEmitter {
  #broker;
  #server;

  constructor(fastify, endpoint, options = {}) {
    super();
    if (!fastify?.server || typeof fastify.server.emit !== 'function') {
      throw new TypeError('a Fastify instance with an underlying server is required');
    }
    this.#server = fastify.server;
    this.#broker = new HandoffBroker(endpoint, options);
    this.#broker.on('error', (error) => this.emit('error', error));
    this.#broker.on('connection', (handoff) => this.#inject(handoff));
  }

  get path() {
    return this.#broker.path;
  }

  close() {
    return this.#broker.close();
  }

  #inject(handoff) {
    let socket;
    let adopted = false;
    let closed = false;
    try {
      socket = handoff.wrapSocket();
      socket.once('close', () => {
        closed = true;
        if (adopted) handoff.release();
      });
      if (this.#server.listenerCount('connection') === 0) {
        throw new Error('Fastify server has no connection pipeline');
      }
      this.#server.emit('connection', socket);
      handoff.adopt();
      adopted = true;
      if (closed) handoff.release();
    } catch (error) {
      if (!adopted) {
        try {
          handoff.reject(REJECT_ADOPTION_FAILED);
        } catch {
          // The native callback may already have rejected an undecided delivery.
        }
      }
      socket?.destroy();
      this.emit('error', error);
    }
  }
}

export function attachPHXP(fastify, endpoint, options) {
  return new FastifyPHXPIngress(fastify, endpoint, options);
}
