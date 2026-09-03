import { EventEmitter } from 'node:events';
import net from 'node:net';
import { native } from './native.js';

export const REJECT_INVALID_DESCRIPTOR = 1;
export const REJECT_DUPLICATE_ID = 2;
export const REJECT_ADOPTION_FAILED = 3;

export class HandoffBroker extends EventEmitter {
  #native;
  #closePromise;

  constructor(endpoint, options = {}) {
    super();
    if (!endpoint || typeof endpoint.path !== 'string') {
      throw new TypeError('PHXP endpoint with a path is required');
    }
    this.#native = native.start(
      endpoint.path,
      {
        validateRuntimeRoot: endpoint.validateRuntimeRoot === true,
        queueSize: options.queueSize ?? 128,
        backlog: options.backlog ?? 128,
        controlTimeoutMs: options.controlTimeoutMs ?? 2000,
        maxControlConnections: options.maxControlConnections ?? 32,
      },
      (delivery) => this.#deliver(delivery),
    );
  }

  get path() {
    return this.#native.path();
  }

  close() {
    this.#closePromise ??= this.#native.close();
    return this.#closePromise;
  }

  #deliver(delivery) {
    let decided = false;
    let socket;
    const connectionId = Buffer.from(delivery.connectionId);
    const handoff = Object.freeze({
      connectionId,
      requestedSni: delivery.requestedSni,
      peekedLength: delivery.peekedLength,
      acceptedAtNs: delivery.acceptedAtNs,
      wrapSocket: (options = {}) => {
        if (socket) throw new Error('PHXP descriptor has already been wrapped');
        socket = new net.Socket({
          fd: delivery.fd,
          readable: true,
          writable: true,
          allowHalfOpen: false,
          ...options,
        });
        try {
          this.#native.transferred(delivery.token);
        } catch (error) {
          socket.destroy();
          throw error;
        }
        return socket;
      },
      adopt: () => {
        if (decided) throw new Error('PHXP delivery has already been decided');
        if (!socket) throw new Error('PHXP descriptor must be wrapped before adoption');
        this.#native.adopt(delivery.token);
        decided = true;
      },
      reject: (reasonCode = REJECT_ADOPTION_FAILED) => {
        if (decided) throw new Error('PHXP delivery has already been decided');
        socket?.destroy();
        this.#native.reject(delivery.token, reasonCode);
        decided = true;
      },
      release: () => this.#native.release(connectionId),
    });

    try {
      this.emit('connection', handoff);
    } catch (error) {
      if (!decided) handoff.reject(REJECT_ADOPTION_FAILED);
      this.emit('error', error);
      return;
    }
    if (!decided) {
      handoff.reject(REJECT_ADOPTION_FAILED);
      this.emit('error', new Error('PHXP connection listener returned without adopting or rejecting'));
    }
  }
}
