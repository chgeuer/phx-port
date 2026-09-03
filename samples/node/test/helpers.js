import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';

let sequence = 0;

export async function runtime(name) {
  const root = path.resolve('test', `.runtime-${process.pid}-${sequence++}-${name}`);
  await mkdir(root, { mode: 0o700 });
  return {
    root,
    endpoint: {
      path: path.join(root, 'handoff', 'receiver.sock'),
      validateRuntimeRoot: true,
    },
    async cleanup() {
      await rm(root, { recursive: true, force: true });
    },
  };
}

export function onceEvent(emitter, name) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      emitter.off(name, onValue);
      reject(error);
    };
    const onValue = (...values) => {
      emitter.off('error', onError);
      resolve(values);
    };
    emitter.once('error', onError);
    emitter.once(name, onValue);
  });
}
