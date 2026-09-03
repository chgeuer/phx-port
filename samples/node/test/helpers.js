import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export async function runtime(name) {
  const temporaryRoot = process.platform === 'darwin' ? '/private/tmp' : os.tmpdir();
  const root = await mkdtemp(path.join(temporaryRoot, `px-${name}-`));
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
