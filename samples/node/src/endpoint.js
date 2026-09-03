import { createHash } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const VALID = /^[a-z0-9._-]{1,128}$/;
const WORKLOAD = /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;

export class EndpointError extends Error {}

export async function development(projectPath) {
  let canonical;
  try {
    canonical = await realpath(projectPath);
  } catch (error) {
    throw new EndpointError(`canonicalize project path: ${error.message}`);
  }
  if (!path.isAbsolute(canonical)) {
    throw new EndpointError('development identity must be a canonical absolute project path');
  }
  return Object.freeze({ kind: 'development', value: canonical });
}

export function production(workloadId) {
  validateWorkloadId(workloadId);
  return Object.freeze({ kind: 'production', value: workloadId });
}

export function validateWorkloadId(value) {
  if (typeof value !== 'string' || !WORKLOAD.test(value)) {
    throw new EndpointError(
      "logical workload ID must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-', and start and end with a letter or digit",
    );
  }
}

export function validateRole(role) {
  if (typeof role !== 'string' || !VALID.test(role)) {
    throw new EndpointError(
      "role must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-'",
    );
  }
}

export function endpointHash(identity, role) {
  return createHash('sha256')
    .update(identity)
    .update(Buffer.from([0]))
    .update(role)
    .digest('hex');
}

export function deriveEndpoint(identity, role, runtimeOverride = undefined) {
  validateRole(role);
  if (!identity || !['development', 'production'].includes(identity.kind)) {
    throw new EndpointError('unknown PHXP endpoint identity');
  }
  if (identity.kind === 'development') {
    if (!identity.value || !path.isAbsolute(identity.value)) {
      throw new EndpointError('development identity must be a canonical absolute project path');
    }
  } else {
    validateWorkloadId(identity.value);
  }

  const environmentOverride = process.env.PHX_PORT_RUNTIME_DIR || undefined;
  const override = runtimeOverride ?? environmentOverride;
  let root;
  if (override !== undefined) {
    root = path.normalize(String(override));
  } else if (identity.kind === 'production') {
    if (process.platform === 'darwin') {
      throw new EndpointError('production PHXP on macOS requires PHX_PORT_RUNTIME_DIR');
    }
    root = '/run/phx-port';
  } else if (process.platform === 'linux') {
    if (!process.env.XDG_RUNTIME_DIR) {
      throw new EndpointError('XDG_RUNTIME_DIR is unavailable; set it or specify a PHXP endpoint');
    }
    root = path.join(process.env.XDG_RUNTIME_DIR, 'phx-port');
  } else if (process.platform === 'darwin') {
    root = `/tmp/phx-port-${process.geteuid()}`;
  } else {
    throw new EndpointError(`PHXP requires Linux or macOS, not ${process.platform}`);
  }

  const socketPath = path.join(root, 'handoff', `${endpointHash(identity.value, role)}.sock`);
  validateSocketPath(socketPath);
  return Object.freeze({
    path: socketPath,
    validateRuntimeRoot: identity.kind === 'development',
  });
}

export async function inspectEndpoint(socketPath) {
  const info = await lstat(socketPath);
  return {
    isSocket: info.isSocket(),
    uid: info.uid,
    mode: info.mode & 0o777,
    device: info.dev,
    inode: info.ino,
  };
}

export function validateSocketPath(socketPath) {
  const maximum = process.platform === 'linux' ? 107 : process.platform === 'darwin' ? 103 : 0;
  if (!maximum) {
    throw new EndpointError(`PHXP requires Linux or macOS, not ${process.platform}`);
  }
  if (Buffer.byteLength(socketPath) > maximum) {
    throw new EndpointError(`PHXP endpoint path is too long: ${socketPath}`);
  }
}
