// chunks.mjs
// Временное хранилище частичных чанков (edge/dns/webrtc/tls/tcp) по corrId.
// TTL 5 минут; Redis (если REDIS_URL) или in-memory fallback.

import { kvGetJSON, kvSetJSON, kvDel, getRedis } from './redis_kv.mjs';

const TTL_MS = 5 * 60 * 1000;
const TTL_SEC = Math.floor(TTL_MS / 1000);

const mem = new Map(); // fallback: corrId -> { ts, parts: { kind: payload } }

export async function addChunk(corrId, kind, payload) {
  if (!corrId || typeof corrId !== 'string' || corrId.length > 128) {
    throw new Error('chunks.addChunk: invalid corrId');
  }
  const now = Date.now();

  // Redis first
  if (getRedis()) {
    const key = `chunks:${corrId}`;
    const entry = (await kvGetJSON(key)) || { ts: now, parts: {} };
    entry.ts = now;
    entry.parts[kind] = payload;
    await kvSetJSON(key, entry, TTL_SEC);
    return { corrId, kind, ok: true, backend: 'redis' };
  }

  // Fallback memory
  const entry = mem.get(corrId) || { ts: now, parts: {} };
  entry.ts = now;
  entry.parts[kind] = payload;
  mem.set(corrId, entry);
  return { corrId, kind, ok: true, backend: 'memory' };
}

export async function getChunks(corrId) {
  if (getRedis()) {
    const key = `chunks:${corrId}`;
    const entry = await kvGetJSON(key);
    return entry ? entry.parts : null;
  }
  const entry = mem.get(corrId);
  return entry ? entry.parts : null;
}

export async function takeChunks(corrId) {
  if (getRedis()) {
    const key = `chunks:${corrId}`;
    const entry = await kvGetJSON(key);
    if (!entry) return null;
    await kvDel(key);
    return entry.parts || null;
  }
  const entry = mem.get(corrId);
  if (!entry) return null;
  mem.delete(corrId);
  return entry.parts || null;
}

// Fallback GC (memory only)
if (!getRedis()) {
  function gc() {
    const now = Date.now();
    for (const [k, v] of mem.entries()) {
      if (now - v.ts > TTL_MS) mem.delete(k);
    }
  }
  setInterval(gc, 60_000).unref();
}
