// chunks.mjs
// Буфер частичных сетевых чанков (edge/dns/webrtc/tls/tcp) по corrId/sessionId.
// Поддерживает Redis (если REDIS_URL задан), иначе — in-memory.
// Интерфейс стабилен: addChunk/getChunks/takeChunks + debugStats().

import { kvGetJSON, kvSetJSON, kvDel, getRedis } from './redis_kv.mjs';

// TTL по умолчанию 15s — хватает дождаться всех сетевых инжестов.
// Можно увеличить через окружение: CHUNKS_TTL_MS=25000
const TTL_MS  = Number(process.env.CHUNKS_TTL_MS || 15000);
const TTL_SEC = Math.max(1, Math.floor(TTL_MS / 1000));

// Формат записи в хранилище:
// { ts: <lastTouch>, parts: { kind: payload }, tsByKind: { kind: ms }, count: <int> }

const mem = new Map(); // fallback: corrId -> entry

function now() { return Date.now(); }

function createEntry() {
  return { ts: now(), parts: {}, tsByKind: {}, count: 0 };
}

export async function addChunk(corrId, kind, payload) {
  if (!corrId || typeof corrId !== 'string' || corrId.length > 128) {
    throw new Error('chunks.addChunk: invalid corrId');
  }
  if (!kind || typeof kind !== 'string') {
    throw new Error('chunks.addChunk: invalid kind');
  }

  const touch = now();

  // Redis
  if (getRedis()) {
    const key = `chunks:${corrId}`;
    const entry = (await kvGetJSON(key)) || createEntry();
    entry.ts = touch;
    entry.parts[kind] = payload;
    entry.tsByKind[kind] = touch;
    entry.count = Object.keys(entry.parts).length;
    await kvSetJSON(key, entry, TTL_SEC);
    return { corrId, kind, ok: true, backend: 'redis', ttlMs: TTL_MS, count: entry.count };
  }

  // In-memory
  const entry = mem.get(corrId) || createEntry();
  entry.ts = touch;
  entry.parts[kind] = payload;
  entry.tsByKind[kind] = touch;
  entry.count = Object.keys(entry.parts).length;
  mem.set(corrId, entry);
  return { corrId, kind, ok: true, backend: 'memory', ttlMs: TTL_MS, count: entry.count };
}

export async function getChunks(corrId) {
  if (!corrId) return null;
  if (getRedis()) {
    const key = `chunks:${corrId}`;
    const entry = await kvGetJSON(key);
    if (!entry) return null;
    // возвращаем только parts (как раньше), чтобы не ломать normalize()
    return entry.parts || null;
  }
  const entry = mem.get(corrId);
  if (!entry) return null;
  // авто-TTL
  if (now() - entry.ts > TTL_MS) { mem.delete(corrId); return null; }
  return entry.parts || null;
}

export async function takeChunks(corrId) {
  if (!corrId) return null;
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

// Диагностика для /api/fp/debug/stats
export function debugStats() {
  if (getRedis()) {
    // Без похода в Redis — только мета
    return { backend: 'redis', ttlMs: TTL_MS };
  }
  return { backend: 'memory', ttlMs: TTL_MS, size: mem.size };
}

// Периодический GC (только для памяти)
if (!getRedis()) {
  const tick = Math.min(TTL_MS, 5000);
  const t = setInterval(() => {
    const tnow = now();
    for (const [k, v] of mem) {
      if (tnow - (v?.ts || 0) > TTL_MS) mem.delete(k);
    }
  }, tick);
  if (typeof t.unref === 'function') t.unref();
}
