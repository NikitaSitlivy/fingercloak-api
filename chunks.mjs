// chunks.mjs
// Буфер частичных сетевых чанков (edge/dns/webrtc/tls/tcp) по corrId/sessionId.
// Поддерживает Redis (если REDIS_URL задан), иначе — in-memory.
// Ключевое: чтение НЕ удаляет чанки (lease), данные живут до TTL и убираются GC.
// Интерфейс стабилен: addChunk/getChunks/takeChunks + debugStats().

import { kvGetJSON, kvSetJSON, kvDel, getRedis } from './redis_kv.mjs';

// TTL по умолчанию 5 минут — согласовано с фронтом (cookie fc_corr=300s).
// Можно увеличить/уменьшить через окружение: CHUNKS_TTL_MS=300000
const TTL_MS  = Number(process.env.CHUNKS_TTL_MS || 5 * 60 * 1000);
const TTL_SEC = Math.max(1, Math.floor(TTL_MS / 1000));

// Формат записи в хранилище:
// { ts: <lastTouch>, parts: { kind: payload }, tsByKind: { kind: ms }, reads: <int> }

const mem = new Map(); // fallback: corrId -> entry
const now = () => Date.now();

function createEntry() {
  return { ts: now(), parts: {}, tsByKind: {}, reads: 0 };
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
    entry.parts[kind] = payload ?? true;
    entry.tsByKind[kind] = touch;
    await kvSetJSON(key, entry, TTL_SEC);
    return { corrId, kind, ok: true, backend: 'redis', ttlMs: TTL_MS, count: Object.keys(entry.parts).length };
  }

  // In-memory
  const entry = mem.get(corrId) || createEntry();
  entry.ts = touch;
  entry.parts[kind] = payload ?? true;
  entry.tsByKind[kind] = touch;
  mem.set(corrId, entry);
  return { corrId, kind, ok: true, backend: 'memory', ttlMs: TTL_MS, count: Object.keys(entry.parts).length };
}

export async function getChunks(corrId) {
  if (!corrId) return null;

  if (getRedis()) {
    const key = `chunks:${corrId}`;
    const entry = await kvGetJSON(key);
    if (!entry) return null;
    // lease-чтение: не продляем TTL и не удаляем записи на чтении
    entry.reads = (entry.reads || 0) + 1; // локальный счётчик (без записи назад)
    return entry.parts || null;
  }

  const entry = mem.get(corrId);
  if (!entry) return null;
  // авто-TTL
  if (now() - entry.ts > TTL_MS) { mem.delete(corrId); return null; }
  entry.reads = (entry.reads || 0) + 1;
  // отдаём копию, чтобы снаружи не мутировали состояние
  return { ...entry.parts };
}

/**
 * Back-compat: раньше takeChunks удалял запись.
 * Теперь — это алиас на getChunks (lease-чтение, НЕ удаляет).
 * Если нужна явная очистка — используйте отдельный административный путь.
 */
export async function takeChunks(corrId) {
  return getChunks(corrId);
}

// Диагностика для /api/fp/debug/stats
export function debugStats() {
  if (getRedis()) {
    // Без обхода ключей Redis — только мета
    return { ok: true, backend: 'redis', ttlMs: TTL_MS };
  }
  const t = now();
  let alive = 0, expired = 0;
  const sample = [];
  for (const [sid, entry] of mem.entries()) {
    const idleMs = t - (entry.ts || 0);
    const isExp = idleMs > TTL_MS;
    if (isExp) expired++; else alive++;
    if (!isExp && sample.length < 100) {
      sample.push({
        sid,
        parts: Object.keys(entry.parts),
        updated: entry.ts,
        idleMs,
        reads: entry.reads || 0
      });
    }
  }
  return { ok: true, backend: 'memory', ttlMs: TTL_MS, size: mem.size, alive, expired, sample };
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
