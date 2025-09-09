// chunks.mjs
// Временное in-memory хранилище частичных «чанков» (edge/dns/webrtc) по corrId.
// TTL 5 минут; периодическая очистка.

const TTL_MS = 5 * 60 * 1000;

const mem = new Map(); // corrId -> { ts, parts: { edge?, dns?, webrtc? } }

export function addChunk(corrId, kind, payload) {
  if (!corrId || typeof corrId !== 'string' || corrId.length > 128) {
    throw new Error('chunks.addChunk: invalid corrId');
  }
  const now = Date.now();
  const entry = mem.get(corrId) || { ts: now, parts: {} };
  entry.ts = now;
  entry.parts[kind] = payload;
  mem.set(corrId, entry);
  return { corrId, kind, ok: true };
}

export function getChunks(corrId) {
  const entry = mem.get(corrId);
  return entry ? entry.parts : null;
}

export function takeChunks(corrId) {
  const entry = mem.get(corrId);
  if (!entry) return null;
  mem.delete(corrId);
  return entry.parts || null;
}

function gc() {
  const now = Date.now();
  for (const [k, v] of mem.entries()) {
    if (now - v.ts > TTL_MS) mem.delete(k);
  }
}
setInterval(gc, 60_000).unref();
