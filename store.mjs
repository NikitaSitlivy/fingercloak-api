// store.mjs — простое in-memory хранилище + необязательный JSONL-лог в WRITE_DIR/snapshots.jsonl
import fs from 'fs';
import path from 'path';
import { nanoid } from 'nanoid';

const TTL_MS = 24 * 60 * 60 * 1000; // 1 день

const mem = {
  byId: new Map(),      // id -> snapshot
  bySession: new Map(), // sid -> ids[]
  indexTs: [],          // { ts, id } (для быстрых выборок последних)
};

let stream = null;
const DIR = process.env.WRITE_DIR;
if (DIR) {
  try {
    fs.mkdirSync(DIR, { recursive: true });
    stream = fs.createWriteStream(path.join(DIR, 'snapshots.jsonl'), { flags: 'a' });
  } catch (e) {
    console.warn('WRITE_DIR error, fallback to memory only:', e.message);
  }
}

function gc() {
  const now = Date.now();
  // вычищаем по TTL
  for (const [id, snap] of mem.byId) {
    if (now - snap.ts > TTL_MS) mem.byId.delete(id);
  }
  mem.indexTs = mem.indexTs.filter(r => mem.byId.has(r.id));
  for (const [sid, ids] of mem.bySession) {
    mem.bySession.set(sid, ids.filter(id => mem.byId.has(id)));
    if (mem.bySession.get(sid).length === 0) mem.bySession.delete(sid);
  }
}
setInterval(gc, 60_000).unref();

/** Сохраняем снапшот. Гарантированно проставляем id и ts. */
export function saveSnapshot(entry) {
  const id = entry.id || nanoid(10);
  const ts = entry.ts || Date.now();
  const snap = { ...entry, id, ts };

  mem.byId.set(id, snap);
  mem.indexTs.push({ ts, id });

  if (snap.sessionId) {
    const arr = mem.bySession.get(snap.sessionId) || [];
    arr.push(id);
    mem.bySession.set(snap.sessionId, arr);
  }

  if (stream) {
    try { stream.write(JSON.stringify(snap) + '\n'); } catch {}
  }
  return snap; // ВАЖНО: возвращаем объект уже с id/ts
}

export const getById = (id) => mem.byId.get(String(id)) || null;

export function getBySession(sessionId) {
  if (!sessionId) return [];
  const ids = mem.bySession.get(sessionId) || [];
  return ids.map(id => mem.byId.get(id)).filter(Boolean).sort((a,b) => a.ts - b.ts);
}

/** Поиск по последним снимкам с простыми фильтрами */
export function search({ from, to, band, ua, page, limit = 50 } = {}) {
  const fromTs = from ? +new Date(from) : 0;
  const toTs = to ? +new Date(to) : Date.now();
  const max = Math.min(Number(limit) || 50, 200);

  const ids = mem.indexTs
    .filter(r => r.ts >= fromTs && r.ts <= toTs)
    .slice(-5000) // берём последние N
    .map(r => r.id);

  const out = [];
  for (let i = ids.length - 1; i >= 0 && out.length < max; i--) {
    const s = mem.byId.get(ids[i]);
    if (!s) continue;
    if (band && s.derived?.scores?.band !== band) continue;
    if (ua && !((s.env?.ua || s.ua || '').toLowerCase().includes(String(ua).toLowerCase()))) continue;
    if (page && s.meta?.page !== page) continue;
    out.push(prune(s));
  }
  return { ok: true, total: out.length, items: out };
}

/** «лёгкая» форма для списков */
function prune(s) {
  const { id, ts, ua, origin, meta, env, screen, webgl, webgl2, webgpu, derived, stableId, contentHash } = s;
  return {
    id, ts, ua, origin, meta,
    env: {
      ua: env?.ua ?? null,
      languages: env?.languages ?? null,
      platform: env?.platform ?? null
    },
    screen: {
      dpr: screen?.dpr ?? null,
      colorDepth: screen?.colorDepth ?? null
    },
    webgl: {
      renderer: webgl?.renderer ?? null
    },
    webgl2: {
      renderer: webgl2?.renderer ?? null
    },
    webgpu: {
      supported: webgpu?.supported ?? null
    },
    stableId,
    contentHash,
    scores: derived?.scores ?? null
  };
}

/** Простейшие агрегаты */
export function stats() {
  const total = mem.byId.size;
  const last = mem.indexTs.at(-1)?.ts || null;
  const bands = { low: 0, medium: 0, high: 0 };
  for (const s of mem.byId.values()) {
    const b = s.derived?.scores?.band;
    if (b && bands[b] !== undefined) bands[b]++;
  }
  return { ok: true, total, last, bands };
}
