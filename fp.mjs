// fp.mjs — сбор/хэш/сравнение + in-memory storage
import crypto from 'node:crypto';

const SALT = process.env.FP_SALT || 'change-me';
const TTL_MS = 24 * 60 * 60 * 1000;

function stableStringify(obj) {
  const seen = new WeakSet();
  const order = (v) => {
    if (v && typeof v === 'object') {
      if (seen.has(v)) return null;
      seen.add(v);
      if (Array.isArray(v)) return v.map(order);
      return Object.keys(v).sort().reduce((a, k) => (a[k] = order(v[k]), a), {});
    }
    return v;
  };
  return JSON.stringify(order(obj));
}

export function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

export function anonIp(ip) {
  return sha256Hex(SALT + '|' + (ip || ''));
}

export function normalizePayload(p) {
  // лёгкая нормализация: обрежем гигантские поля, приведём типы
  const MAX = 8_192;
  const safe = JSON.parse(JSON.stringify(p || {}, (_, v) => (
    typeof v === 'string' && v.length > MAX ? v.slice(0, MAX) :
    v
  )));
  return safe;
}

export function fpHash(payload) {
  const norm = normalizePayload(payload);
  return sha256Hex(stableStringify(norm));
}

export function fpNonZero(payload) {
  const s = stableStringify(payload);
  // простая эвристика: есть ли хоть что-то кроме пустых/нулей
  return /[1-9a-zA-Z]/.test(s);
}

export function similarity(a, b) {
  // грубый косинус на множестве путей-ключей
  const keysA = new Set(Object.keys(flatten(a)));
  const keysB = new Set(Object.keys(flatten(b)));
  const inter = [...keysA].filter(k => keysB.has(k)).length;
  const denom = Math.sqrt(keysA.size * keysB.size) || 1;
  return inter / denom; // 0..1
}

function flatten(obj, prefix = '', out = {}) {
  if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      flatten(v, prefix ? `${prefix}.${k}` : k, out);
    }
  } else {
    out[prefix] = obj;
  }
  return out;
}

/* ---------- In-memory storage (swap to DB later) ---------- */
const store = new Map(); // id -> { id, ts, ipHash, ua, hash, payload }
function gc() {
  const now = Date.now();
  for (const [k, v] of store) if (now - v.ts > TTL_MS) store.delete(k);
}
setInterval(gc, 60_000).unref();

export function saveFingerprint({ ip, ua, payload }) {
  const norm = normalizePayload(payload);
  const id = crypto.randomUUID();
  const entry = {
    id,
    ts: Date.now(),
    ipHash: anonIp(ip),
    ua: String(ua || ''),
    hash: fpHash(norm),
    nonzero: fpNonZero(norm),
    payload: norm
  };
  store.set(id, entry);
  return entry;
}

export function getFingerprint(id) {
  return store.get(id) || null;
}

export function compareFingerprints(aId, bId) {
  const A = getFingerprint(aId);
  const B = getFingerprint(bId);
  if (!A || !B) return null;
  const sim = similarity(A.payload, B.payload);
  return {
    aId, bId,
    aHash: A.hash, bHash: B.hash,
    sameHash: A.hash === B.hash,
    similarity: sim,
    delta: diffObjects(A.payload, B.payload).slice(0, 200) // лимит примеров
  };
}

// очень простой дифф
function diffObjects(a, b, path = '') {
  const res = [];
  const keys = new Set([...Object.keys(a || {}), ...Object.keys(b || {})]);
  for (const k of keys) {
    const p = path ? `${path}.${k}` : k;
    const av = a?.[k], bv = b?.[k];
    if (typeof av === 'object' && typeof bv === 'object' && av && bv) {
      res.push(...diffObjects(av, bv, p));
    } else if (JSON.stringify(av) !== JSON.stringify(bv)) {
      res.push({ path: p, a: av, b: bv });
    }
  }
  return res;
}
