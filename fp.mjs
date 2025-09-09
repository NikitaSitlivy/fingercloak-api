// fp.mjs — слой доменной логики вокруг normalize/hashing/store
import { normalizePayload } from './normalize.mjs';
import { hmacIp as anonIp, makeStableId, makeContentHash, hammingDistanceHex } from './hashing.mjs';
import { saveSnapshot, getById, getBySession, search as storeSearch, stats as storeStats } from './store.mjs';
import { takeChunks } from './chunks.mjs';

const VERSION = '1.2.1';

// утилита для IP (учитываем прокси, если в server включён trust proxy)
export function extractClientIp(req) {
  return req.headers['x-forwarded-for']?.toString().split(',')[0].trim()
    || req.ip
    || req.socket?.remoteAddress
    || 'local';
}

export function getVersionInfo() {
  return { api: 'fingercloak', version: VERSION };
}

export function saveFingerprint({ ip, ua, origin = null, payload }) {
  // нормализуем «сырой» снимок из лаборатории
  const normalized = normalizePayload(payload, { ua });

  // corrId: используем meta.sessionId как объединяющий идентификатор
  const sessionId = payload?.meta?.sessionId || null;
  const consent = payload?.consent || null;

  // подтянем частичные чанки (edge/dns/webrtc), если они приходили до collect
  const chunks = sessionId ? takeChunks(sessionId) : null;
  if (chunks) {
    normalized.network = {
      edge: chunks.edge || null,
      dns: chunks.dns || null,
      webrtc: chunks.webrtc || null
    };
  }

  // стабильные идентификаторы (ядро/контент)
  const stableId = makeStableId(normalized);
  const contentHash = makeContentHash(normalized);

  const entry = {
    ok: true,
    ua: String(ua || ''),
    origin,
    ipHash: anonIp(ip),
    sessionId,
    consent,
    schemaVersion: 1,
    collectorVersion: payload?.collectorVersion || null,
    ...normalized,
    stableId,
    contentHash,
    nonzero: true
  };

  return saveSnapshot(entry); // возвращает снимок с id/ts
}

export function getFingerprint(id) {
  const s = getById(id);
  if (!s) return null;
  return { ok: true, ...s };
}

export function compareFingerprints(aId, bId) {
  const A = getById(aId);
  const B = getById(bId);
  if (!A || !B) return null;

  const sameStable = A.stableId === B.stableId;
  const distHash = hammingDistanceHex(A.contentHash, B.contentHash);

  // очень простой скор
  let compat = 50;
  if (sameStable) compat += 30;
  compat -= Math.min(30, Math.round(distHash / 4));
  if (A.env?.ua && B.env?.ua && A.env.ua.split('/')[0] === B.env.ua.split('/')[0]) compat += 10;
  compat = Math.max(0, Math.min(100, compat));

  return {
    ok: true,
    a: { id: A.id, ts: A.ts },
    b: { id: B.id, ts: B.ts },
    sameStable,
    contentHashHamming: distHash,
    compatScore: compat,
    topFactors: explain(A, B),
    diff: diffSnapshots(A, B)
  };
}

function explain(a, b) {
  const out = [];
  if (a.stableId === b.stableId) out.push({ kind: 'pro', msg: 'stableId совпадает' });
  if (a.env?.ua === b.env?.ua) out.push({ kind: 'pro', msg: 'User-Agent совпадает' });
  if (a.webgl?.renderer === b.webgl?.renderer || a.webgl2?.renderer === b.webgl2?.renderer)
    out.push({ kind: 'pro', msg: 'WebGL renderer совпадает' });
  if (a.canvas?.hash && a.canvas.hash === b.canvas?.hash)
    out.push({ kind: 'pro', msg: 'Canvas hash совпадает' });
  if (a.audio?.hash && a.audio.hash === b.audio?.hash)
    out.push({ kind: 'pro', msg: 'Audio hash совпадает' });

  if (a.screen?.dpr !== b.screen?.dpr) out.push({ kind: 'con', msg: 'Разный DPR' });
  if (a.intl?.timeZone !== b.intl?.timeZone) out.push({ kind: 'con', msg: 'Разный TimeZone' });
  return out.slice(0, 6);
}

function diffSnapshots(a, b) {
  const group = (key, fields) => {
    const g = {};
    for (const f of fields) g[f] = { a: a[key]?.[f] ?? null, b: b[key]?.[f] ?? null, same: (a[key]?.[f] ?? null) === (b[key]?.[f] ?? null) };
    return g;
  };
  return {
    env: group('env', ['ua', 'languages', 'platform', 'hardwareConcurrency', 'deviceMemory']),
    screen: group('screen', ['dpr', 'colorDepth', 'touchPoints']),
    webgl: group('webgl', ['vendor', 'renderer', 'maxTexture']),
    webgl2: group('webgl2', ['vendor', 'renderer', 'maxTexture']),
    webgpu: group('webgpu', ['supported']),
    intl: group('intl', ['locale', 'timeZone']),
    canvas: group('canvas', ['hash']),
    audio: group('audio', ['hash'])
  };
}

export function searchSnapshots(query) {
  return storeSearch(query);
}

export function getSession(sessionId) {
  const items = getBySession(sessionId);
  if (!items.length) return null;
  return { ok: true, sessionId, total: items.length, items: items.map(s => ({ id: s.id, ts: s.ts, scores: s.derived?.scores })) };
}

export function getStats() {
  return storeStats();
}
