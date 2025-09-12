// fp.mjs — доменная логика вокруг normalize/hashing/store + серверные обогащения
import { normalizePayload } from './normalize.mjs';
import { hmacIp as anonIp, makeStableId, makeContentHash, hammingDistanceHex } from './hashing.mjs';
import { saveSnapshot, getById, getBySession, search as storeSearch, stats as storeStats } from './store.mjs';
import { getChunks } from './chunks.mjs'; // ВАЖНО: lease-чтение (НЕ удаляет)

const VERSION = '1.4.0';

// утилита для IP (учитываем прокси, если включён trust proxy)
export function extractClientIp(req) {
  return req.headers['x-forwarded-for']?.toString().split(',')[0].trim()
    || req.ip
    || req.socket?.remoteAddress
    || 'local';
}

export function getVersionInfo() {
  return { api: 'fingercloak', version: VERSION };
}

/**
 * saveFingerprint теперь умеет принимать серверные обогащения:
 *  - headersSrv: { order[], hash, sample[] }
 *  - geoSrv:     { asn, isp, country, region, city }
 *  - rdap:       { asn, org, country, rir }
 *
 * и склеивает частичные чанки (edge/dns/webrtc/tls/tcp) по sessionId (corrId)
 * через НЕразрушающее чтение (lease).
 */
export async function saveFingerprint({ ip, ua, origin = null, payload, headersSrv = null, geoSrv = null, rdap = null }) {
  // 1) нормализуем «сырой» снимок из лаборатории
  const normalized = normalizePayload(payload, { ua });

  // 2) session/corrId
  const sessionId = payload?.meta?.sessionId || null;
  const consent = payload?.consent || null;

  // 3) подтянем частичные чанки (edge/dns/webrtc/tls/tcp), НЕ удаляя их
  const parts = sessionId ? (await getChunks(sessionId)) : null;

  // 4) соберём network-раздел
  const network = {};

  // (а) «живые» части, пришедшие через ingest
  if (parts?.edge)   network.edge   = parts.edge;
  if (parts?.dns)    network.dns    = parts.dns;
  if (parts?.webrtc) network.webrtc = parts.webrtc;
  if (parts?.tls)    network.tls    = parts.tls;
  if (parts?.tcp)    network.tcp    = parts.tcp;

  // (б) серверные обогащения (если edge не предоставил аналогичные)
  const haveEdgeHeaders = !!network.edge?.headers;
  if (!haveEdgeHeaders && headersSrv) network.headersSrv = headersSrv;

  const haveEdgeGeo = !!network.edge?.geo;
  if (!haveEdgeGeo && geoSrv) network.geoSrv = geoSrv;

  if (rdap) network.rdap = rdap;

  if (Object.keys(network).length) {
    normalized.network = network;
  }

  // 5) стабильные идентификаторы (ядро/контент)
  const stableId    = makeStableId(normalized);
  const contentHash = makeContentHash(normalized);

  // 6) финальный снапшот
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

  const saved = saveSnapshot(entry);

  // 7) служебные флаги — что из network было найдено
  const networkFound = {
    edge:       !!network.edge,
    dns:        !!network.dns,
    webrtc:     !!network.webrtc,
    tls:        !!network.tls,
    tcp:        !!network.tcp,
    headersSrv: !!network.headersSrv,
    geoSrv:     !!network.geoSrv,
    rdap:       !!network.rdap
  };

  return { ...saved, networkFound };
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

// getSession оставляем как есть (по снимкам), т.к. фронт уже опрашивает /api/fp/debug/chunks/:sid
// и объединяет результаты; это не требует правок server.mjs.
export function getSession(sessionId) {
  const items = getBySession(sessionId);
  if (!items.length) return null;
  return { ok: true, sessionId, total: items.length, items: items.map(s => ({ id: s.id, ts: s.ts, scores: s.derived?.scores })) };
}

export function getStats() {
  return storeStats();
}
