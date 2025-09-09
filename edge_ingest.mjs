// edge_ingest.mjs
// Приём метаданных с Edge/Proxy/Worker (JA3/JA4/H2/TLS/IP/ASN/Geo, raw header order).

import crypto from 'crypto';
import { addChunk } from './chunks.mjs';

function verifySignature(body, signature, secret) {
  // Если секрет не задан — считаем, что подпись не требуется (удобно для локального теста).
  if (!secret) return true;
  if (!signature) return false;
  const h = crypto.createHmac('sha256', secret).update(JSON.stringify(body)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(String(signature)));
}

function normStr(x, max = 256) {
  if (typeof x !== 'string') return null;
  const s = x.trim();
  return s ? s.slice(0, max) : null;
}
function normInt(x, max = 1e12) {
  const n = Number(x);
  if (!Number.isFinite(n)) return null;
  if (n < -max || n > max) return null;
  return Math.round(n);
}
function clampList(arr, maxLen = 500) {
  return Array.isArray(arr) ? arr.slice(0, maxLen) : [];
}

/**
 * Ожидаемый payload от Edge:
 * {
 *   corrId: "uuid-or-nanoid",
 *   observedAt: 173... (ms),
 *   ip: "1.2.3.4",
 *   httpVersion: "2"|"1.1"|"3",
 *   alpn: "h2"|"http/1.1"|"h3",
 *   tls: { version: "TLS 1.3", cipher: "TLS_AES_128_GCM_SHA256" },
 *   ja3: "hex", ja3n: "hex", ja4: "token", ja4t: "token",
 *   h2: {
 *     settings: { headerTableSize, enablePush, initialWindowSize, maxHeaderListSize },
 *     windowUpdate: { sizeIncrement },
 *     prioritySig: "weight:dep:exclusive"
 *   },
 *   geo: { asn, isp, country, region, city },
 *   headers: { order: ["Name", ...], hash: "abc", sample: [["Name","val"], ...] },
 *   _signature: "hmac hex" // опционально (если EDGE_SHARED_SECRET задан)
 * }
 */
export function normalizeEdgePayload(raw = {}) {
  const out = {
    corrId: normStr(raw.corrId),
    observedAt: normInt(raw.observedAt) || Date.now(),
    ip: normStr(raw.ip, 64),
    httpVersion: normStr(raw.httpVersion, 16),
    alpn: normStr(raw.alpn, 16),
    tls: {
      version: normStr(raw?.tls?.version, 32),
      cipher: normStr(raw?.tls?.cipher, 64),
    },
    ja3: normStr(raw.ja3, 128),
    ja3n: normStr(raw.ja3n, 128),
    ja4: normStr(raw.ja4, 128),
    ja4t: normStr(raw.ja4t, 128),
    h2: raw.h2 ? {
      settings: {
        headerTableSize: normInt(raw.h2.settings?.headerTableSize),
        enablePush: normInt(raw.h2.settings?.enablePush),
        initialWindowSize: normInt(raw.h2.settings?.initialWindowSize),
        maxHeaderListSize: normInt(raw.h2.settings?.maxHeaderListSize),
      },
      windowUpdate: {
        sizeIncrement: normInt(raw.h2.windowUpdate?.sizeIncrement),
      },
      prioritySig: normStr(raw.h2.prioritySig, 128),
    } : null,
    geo: raw.geo ? {
      asn: normStr(raw.geo.asn, 32),
      isp: normStr(raw.geo.isp, 128),
      country: normStr(raw.geo.country, 64),
      region: normStr(raw.geo.region, 64),
      city: normStr(raw.geo.city, 64),
    } : null,
    headers: raw.headers ? {
      order: clampList(raw.headers.order, 256).map(x => normStr(x, 128)),
      hash: normStr(raw.headers.hash, 64),
      sample: clampList(raw.headers.sample, 20).map(pair => (Array.isArray(pair) ? [normStr(pair[0], 64), normStr(pair[1], 256)] : null)).filter(Boolean)
    } : null,
  };
  if (!out.corrId) throw new Error('edge_ingest: corrId required');
  return out;
}

export function handleEdgeIngest({ body, sharedSecret }) {
  const normalizedForSign = { ...body }; // тело для HMAC
  delete normalizedForSign._signature;

  const signature = body?._signature || body?.signature || null;
  if (!verifySignature(normalizedForSign, signature, sharedSecret)) {
    throw new Error('edge_ingest: signature invalid');
  }
  const normalized = normalizeEdgePayload(body);
  addChunk(normalized.corrId, 'edge', normalized);
  return { ok: true, corrId: normalized.corrId };
}
