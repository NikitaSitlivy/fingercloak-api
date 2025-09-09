// dns_ingest.mjs
// Приём списка резолверов из авторитативных логов (DNS-leak).

import { addChunk } from './chunks.mjs';

function normStr(x, max = 256) {
  if (typeof x !== 'string') return null;
  const s = x.trim();
  return s ? s.slice(0, max) : null;
}
function normInt(x) {
  const n = Number(x);
  return Number.isFinite(n) ? Math.round(n) : null;
}
function clamp(arr, n = 1000) {
  return Array.isArray(arr) ? arr.slice(0, n) : [];
}

/**
 * Payload:
 * {
 *   corrId: "id",
 *   method: "authoritative-logs",
 *   tookMs: 123,
 *   resolvers: [
 *     { ip: "8.8.8.8", asn: "AS15169", isp: "Google LLC", country: "NL", v: 4 },
 *     { ip: "2a00:...", asn: "AS...", isp: "...", country: "NL", v: 6 }
 *   ]
 * }
 */
export function handleDnsIngest(body = {}) {
  const corrId = normStr(body.corrId, 128);
  if (!corrId) throw new Error('dns_ingest: corrId required');

  const resolvers = clamp(body.resolvers, 2000).map(r => ({
    ip: normStr(r.ip, 64),
    asn: normStr(r.asn, 32),
    isp: normStr(r.isp, 128),
    country: normStr(r.country, 64),
    v: (r.v === 6 ? 6 : 4)
  })).filter(r => r.ip);

  const out = {
    corrId,
    method: normStr(body.method, 64) || 'authoritative-logs',
    tookMs: normInt(body.tookMs),
    resolvers
  };
  addChunk(corrId, 'dns', out);
  return { ok: true, corrId, count: resolvers.length };
}
