// dns_ingest.mjs
// Приём списка резолверов из авторитативных логов и активных DoH-проб (DNS).

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
function oneOf(x, allowed) {
  const s = typeof x === 'string' ? x.toLowerCase().trim() : '';
  return allowed.includes(s) ? s : null;
}

/**
 * Payload ожидается такой:
 * {
 *   corrId: "id",
 *   method: "authoritative-logs" | "passive" | "active",
 *   tookMs: 123,
 *   resolvers: [
 *     {
 *       ip: "8.8.8.8", asn: "AS15169", isp: "Google LLC", country: "NL", v: 4,
 *       // расширенные поля (опц.)
 *       proto: "doh"|"udp"|"dot",
 *       dohName: "Google", dohEndpoint: "https://dns.google/resolve",
 *       verified: true, rttMs: 42
 *     }
 *   ],
 *   // опционально (для активных DoH-проб)
 *   dohResults: [
 *     { name:"Google", endpoint:"https://dns.google/resolve", ok:true, rttMs:42, status:200 }
 *   ]
 * }
 */
export function handleDnsIngest(body = {}) {
  const corrId = normStr(body.corrId, 128);
  if (!corrId) throw new Error('dns_ingest: corrId required');

  // Маппинг резолверов с поддержкой расширенных полей
  const resolvers = clamp(body.resolvers, 2000)
    .map(r => {
      const ip = normStr(r?.ip, 64);
      if (!ip) return null;
      return {
        ip,
        asn:     normStr(r?.asn, 32),
        isp:     normStr(r?.isp, 128),
        country: normStr(r?.country, 64),
        v:       (r?.v === 6 ? 6 : 4),

        // расширенные поля (если пришли — сохраняем)
        proto:       oneOf(r?.proto, ['udp','doh','dot']),
        dohName:     normStr(r?.dohName, 64),
        dohEndpoint: normStr(r?.dohEndpoint, 512),
        verified:    r?.verified === true,
        rttMs:       normInt(r?.rttMs),
      };
    })
    .filter(Boolean);

  // Сводка DoH-запросов (необязательная)
  const dohResults = clamp(body.dohResults, 100)
    .map(d => ({
      name:     normStr(d?.name, 64),
      endpoint: normStr(d?.endpoint, 512),
      ok:       !!d?.ok,
      rttMs:    normInt(d?.rttMs),
      status:   typeof d?.status === 'number' ? d.status : normStr(d?.status, 32),
    }))
    .filter(x => x.name || x.endpoint);

  const out = {
    corrId,
    method: normStr(body.method, 64) || 'authoritative-logs',
    tookMs: normInt(body.tookMs),
    resolvers,
    ...(dohResults.length ? { dohResults } : {}),
  };

  addChunk(corrId, 'dns', out);
  return { ok: true, corrId, method: out.method, count: resolvers.length };
}
