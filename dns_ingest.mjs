// dns_ingest.mjs
// Приём списка резолверов из авторитативных логов и активных DoH-проб (DNS).

import { addChunk } from './chunks.mjs';

/* ------------ utils ------------ */
function normStr(x, max = 256) {
  if (typeof x !== 'string') return null;
  const s = x.trim();
  return s ? s.slice(0, max) : null;
}
function normInt(x) {
  const n = Number(x);
  return Number.isFinite(n) ? Math.round(n) : null;
}
function normBool(x) {
  return x === true ? true : x === false ? false : null;
}
function clamp(arr, n = 1000) {
  return Array.isArray(arr) ? arr.slice(0, n) : [];
}
function oneOf(x, allowed) {
  const s = typeof x === 'string' ? x.toLowerCase().trim() : '';
  return allowed.includes(s) ? s : null;
}

/**
 * Ожидаемый payload:
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
 *       verified: true, rttMs: 42,
 *       // сигналы авторитативного слоя (если есть)
 *       ecs: "1.2.3.0/24",         // EDNS ECS (как строка)
 *       ednsDo: true,              // DO-бит (DNSSEC OK)
 *       qnameMin: true,            // QNAME minimization
 *       ttl1: 300, ttl2: 298       // пример для кэш-теста (необязательно)
 *     }
 *   ],
 *   // опционально для активных DoH-проб
 *   dohResults: [
 *     { name:"Google", endpoint:"https://dns.google/resolve", ok:true, rttMs:42, status:200 }
 *   ],
 *   // опционально сводка по кодам ответов из авторитативных логов
 *   rcodeCounts: { NOERROR: 12, NXDOMAIN: 3 }
 * }
 */
export function handleDnsIngest(body = {}) {
  const corrId = normStr(body.corrId, 128);
  if (!corrId) throw new Error('dns_ingest: corrId required');

  const method = normStr(body.method, 64) || 'authoritative-logs';
  const tookMs = normInt(body.tookMs);

  // Нормализуем и дедуплицируем резолверы по ключу ip|proto|endpoint
  const seen = new Set();
  const resolvers = clamp(body.resolvers, 2000)
    .map((r) => {
      const ip = normStr(r?.ip, 64);
      if (!ip) return null;

      const item = {
        ip,
        asn:     normStr(r?.asn, 32),
        isp:     normStr(r?.isp, 128),
        country: normStr(r?.country, 64),
        v:       r?.v === 6 ? 6 : 4,

        // активные поля (если есть — сохраняем)
        proto:       oneOf(r?.proto, ['udp', 'doh', 'dot']),
        dohName:     normStr(r?.dohName, 64),
        dohEndpoint: normStr(r?.dohEndpoint, 512),
        verified:    r?.verified === true,           // только true фиксируем как true
        rttMs:       normInt(r?.rttMs),

        // сигналы из авторитативного слоя (все опц.)
        ecs:       normStr(r?.ecs, 64),
        ednsDo:    normBool(r?.ednsDo),
        qnameMin:  normBool(r?.qnameMin),
        ttl1:      normInt(r?.ttl1),
        ttl2:      normInt(r?.ttl2),
      };

      // ключ для дедупа
      const k = [item.ip, item.proto || '-', item.dohEndpoint || '-'].join('|');
      if (seen.has(k)) return null;
      seen.add(k);
      return item;
    })
    .filter(Boolean);

  // Сводка DoH-запросов (необязательная)
  const dohResults = clamp(body.dohResults, 200)
    .map((d) => ({
      name:     normStr(d?.name, 64),
      endpoint: normStr(d?.endpoint, 512),
      ok:       !!d?.ok,
      rttMs:    normInt(d?.rttMs),
      status:   typeof d?.status === 'number' ? d.status : normStr(d?.status, 32),
    }))
    .filter((x) => x.name || x.endpoint);

  // Опциональная сводка по RCODE (если прилетела)
  let rcodeCounts = null;
  if (body.rcodeCounts && typeof body.rcodeCounts === 'object') {
    rcodeCounts = {};
    for (const [k, v] of Object.entries(body.rcodeCounts)) {
      const kk = normStr(k, 32);
      const vv = normInt(v);
      if (kk && vv != null) rcodeCounts[kk] = vv;
    }
    if (!Object.keys(rcodeCounts).length) rcodeCounts = null;
  }

  const out = {
    corrId,
    method,
    tookMs,
    resolvers,
    ...(dohResults.length ? { dohResults } : {}),
    ...(rcodeCounts ? { rcodeCounts } : {}),
  };

  addChunk(corrId, 'dns', out);
  return {
    ok: true,
    corrId,
    method,
    count: resolvers.length,
    doh: dohResults.length || 0,
  };
}
