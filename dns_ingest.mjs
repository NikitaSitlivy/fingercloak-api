// dns_ingest.mjs
// Приём списка резолверов из авторитативных логов и активных DoH-проб (DNS).

import { addChunk } from './chunks.mjs';
import { lookupIp } from './geoip.mjs';
import { cymruAsnLookup } from './rdap_cymru.mjs';

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
function ipVersion(ip) {
  if (!ip || typeof ip !== 'string') return null;
  return ip.includes(':') ? 6 : 4;
}
function normEcs(x) {
  // ECS как "a.b.c.d/nn" или "xxxx::/nn" → оставляем строкой, режем до 64
  const s = normStr(x, 64);
  if (!s) return null;
  // мини-фильтр мусора
  if (!/^[0-9a-f:.]+\/\d{1,3}$/i.test(s)) return null;
  return s;
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
 *       proto: "doh"|"udp"|"dot",
 *       dohName: "Google", dohEndpoint: "https://dns.google/resolve",
 *       verified: true, rttMs: 42,
 *       ecs: "1.2.3.0/24", ednsDo: true, qnameMin: true, ttl1: 300, ttl2: 298
 *     }
 *   ],
 *   dohResults: [{ name, endpoint, ok, rttMs, status }],
 *   rcodeCounts: { NOERROR: 12, NXDOMAIN: 3 }
 * }
 */
export async function handleDnsIngest(body = {}) {
  const corrId = normStr(body.corrId, 128);
  if (!corrId) throw new Error('dns_ingest: corrId required');

  const method = oneOf(body.method, ['authoritative-logs', 'passive', 'active']) || 'authoritative-logs';
  const tookMs = normInt(body.tookMs);

  // Нормализуем и дедуплицируем резолверы по ключу ip|proto|endpoint
  const seen = new Set();
  const rawResolvers = clamp(body.resolvers, 2000);

  const resolvers = [];
  for (const r of rawResolvers) {
    const ip = normStr(r?.ip, 64);
    if (!ip) continue;

    const v = r?.v === 6 ? 6 : (r?.v === 4 ? 4 : ipVersion(ip) || 4);

    const item = {
      ip,
      asn:     normStr(r?.asn, 32),
      isp:     normStr(r?.isp, 128),
      country: normStr(r?.country, 64),
      v,

      proto:       oneOf(r?.proto, ['udp', 'doh', 'dot']),
      dohName:     normStr(r?.dohName, 64),
      dohEndpoint: normStr(r?.dohEndpoint, 512),
      verified:    r?.verified === true,
      rttMs:       normInt(r?.rttMs),

      ecs:       normEcs(r?.ecs),
      ednsDo:    normBool(r?.ednsDo),
      qnameMin:  normBool(r?.qnameMin),
      ttl1:      normInt(r?.ttl1),
      ttl2:      normInt(r?.ttl2),
    };

    // enrich ASN/Geo если не пришло
    if (!item.asn || !item.country || !item.isp) {
      const g = lookupIp(ip) || {};
      if (!item.asn && g.asn) item.asn = String(g.asn);
      if (!item.country && g.country) item.country = normStr(g.country, 64);
      if (!item.isp && g.isp) item.isp = normStr(g.isp, 128);
    }

    // при необходимости — fallback через Team Cymru
    if ((!item.asn || !item.isp || !item.country) && process.env.DNS_ENRICH_FALLBACK_CYMRU === '1') {
      try {
        const c = await cymruAsnLookup(ip);
        if (c) {
          if (!item.asn && c.asn) item.asn = String(c.asn);
          if (!item.isp && c.org) item.isp = normStr(c.org, 128);
          if (!item.country && c.country) item.country = normStr(c.country, 64);
        }
      } catch { /* ignore */ }
    }

    const k = [item.ip, item.proto || '-', item.dohEndpoint || '-'].join('|');
    if (seen.has(k)) continue;
    seen.add(k);
    resolvers.push(item);
  }

  // Сортировка: verified desc → rtt asc → proto
  resolvers.sort((a, b) => {
    if (a.verified !== b.verified) return b.verified - a.verified;
    const ar = a.rttMs ?? Number.POSITIVE_INFINITY;
    const br = b.rttMs ?? Number.POSITIVE_INFINITY;
    if (ar !== br) return ar - br;
    return String(a.proto || '').localeCompare(String(b.proto || ''));
  });

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
