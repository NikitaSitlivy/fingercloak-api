// rdap.mjs — RDAP по IP/ASN через публичный агрегатор rdap.org.
// Работает только если RDAP_ENABLE === "1".
import { request } from 'undici';

const TIMEOUT_MS = Number(process.env.RDAP_TIMEOUT_MS || 2500);
const MAX_REDIRECTS = 5;

async function getJsonFollow(url) {
  let current = url;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const { statusCode, headers, body } = await request(current, {
        method: 'GET',
        headers: {
          accept: 'application/rdap+json, application/json',
          // некоторые RDAP узлы любят нормальный UA
          'user-agent': 'fingercloak/rdap (+https://fingercloak.com)'
        },
        signal: controller.signal
      });

      // 2xx — ок
      if (statusCode >= 200 && statusCode < 300) {
        const txt = await body.text();
        return JSON.parse(txt);
      }

      // 3xx — попробуем перейти по Location
      if ([301, 302, 303, 307, 308].includes(statusCode)) {
        const loc = headers.location || headers.Location;
        if (!loc) throw new Error(`Redirect ${statusCode} without Location`);
        // абсолютный/относительный — undici сам разберётся
        current = new URL(loc, current).toString();
        if (process.env.RDAP_DEBUG === '1') console.log('[RDAP] redirect ->', current);
        continue; // следующий виток цикла
      }

      // остальное — ошибка
      throw new Error(`HTTP ${statusCode}`);
    } finally {
      clearTimeout(t);
    }
  }
  throw new Error(`Too many redirects (> ${MAX_REDIRECTS})`);
}

function pickRirFromHandle(h = '') {
  const s = String(h || '').toUpperCase();
  if (s.includes('APNIC'))  return 'APNIC';
  if (s.includes('ARIN'))   return 'ARIN';
  if (s.includes('RIPE'))   return 'RIPE';
  if (s.includes('LACNIC')) return 'LACNIC';
  if (s.includes('AFRINIC'))return 'AFRINIC';
  return null;
}

function extractOrg(entities = []) {
  for (const e of entities || []) {
    const card = e?.vcardArray?.[1];
    if (Array.isArray(card)) {
      for (const item of card) {
        if (item?.[0] === 'fn' && item?.[3]) return String(item[3]);
      }
    }
    if (e?.roles?.includes?.('registrant') && e?.handle) return e.handle;
  }
  return null;
}

export async function rdapByIp(ip) {
  const j = await getJsonFollow(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
  if (process.env.RDAP_DEBUG === '1') console.log('[RDAP] ip ok:', ip);
  const rir = pickRirFromHandle(j?.port43) || pickRirFromHandle(j?.handle) || null;
  const org = extractOrg(j?.entities) || j?.name || null;

  // Попробуем вытянуть AS из связанных ссылок
  let asn = null;
  const link = (j?.links || []).find(l => /\/autnum\/AS?\d+$/i.test(l?.href || ''));
  if (link?.href) {
    try {
      const a = await getJsonFollow(link.href);
      const num = a?.handle?.toString().replace(/^AS/i, '');
      if (num && /^\d+$/.test(num)) asn = 'AS' + num;
    } catch (e) {
      if (process.env.RDAP_DEBUG === '1') console.warn('[RDAP] autnum follow failed:', e?.message || e);
    }
  }
  return { rir, org, asn };
}

export async function rdapByAsn(asn) {
  const clean = String(asn || '').replace(/^AS/i, '');
  const j = await getJsonFollow(`https://rdap.org/autnum/${encodeURIComponent(clean)}`);
  const rir = pickRirFromHandle(j?.port43) || pickRirFromHandle(j?.handle) || null;
  const org = extractOrg(j?.entities) || j?.name || null;
  const handle = j?.handle?.toString().toUpperCase();
  const outAsn = handle?.startsWith('AS') ? handle : (clean ? `AS${clean}` : null);
  return { rir, org, asn: outAsn };
}

export async function rdapLookup({ ip = null, asn = null } = {}) {
  if (process.env.RDAP_ENABLE !== '1') return null;
  try {
    if (asn) return await rdapByAsn(asn);
    if (ip)  return await rdapByIp(ip);
  } catch (e) {
    if (process.env.RDAP_DEBUG === '1') {
      console.warn('[RDAP] lookup failed:', e?.message || e);
    }
  }
  return null;
}
