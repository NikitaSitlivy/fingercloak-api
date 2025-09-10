// geoip.mjs — только geoip-lite, без MaxMind
import geoip from 'geoip-lite';

export async function initGeoIP() {
  console.log('[GeoIP] using geoip-lite:', typeof geoip?.lookup === 'function');
}

export function lookupIp(ip) {
  if (!ip || ip === 'local') return null;

  const out = { asn: null, isp: null, country: null, region: null, city: null };

  try {
    const r = geoip.lookup(ip); // <- синхронно
    if (r) {
      out.country = r.country || null;
      // в geoip-lite region — код штата/региона, просто положим как есть
      out.region  = Array.isArray(r.region) ? r.region[0] : r.region || null;
      out.city    = r.city || null;
      // ASN в geoip-lite нет — оставляем null
    }
  } catch {}

  // если ничего не заполнили — вернём null, чтобы поле вообще не появлялось
  const has = Object.values(out).some(Boolean);
  return has ? out : null;
}
