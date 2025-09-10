// geoip.mjs — GeoIP ASN+City без регистраций:
// 1) Если заданы GEOIP_*_DB — используем MaxMind .mmdb
// 2) Иначе — fallback на geoip-lite (страна/регион/город)

import maxmind from 'maxmind';

let asnReader = null;
let cityReader = null;
let geoipLite = null;

export async function initGeoIP() {
  const asnPath  = process.env.GEOIP_ASN_DB  || '';
  const cityPath = process.env.GEOIP_CITY_DB || '';

  // Пытаемся открыть MaxMind базы (если указаны)
  try {
    if (asnPath)  asnReader  = await maxmind.open(asnPath);
    if (cityPath) cityReader = await maxmind.open(cityPath);
  } catch (e) {
    console.warn('[GeoIP] MaxMind init error:', e?.message || e);
  }

  // Если MaxMind нет — подключаем geoip-lite (без регистраций)
  if (!asnReader && !cityReader) {
    try {
      geoipLite = await import('geoip-lite'); // динамический импорт
      console.log('[GeoIP] using geoip-lite fallback');
    } catch (e) {
      console.warn('[GeoIP] geoip-lite not available:', e?.message || e);
    }
  }

  console.log('[GeoIP] ASN:', !!asnReader || !!geoipLite, 'City:', !!cityReader || !!geoipLite);
}

export function lookupIp(ip) {
  if (!ip || ip === 'local') return null;

  const out = { asn: null, isp: null, country: null, region: null, city: null };

  // 1) MaxMind сначала, если есть
  try {
    if (asnReader) {
      const asn = asnReader.get(ip);
      if (asn) {
        out.asn = asn.autonomous_system_number ? `AS${asn.autonomous_system_number}` : null;
        out.isp = asn.autonomous_system_organization || null;
      }
    }
  } catch {}

  try {
    if (cityReader) {
      const city = cityReader.get(ip);
      if (city) {
        out.country = city.country?.iso_code || null;
        out.region  = city.subdivisions?.[0]?.iso_code || city.subdivisions?.[0]?.names?.en || null;
        out.city    = city.city?.names?.en || null;
      }
    }
  } catch {}

  // 2) Fallback: geoip-lite (ASN не даёт; страна/регион/город — да)
  if ((!out.country && geoipLite)) {
    try {
      const r = geoipLite.default.lookup(ip); // { country, region, city, ... }
      if (r) {
        out.country = r.country || null;
        out.region  = Array.isArray(r.region) ? r.region[0] : r.region || null;
        out.city    = r.city || null;
      }
    } catch {}
  }

  const has = Object.values(out).some(Boolean);
  return has ? out : null;
}
