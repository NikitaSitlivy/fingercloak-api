// rdap_cymru.mjs
// Лёгкий ASN-lookup без регистраций через Team Cymru DNS TXT.
// Возвращает { asn, org, rir, country } или null.

import { promises as dns } from 'dns';

function parseTxt(txt) {
  // Склейка TXT-чанков и нормализация
  return String([].concat(...txt).join('')).trim();
}

export async function cymruAsnLookup(ip) {
  if (!ip || ip === 'local') return null;

  // 1) IP -> AS / country / rir
  // Пример: 8.8.8.8.origin.asn.cymru.com -> "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
  let asn = null, country = null, rir = null;
  try {
    const q1 = `${ip}.origin.asn.cymru.com`;
    const ans1 = await dns.resolveTxt(q1);
    const line1 = parseTxt(ans1);
    const parts1 = line1.split('|').map(s => s.trim());
    // parts1[0] = "15169"
    if (parts1[0] && /^\d+$/.test(parts1[0])) asn = 'AS' + parts1[0];
    country = parts1[2] || null; // "US"
    rir = parts1[3] ? parts1[3].toUpperCase() : null; // "ARIN"
  } catch (_) { /* ignore */ }

  if (!asn) return null;

  // 2) AS -> org
  // Пример: AS15169.asn.cymru.com -> "15169 | US | arin | 2000-03-30 | GOOGLE, US"
  let org = null;
  try {
    const q2 = `${asn}.asn.cymru.com`;
    const ans2 = await dns.resolveTxt(q2);
    const line2 = parseTxt(ans2);
    const parts2 = line2.split('|').map(s => s.trim());
    // org обычно в parts2[4]
    org = parts2[4] || null;
    // иногда встречается в upper-case — чуть подчистим
    if (org && org.length > 2) {
      // аккуратное капитализирование не делаем — оставим как есть
    }
  } catch (_) { /* ignore */ }

  return { asn, org, rir, country };
}
