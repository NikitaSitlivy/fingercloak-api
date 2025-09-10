// header_utils.mjs
// Вычисление порядка/кейса заголовков и стабильного хэша.

import crypto from 'crypto';

export function headerOrderAndHash(rawHeaders) {
  if (!Array.isArray(rawHeaders)) return { order: [], hash: null, sample: [] };

  const order = [];
  const sample = [];
  const SENSITIVE = new Set([
    'cookie','authorization','proxy-authorization',
    'x-forwarded-for','cf-connecting-ip','true-client-ip'
  ]);
  const maskIps = (s='') =>
    String(s)
      // IPv4
     .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, 'x.x.x.x')
     // IPv6 (грубо)
     .replace(/\b[a-f0-9:]{2,}\b/ig, 'v6::mask');
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = String(rawHeaders[i] || '');
    const value = String(rawHeaders[i + 1] || '');
    order.push(name);
    if (i < 40) {
     const lower = name.toLowerCase();
     if (!SENSITIVE.has(lower)) sample.push([name, maskIps(value.slice(0, 256))]);
    } // небольшой сэмпл для UI
  }
  const hash = crypto
    .createHash('sha256')
    .update(order.join('\n'))
    .digest('hex')
    .slice(0, 32);

  return { order, hash, sample };
}
