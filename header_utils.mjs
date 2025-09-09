// header_utils.mjs
// Вычисление порядка/кейса заголовков и стабильного хэша.

import crypto from 'crypto';

export function headerOrderAndHash(rawHeaders) {
  if (!Array.isArray(rawHeaders)) return { order: [], hash: null, sample: [] };

  const order = [];
  const sample = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = String(rawHeaders[i] || '');
    const value = String(rawHeaders[i + 1] || '');
    order.push(name);
    if (i < 20) sample.push([name, value]); // небольшой сэмпл для UI
  }
  const hash = crypto
    .createHash('sha256')
    .update(order.join('\n'))
    .digest('hex')
    .slice(0, 32);

  return { order, hash, sample };
}
