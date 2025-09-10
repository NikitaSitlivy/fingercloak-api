// tls_ingest.mjs
// Приём TLS/JA3/JA4/H2 с прокси/edge (если хотите без edge — это ваш собственный прокси/Nginx-сенсор)

import crypto from 'crypto';
import { addChunk } from './chunks.mjs';

function verifySignature(body, signature, secret) {
  if (!secret) return true;
  if (!signature) return false;
  const h = crypto.createHmac('sha256', secret).update(JSON.stringify(body)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(String(signature)));
}

const ns = (x, max = 256) => (typeof x === 'string' ? (x.trim() || null)?.slice(0, max) : null);
const ni = (x, max = 1e12) => {
  const n = Number(x);
  if (!Number.isFinite(n)) return null;
  if (n < -max || n > max) return null;
  return Math.round(n);
};

export function normalizeTlsPayload(raw = {}) {
  const out = {
    corrId: ns(raw.corrId, 128),
    observedAt: ni(raw.observedAt) || Date.now(),
    httpVersion: ns(raw.httpVersion, 16),
    alpn: ns(raw.alpn, 16),
    tls: {
      version: ns(raw?.tls?.version, 32),
      cipher: ns(raw?.tls?.cipher, 64),
    },
    ja3: ns(raw.ja3, 128),
    ja3n: ns(raw.ja3n, 128),
    ja4: ns(raw.ja4, 128),
    ja4t: ns(raw.ja4t, 128),
    h2: raw.h2 ? {
      settings: {
        headerTableSize: ni(raw.h2.settings?.headerTableSize),
        enablePush: ni(raw.h2.settings?.enablePush),
        initialWindowSize: ni(raw.h2.settings?.initialWindowSize),
        maxHeaderListSize: ni(raw.h2.settings?.maxHeaderListSize),
      },
      windowUpdate: {
        sizeIncrement: ni(raw.h2.windowUpdate?.sizeIncrement),
      },
      prioritySig: ns(raw.h2.prioritySig, 128),
    } : null,
  };
  if (!out.corrId) throw new Error('tls_ingest: corrId required');
  return out;
}

export function handleTlsIngest({ body, sharedSecret }) {
  const normalizedForSign = { ...body };
  delete normalizedForSign._signature;

  const signature = body?._signature || body?.signature || null;
  if (!verifySignature(normalizedForSign, signature, sharedSecret)) {
    throw new Error('tls_ingest: signature invalid');
  }
  const normalized = normalizeTlsPayload(body);
  addChunk(normalized.corrId, 'tls', normalized);
  return { ok: true, corrId: normalized.corrId };
}
