// tcp_ingest.mjs
// Приём пассивного TCP fingerprint (из HAProxy/pcap-сенсора)

import { addChunk } from './chunks.mjs';

const ns = (x, max = 256) => (typeof x === 'string' ? (x.trim() || null)?.slice(0, max) : null);
const ni = (x, max = 1e12) => {
  const n = Number(x);
  if (!Number.isFinite(n)) return null;
  if (n < -max || n > max) return null;
  return Math.round(n);
};

export function handleTcpIngest(body = {}) {
  const corrId = ns(body.corrId, 128);
  if (!corrId) throw new Error('tcp_ingest: corrId required');

  const payload = {
    corrId,
    mss: ni(body.mss),
    ws: ni(body.ws),
    sack: !!body.sack,
    tsVal: ni(body.tsVal),
    ttlSeen: ni(body.ttlSeen),
    hopsEst: ni(body.hopsEst),
    mtuEst: ni(body.mtuEst),
    vpnLikely: !!body.vpnLikely,
    observedAt: ni(body.observedAt) || Date.now()
  };

  addChunk(corrId, 'tcp', payload);
  return { ok: true, corrId, vpnLikely: payload.vpnLikely };
}
