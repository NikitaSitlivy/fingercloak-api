// webrtc_ingest.mjs
// Приём ICE-кандидатов/статистики от фронта (WebRTC leak).

import { addChunk } from './chunks.mjs';

function normStr(x, max = 256) {
  if (typeof x !== 'string') return null;
  const s = x.trim();
  return s ? s.slice(0, max) : null;
}
function clamp(arr, n = 2000) {
  return Array.isArray(arr) ? arr.slice(0, n) : [];
}

function deriveSummary(cands = []) {
  let host = false, srflx = false, relay = false, v6 = false;
  for (const c of cands) {
    const t = (c.type || '').toLowerCase();
    if (t === 'host') host = true;
    if (t === 'srflx') srflx = true;
    if (t === 'relay') relay = true;
    if ((c.address && c.address.includes(':')) || (c.ip && c.ip.includes(':'))) v6 = true;
  }
  return { host, srflx, relay, v6 };
}

/**
 * Payload:
 * {
 *   corrId: "id",
 *   stun: { uri: "stun:stun.fingercloak.com:3478", ok: true },
 *   candidates: [
 *     { foundation, component, protocol, priority, ip, address, port, type, relAddr, relPort },
 *   ],
 *   stats: { gatherTimeMs: 123, iceSuccess: true }
 * }
 */
export function handleWebrtcIngest(body = {}) {
  const corrId = normStr(body.corrId, 128);
  if (!corrId) throw new Error('webrtc_ingest: corrId required');

  const stun = {
    uri: normStr(body?.stun?.uri, 256),
    ok: !!body?.stun?.ok
  };

  const candidates = clamp(body.candidates, 2000).map(c => ({
    protocol: normStr(c.protocol, 8),
    ip: normStr(c.ip || c.address, 64),
    port: Number.isFinite(+c.port) ? +c.port : null,
    type: normStr(c.type, 16),
    relAddr: normStr(c.relAddr, 64),
    relPort: Number.isFinite(+c.relPort) ? +c.relPort : null,
    foundation: normStr(c.foundation, 64),
    priority: Number.isFinite(+c.priority) ? +c.priority : null
  })).filter(c => c.type && (c.ip || c.relAddr));

  const stats = {
    gatherTimeMs: Number.isFinite(+body?.stats?.gatherTimeMs) ? +body.stats.gatherTimeMs : null,
    iceSuccess: !!body?.stats?.iceSuccess
  };

  const summary = deriveSummary(candidates);

  const out = { corrId, stun, candidates, stats, summary };
  addChunk(corrId, 'webrtc', out);
  return { ok: true, corrId, summary, total: candidates.length };
}
