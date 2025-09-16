// server.mjs — основной HTTP сервер (Express)
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

import { sendIndexNow } from './indexnow.mjs';
import {
  saveFingerprint, getFingerprint, compareFingerprints,
  searchSnapshots, getSession, getStats, getVersionInfo, extractClientIp
} from './fp.mjs';

import { headerOrderAndHash } from './header_utils.mjs';
import { handleEdgeIngest } from './edge_ingest.mjs';
import { handleDnsIngest } from './dns_ingest.mjs';
import { handleWebrtcIngest } from './webrtc_ingest.mjs';
import { handleTlsIngest } from './tls_ingest.mjs';
import { handleTcpIngest } from './tcp_ingest.mjs';

import { initGeoIP, lookupIp } from './geoip.mjs';
import { getChunks, debugStats } from './chunks.mjs';
import { rdapLookup } from './rdap.mjs';
import { cymruAsnLookup } from './rdap_cymru.mjs';

const app = express();
function getCookie(req, name) {
  try {
    const rx = new RegExp('(?:^|; )' + name.replace(/[-[\]/{}()*+?.\\^$|]/g, '\\$&') + '=([^;]*)');
    const m = (req.headers.cookie || '').match(rx);
    return m ? decodeURIComponent(m[1]) : null;
  } catch { return null; }
}

/* Security headers & logs */
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '2mb' })); // подняли лимит

/* CORS */
const ALLOWED = (process.env.ALLOWED_ORIGINS || 'https://fingercloak.com,https://www.fingercloak.com')
  .split(',')
  // срезаем возможные обрамляющие кавычки + хвостовые /
  .map(s => s.trim().replace(/^['"]+|['"]+$/g, '').replace(/\/+$/, '').toLowerCase())
  .filter(Boolean);


app.use(cors({
  origin(origin, cb) {
    const o = (origin || '')
  .trim()
  .replace(/^['"]+|['"]+$/g, '') // убираем случайные кавычки
  .replace(/\/+$/, '')
  .toLowerCase();
    if (!o) return cb(null, true);     // прямой заход без Origin (curl/health)
    if (ALLOWED.includes(o)) return cb(null, true);
    return cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true
}));

// Разрешаем preflight для всех путей (важно для edge/ingest)
app.options('*', cors());

/* Trust proxy (Render/CF) */
if (process.env.TRUST_PROXY !== 'false') {
  app.set('trust proxy', true);
}

/* Init GeoIP (async, без блокировки старта) */
initGeoIP().catch(()=>{});

/* Health & sample */
app.get('/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'dev', ts: Date.now() }));
app.get('/ping', (req, res) => res.type('text').send('pong'));
app.get('/api/version', (req, res) => res.json(getVersionInfo()));
app.get('/api/echo', (req, res) => {
  const httpVersion = req.httpVersion;
  const { order, hash, sample } = headerOrderAndHash(req.rawHeaders);
  res.json({ httpVersion, headerOrderHash: hash, headerOrder: order, headerSample: sample, query: req.query });
});

/* ------------ SEO helpers: sitemap & feed ------------- */
const CANON = 'https://fingercloak.com';
const STATIC_URLS = ['/', '/lab', '/docs', '/privacy', '/terms'];

app.get('/sitemap.xml', (req, res) => {
  const urls = STATIC_URLS
    .map(u => `<url><loc>${CANON}${u}</loc><changefreq>daily</changefreq><priority>${u==='/'? '1.0':'0.8'}</priority></url>`)
    .join('');
  const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`;
  res.type('application/xml').send(xml);
});

app.get('/feed.xml', (req, res) => {
  const now = new Date().toUTCString();
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
  <rss version="2.0"><channel>
    <title>FingerCloak Updates</title>
    <link>${CANON}</link>
    <description>Releases & lab updates</description>
    <lastBuildDate>${now}</lastBuildDate>
    <item><title>Lab online</title><link>${CANON}/lab</link><pubDate>${now}</pubDate></item>
  </channel></rss>`;
  res.type('application/rss+xml').send(xml);
});

/* ---------------- IndexNow endpoint ---------------- */
const COOL_DOWN_MS = 2000;
const lastByIp = new Map();
app.post('/api/indexnow', async (req, res) => {
  try {
    const t = Date.now();
    const ip = extractClientIp(req);
    const last = lastByIp.get(ip) || 0;
    if (t - last < COOL_DOWN_MS) return res.status(429).json({ error: 'Too Many Requests' });
    lastByIp.set(ip, t);

    const { url, urls } = req.body || {};
    const list = [
      ...(Array.isArray(urls) ? urls : []),
      ...(url ? [url] : []),
    ];
    const host = process.env.INDEXNOW_HOST || 'fingercloak.com';
    const key = process.env.INDEXNOW_KEY;
    const keyLocation = process.env.INDEXNOW_KEY_LOCATION || `https://${host}/indexnow.txt`;

    const result = await sendIndexNow(list, { host, key, keyLocation });
    res.json({ ok: true, ...result, host, keyLocation });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

/* ---------------- Ingest endpoints ---------------- */

// Лимит частоты только на ingest, чтобы не долбили.
const ingestLimiter = rateLimit({
  windowMs: 15 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(['/api/*/ingest'], ingestLimiter);
// Нормализуем corrId/sid/sessionId и логируем входящие ingest-запросы
app.use(['/api/*/ingest'], (req, _res, next) => {
  const b = req.body || {};
  const sid =
    b.corrId ||
    b.sid ||
    b.sessionId ||
    (b.meta && b.meta.sessionId) ||
    req.headers['x-fc-corr'] ||
    getCookie(req, 'fc_corr') ||
    null;

  if (sid) req.body.corrId = String(sid); // ⬅️ единое поле, которое ждут handle*Ingest
  console.log('[INGEST] path=%s sid=%s keys=%o', req.path, sid || '-', Object.keys(b));
  next();
});


app.post('/api/edge/ingest', (req, res) => {
  try {
    const shared = process.env.EDGE_SHARED_SECRET || '';
    const result = handleEdgeIngest({ body: req.body, sharedSecret: shared });
    res.json(result);
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

app.post('/api/tls/ingest', (req, res) => {
  try {
    const shared = process.env.TLS_SHARED_SECRET || process.env.EDGE_SHARED_SECRET || '';
    const result = handleTlsIngest({ body: req.body, sharedSecret: shared });
    res.json(result);
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

app.post('/api/dns/ingest', (req, res) => {
  try {
    console.log(
  '[INGEST DNS] sid=%s method=%s resolvers=%d doh=%d',
  req.body?.corrId,
  req.body?.method,
  (req.body?.resolvers || []).length,
  (req.body?.dohResults || []).length
);
    const result = handleDnsIngest(req.body);
    console.log('[INGEST DNS] ->', result);
    res.json(result);
  } catch (e) {
    console.error('[INGEST DNS] ERROR', e);
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});
app.post('/api/webrtc/ingest', (req, res) => {
  try {
    console.log('[INGEST WebRTC] sid=%s candidates=%d', req.body?.corrId, (req.body?.candidates || []).length);
    const result = handleWebrtcIngest(req.body);
    console.log('[INGEST WebRTC] ->', result);
    res.json(result);
  } catch (e) {
    console.error('[INGEST WebRTC] ERROR', e);
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

app.post('/api/tcp/ingest', (req, res) => {
  try {
    const result = handleTcpIngest(req.body);
    res.json(result);
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

/* ---------------- Fingerprint endpoints ---------------- */

// «Умное ожидание» поступления нужных чанков
async function waitUntilChunks(sid, kinds = [], timeoutMs = 8000, stepMs = 120) {
  if (!sid || !kinds.length || timeoutMs <= 0) return { ok:false, ready:[] };
  const t0 = Date.now();
  let ready = [];
  while (Date.now() - t0 < timeoutMs) {
    const parts = await getChunks(sid) || {};
    ready = kinds.filter(k => !!parts?.[k]);
    if (ready.length === kinds.length) return { ok:true, ready };
    await new Promise(r => setTimeout(r, stepMs));
  }
  return { ok:false, ready };
}

// собрать и вернуть id/хэш/флаги
app.post('/api/fp/collect', async (req, res) => {
  const ip = extractClientIp(req);
  const ua = req.headers['user-agent'];
  const origin = req.headers['origin'] || null;
  const payload = req.body?.payload ?? req.body;

  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ ok: false, error: 'payload required' });
  }

  // опциональное ожидание нужных чанков (webrtc,dns,tls,tcp,edge)
  const waitFor = String(req.query.waitFor || process.env.COLLECT_WAIT_FOR || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  const timeoutMs = Number(req.query.timeoutMs || process.env.COLLECT_TIMEOUT_MS || 8000);
  const sid = payload?.meta?.sessionId || null;

  let waited = { ok:false, ready:[] };
  if (sid && waitFor.length && timeoutMs > 0) {
    waited = await waitUntilChunks(sid, waitFor, timeoutMs).catch(()=>({ok:false,ready:[]}));
  }

  // серверные обогащения:
  const { order, hash, sample } = headerOrderAndHash(req.rawHeaders);
  const headersSrv = { order, hash, sample };

  let geoSrv = lookupIp(ip) || {};
  let rdap = await rdapLookup({ ip, asn: geoSrv?.asn || null }).catch(() => null);

  if (process.env.RDAP_FALLBACK_CYMRU === '1' && (!rdap || !rdap.asn || !geoSrv?.asn)) {
    const asnInfo = await cymruAsnLookup(ip).catch(() => null);
    if (asnInfo) {
      rdap = rdap || {};
      rdap.asn = rdap.asn || asnInfo.asn;
      rdap.org = rdap.org || asnInfo.org;
      rdap.rir = rdap.rir || asnInfo.rir;

      if (asnInfo.asn && !geoSrv.asn)         geoSrv.asn = asnInfo.asn;
      if (asnInfo.org && !geoSrv.isp)         geoSrv.isp = asnInfo.org;
      if (asnInfo.country && !geoSrv.country) geoSrv.country = asnInfo.country;
    }
  }

  try {
    const entry = await saveFingerprint({ ip, ua, origin, payload, headersSrv, geoSrv, rdap });
    res.json({
      ok: true,
      id: entry.id,
      hash: entry.contentHash ?? entry.hash ?? null,
      nonzero: !!entry.nonzero,
      ts: entry.ts,
      networkFound: entry.networkFound || null,
      waited, // отладка: какие чанки реально дождались
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

// ⚠️ СНАЧАЛА — специфичные подпути:
app.get('/api/fp/compare', (req, res) => {
  const { a, b } = req.query;
  if (!a || !b) return res.status(400).json({ ok: false, error: 'a and b required' });
  const cmp = compareFingerprints(String(a), String(b));
  if (!cmp) return res.status(404).json({ ok: false, error: 'one or both ids not found' });
  res.json(cmp);
});

app.get('/api/fp/search', (req, res) => {
  res.json(searchSnapshots(req.query));
});

app.get('/api/fp/session/:sid', (req, res) => {
  const result = getSession(req.params.sid);
  if (!result) return res.status(404).json({ ok: false, error: 'not found' });
  res.json(result);
});

app.get('/api/fp/stats', (req, res) => {
  res.json(getStats());
});

/* Диагностика чанков (по corrId/sessionId) */
app.get('/api/fp/debug/chunks/:sid', async (req, res) => {
  try {
    const parts = await getChunks(req.params.sid);
    res.json({ ok: true, corrId: req.params.sid, parts: parts || null });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

// Общий маршрут по id (после специфичных путей)
app.get('/api/fp/:id([A-Za-z0-9_-]{6,64})', (req, res) => {
  const item = getFingerprint(req.params.id);
  if (!item) return res.status(404).json({ ok: false, error: 'not found' });
  res.json(item);
});

// Диагностика стора чанков
app.get('/api/fp/debug/stats', (req, res) => {
  res.json({ ok: true, chunks: debugStats() });
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API up on :${PORT}`));
