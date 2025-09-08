import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { sendIndexNow } from './indexnow.mjs';
import {
  saveFingerprint, getFingerprint, compareFingerprints,
  searchSnapshots, getSession, getStats, getVersionInfo, extractClientIp
} from './fp.mjs';

const app = express();

/* Security headers & logs */
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '1mb' }));

/* CORS */
const ALLOWED = (process.env.ALLOWED_ORIGINS || 'https://fingercloak.com,https://www.fingercloak.com')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    cb(new Error('CORS blocked'));
  },
  credentials: true
}));

/* Trust proxy (Render) */
if (process.env.TRUST_PROXY !== 'false') {
  app.set('trust proxy', true);
}

/* Health & sample */
app.get('/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'dev', ts: Date.now() }));
app.get('/ping', (req, res) => res.type('text').send('pong'));
app.get('/api/version', (req, res) => res.json(getVersionInfo()));
app.get('/api/echo', (req, res) => res.json({ query: req.query, headers: req.headers }));

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
    const now = Date.now();
    const ip = extractClientIp(req);
    const last = lastByIp.get(ip) || 0;
    if (now - last < COOL_DOWN_MS) return res.status(429).json({ error: 'Too Many Requests' });
    lastByIp.set(ip, now);

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

/* ---------------- Fingerprint endpoints ---------------- */

// собрать и вернуть id/хэш/флаги
/* ---------------- Fingerprint endpoints ---------------- */

// собрать и вернуть id/хэш/флаги
app.post('/api/fp/collect', (req, res) => {
  const ip = extractClientIp(req);
  const ua = req.headers['user-agent'];
  const origin = req.headers['origin'] || null;
  const payload = req.body?.payload ?? req.body;

  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ ok: false, error: 'payload required' });
  }
  try {
    const entry = saveFingerprint({ ip, ua, origin, payload });
    res.json({
      ok: true,
      id: entry.id,
      hash: entry.contentHash ?? entry.hash ?? null,
      nonzero: !!entry.nonzero,
      ts: entry.ts
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

// И ТОЛЬКО ПОТОМ — “общий” маршрут по id.
// Дополнительно сужаем маску id, чтобы не ловить "compare", "search" и т.п.
app.get('/api/fp/:id([A-Za-z0-9_-]{6,64})', (req, res) => {
  const item = getFingerprint(req.params.id);
  if (!item) return res.status(404).json({ ok: false, error: 'not found' });
  res.json(item);
});

// получить сохранённый снимок
app.get('/api/fp/:id', (req, res) => {
  const item = getFingerprint(req.params.id);
  if (!item) return res.status(404).json({ ok: false, error: 'not found' });
  res.json(item);
});

// сравнить два снимка
app.get('/api/fp/compare', (req, res) => {
  const { a, b } = req.query;
  if (!a || !b) return res.status(400).json({ ok: false, error: 'a and b required' });
  const cmp = compareFingerprints(String(a), String(b));
  if (!cmp) return res.status(404).json({ ok: false, error: 'one or both ids not found' });
  res.json(cmp);
});

// поиск по снимкам (простые фильтры)
app.get('/api/fp/search', (req, res) => {
  res.json(searchSnapshots(req.query));
});

// все снимки по sessionId
app.get('/api/fp/session/:sid', (req, res) => {
  const result = getSession(req.params.sid);
  if (!result) return res.status(404).json({ ok: false, error: 'not found' });
  res.json(result);
});

// агрегированные метрики
app.get('/api/fp/stats', (req, res) => {
  res.json(getStats());
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API up on :${PORT}`));
