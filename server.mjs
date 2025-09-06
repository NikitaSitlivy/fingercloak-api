import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { sendIndexNow } from './indexnow.mjs';
import {
  saveFingerprint, getFingerprint, compareFingerprints,
} from './fp.mjs';

const app = express();

// Security headers & logs
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '1mb' }));

// CORS
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

// Health & sample
app.get('/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'dev', ts: Date.now() }));
app.get('/ping', (req, res) => res.type('text').send('pong'));
app.get('/api/version', (req, res) => res.json({ api: 'fingercloak', version: '1.1.0' }));
app.get('/api/echo', (req, res) => res.json({ query: req.query, headers: req.headers }));

/* ------------ SEO helpers: sitemap & feed ------------- */
const CANON = 'https://fingercloak.com';
const STATIC_URLS = [
  '/', '/lab', '/docs', '/privacy', '/terms'
];

app.get('/sitemap.xml', (req, res) => {
  const urls = STATIC_URLS
    .map(u => `<url><loc>${CANON}${u}</loc><changefreq>daily</changefreq><priority>${u==='/'? '1.0':'0.8'}</priority></url>`)
    .join('');
  const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`;
  res.type('application/xml').send(xml);
});

app.get('/feed.xml', (req, res) => {
  // простой фид — позже можем подцепить реальные релизы/посты
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

/* ---------------- IndexNow endpoint (как раньше) ---------------- */
const COOL_DOWN_MS = 2000;
const lastByIp = new Map();
app.post('/api/indexnow', async (req, res) => {
  try {
    const now = Date.now();
    const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress || 'local';
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
    const keyLocation = process.env.INDEXNOW_KEY_LOCATION || `https://${host}/${key}.txt`;

    const result = await sendIndexNow(list, { host, key, keyLocation });
    res.json({ ok: true, ...result, host, keyLocation });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

/* ---------------- Fingerprint endpoints ---------------- */

// собрать и вернуть id/хэш/флаги
app.post('/api/fp/collect', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress;
  const ua = req.headers['user-agent'];
  const payload = req.body?.payload ?? req.body; // принимаем и просто тело, и {payload}
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ ok: false, error: 'payload required' });
  }
  const entry = saveFingerprint({ ip, ua, payload });
  res.json({
    ok: true,
    id: entry.id,
    hash: entry.hash,
    nonzero: entry.nonzero,
    ts: entry.ts
  });
});

// получить сохранённый отпечаток (для страницы-демо и ссылок)
app.get('/api/fp/:id', (req, res) => {
  const item = getFingerprint(req.params.id);
  if (!item) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({
    ok: true,
    id: item.id,
    ts: item.ts,
    ua: item.ua,
    hash: item.hash,
    nonzero: item.nonzero,
    payload: item.payload
  });
});

// сравнить два снимка
app.get('/api/fp/compare', (req, res) => {
  const { a, b } = req.query;
  if (!a || !b) return res.status(400).json({ ok: false, error: 'a and b required' });
  const cmp = compareFingerprints(String(a), String(b));
  if (!cmp) return res.status(404).json({ ok: false, error: 'one or both ids not found' });
  res.json({ ok: true, ...cmp });
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API up on :${PORT}`));
