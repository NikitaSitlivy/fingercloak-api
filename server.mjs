import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { sendIndexNow } from './indexnow.mjs';

const app = express();

// Security headers & logs
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json());

// CORS
const ALLOWED = (process.env.ALLOWED_ORIGINS || 'https://fingercloak.com,https://www.fingercloak.com')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // curl/healthchecks
    if (ALLOWED.includes(origin)) return cb(null, true);
    cb(new Error('CORS blocked'));
  },
  credentials: true
}));

// Health & sample endpoints
app.get('/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'dev', ts: Date.now() }));
app.get('/ping', (req, res) => res.type('text').send('pong'));
app.get('/api/version', (req, res) => res.json({ api: 'fingercloak', version: '1.0.0' }));
app.get('/api/echo', (req, res) => res.json({ query: req.query, headers: req.headers }));

/** -------- IndexNow endpoint --------
 *  POST /api/indexnow
 *  body: { url?: string, urls?: string[] }
 */
const COOL_DOWN_MS = 2000;
const lastByIp = new Map();

app.post('/api/indexnow', async (req, res) => {
  try {
    const now = Date.now();
    const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress || 'local';
    const last = lastByIp.get(ip) || 0;
    if (now - last < COOL_DOWN_MS) {
      return res.status(429).json({ error: 'Too Many Requests' });
    }
    lastByIp.set(ip, now);

    const { url, urls } = req.body || {};
    const list = [
      ...(Array.isArray(urls) ? urls : []),
      ...(url ? [url] : []),
    ];

    const host = process.env.INDEXNOW_HOST || 'fingercloak.com';
    const key = process.env.INDEXNOW_KEY;
    const keyLocation = process.env.INDEXNOW_KEY_LOCATION
      || `https://${host}/${key}.txt`;

    const result = await sendIndexNow(list, { host, key, keyLocation });
    res.json({ ok: true, ...result, host, keyLocation });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API up on :${PORT}`));
