import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';

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

// 404
app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API up on :${PORT}`));
