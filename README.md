# fingercloak-api

Minimal Express API for FingerCloak, ready for Render + custom domain `api.fingercloak.com`.

## Local run

```bash
npm ci
npm run dev
# open http://localhost:3000/health
```

## Environment

- `ALLOWED_ORIGINS` — comma-separated list of allowed CORS origins.
  Default: `https://fingercloak.com,https://www.fingercloak.com`

## Deploy to Render

1. Push this repo to GitHub.
2. In Render → New → Web Service → select this repo. `render.yaml` will auto-configure.
3. After first deploy, open the temporary URL `/health` to verify.

### Custom Domain

- Add `api.fingercloak.com` in **Settings → Custom Domains**
- Create a CNAME in your DNS pointing to the Render target
- Verify and enable **Force HTTPS**

## Endpoints

- `GET /health` — service health
- `GET /ping` — `pong`
- `GET /api/version` — API version
- `GET /api/echo` — echoes query & headers
