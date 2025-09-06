// indexnow.mjs
const INDEXNOW_ENDPOINT = 'https://api.indexnow.org/IndexNow';

function chunk(arr, n) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
}

function normalizeUrls(urls = [], host) {
  const u = new URL('https://' + host);
  return [...new Set(
    urls
      .filter(Boolean)
      .map(String)
      .map(s => s.trim())
      .map(s => {
        // Разрешаем относительные пути вида "/lab"
        if (s.startsWith('/')) return `https://${host}${s}`;
        return s;
      })
      .filter(s => {
        try {
          const x = new URL(s);
          return x.host === u.host; // строго тот же host
        } catch { return false; }
      })
  )];
}

async function postOnce(body) {
  const res = await fetch(INDEXNOW_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text().catch(() => '');
  return { ok: res.ok, status: res.status, text };
}

export async function sendIndexNow(urls, {
  host,
  key,
  keyLocation,
  batchSize = 1000,
  maxRetries = 3,
} = {}) {
  if (!host || !key || !keyLocation) {
    throw new Error('IndexNow: host/key/keyLocation are required');
  }

  const list = normalizeUrls(urls, host);
  if (!list.length) return { sent: 0, batches: 0 };

  const batches = chunk(list, batchSize);
  for (const part of batches) {
    const body = { host, key, keyLocation, urlList: part };
    let attempt = 0;
    // ретраи на 429/5xx
    while (true) {
      attempt++;
      const { ok, status, text } = await postOnce(body);
      if (ok) break;
      if ((status === 429 || status >= 500) && attempt <= maxRetries) {
        const delay = 300 * attempt; // простой backoff
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw new Error(`IndexNow failed [${status}] ${text || ''}`.trim());
    }
  }
  return { sent: list.length, batches: batches.length };
}
