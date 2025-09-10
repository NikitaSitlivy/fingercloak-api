// redis_kv.mjs
import Redis from 'ioredis';

let redis = null;

export function getRedis() {
  if (redis !== null) return redis;
  const url = process.env.REDIS_URL || '';
  if (!url) {
    redis = false; // явный фоллбек: Redis не используется
    return redis;
  }
  redis = new Redis(url, {
    maxRetriesPerRequest: 3,
    enableAutoPipelining: true,
    lazyConnect: true,
  });
  redis.on('error', (e) => console.warn('Redis error:', e?.message || e));
  return redis;
}

export async function kvGetJSON(key) {
  const r = getRedis();
  if (!r) return null;
  const s = await r.get(key);
  if (!s) return null;
  try { return JSON.parse(s); } catch { return null; }
}

export async function kvSetJSON(key, obj, ttlSec) {
  const r = getRedis();
  if (!r) return false;
  const s = JSON.stringify(obj);
  if (ttlSec) {
    await r.set(key, s, 'EX', ttlSec);
  } else {
    await r.set(key, s);
  }
  return true;
}

export async function kvDel(key) {
  const r = getRedis();
  if (!r) return 0;
  return r.del(key);
}
