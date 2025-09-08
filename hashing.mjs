import crypto from 'crypto';
import objectHash from 'object-hash';

// HMAC от IP (без обратимости), соль из env
export function hmacIp(ip) {
  const salt = process.env.IP_HMAC_SALT || 'dev-salt';
  return crypto.createHmac('sha256', salt).update(ip || 'unknown').digest('hex').slice(0, 32);
}

// Стабильный идентификатор «железо/движок» — избегаем сетевых/временных/поведенческих штук
export function makeStableId(normalized) {
  const pick = {
    ua: safe(normalized.env?.ua),
    hc: normalized.env?.hardwareConcurrency ?? null,
    dm: normalized.env?.deviceMemory ?? null,
    dpr: normalized.screen?.dpr ?? null,
    webgl: {
      vendor: normalized.webgl?.vendor || normalized.webgl2?.vendor || null,
      renderer: normalized.webgl?.renderer || normalized.webgl2?.renderer || null,
      maxTex: normalized.webgl?.maxTexture || normalized.webgl2?.maxTexture || null
    },
    webgpu: normalized.webgpu?.supported ? {
      featuresHash: normalized.webgpu.featuresHash,
      maxBindGroups: normalized.webgpu.limits?.maxBindGroups ?? null
    } : null,
    codecs: {
      wcVideo: normalized.webcodecs?.video || [],
      wcAudio: normalized.webcodecs?.audio || []
    },
    canvas: { hash: normalized.canvas?.hash || null },
    audio: { hash: normalized.audio?.hash || null },
    fonts: { presentCount: normalized.pro3?.fontsDeep?.present?.length || null } // если прилетит
  };
  return objectHash(pick, { algorithm: 'sha1', unorderedArrays: true });
}

// Контент-хэш «ядра», исключаем волатильные штуки (время, IP, лаги, поведение детально)
export function makeContentHash(normalized) {
  const core = {
    env: {
      ua: safe(normalized.env?.ua),
      languages: normalized.env?.languages,
      platform: normalized.env?.platform
    },
    screen: {
      colorDepth: normalized.screen?.colorDepth,
      dpr: normalized.screen?.dpr
    },
    webgl: {
      vendor: normalized.webgl?.vendor || normalized.webgl2?.vendor,
      renderer: normalized.webgl?.renderer || normalized.webgl2?.renderer,
      maxTexture: normalized.webgl?.maxTexture || normalized.webgl2?.maxTexture
    },
    webgpu: normalized.webgpu?.supported ? normalized.webgpu.featuresHash : 'no',
    webcodecs: {
      video: normalized.webcodecs?.video || [],
      audio: normalized.webcodecs?.audio || []
    },
    intl: {
      locale: normalized.intl?.locale,
      timeZone: normalized.intl?.timeZone
    },
    canvas: normalized.canvas?.hash,
    audio: normalized.audio?.hash
  };
  return objectHash(core, { algorithm: 'sha1', unorderedArrays: true });
}

export function hammingDistanceHex(a, b) {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  const len = Math.min(bufA.length, bufB.length);
  let dist = 0;
  for (let i = 0; i < len; i++) {
    const xor = bufA[i] ^ bufB[i];
    dist += popcnt(xor);
  }
  return dist + 8 * Math.abs(bufA.length - bufB.length);
}

function popcnt(x) {
  x = x - ((x >> 1) & 0x55);
  x = (x & 0x33) + ((x >> 2) & 0x33);
  return (((x + (x >> 4)) & 0x0F) * 0x01);
}

const safe = (s) => (typeof s === 'string' ? s.slice(0, 256) : s);
