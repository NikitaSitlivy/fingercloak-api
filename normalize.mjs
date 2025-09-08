// Нормализация "сырого" payload из Лаборатории в стабильную структуру.
// Правила: маскируем чувствительные поля, сортируем списки, квантуем числа, считаем derived.

import dayjs from 'dayjs';

const toInt = (v) => Number.isFinite(+v) ? Math.round(+v) : null;
const toFloat = (v, p = 3) => Number.isFinite(+v) ? +(+v).toFixed(p) : null;
const quant = (v, step = 1) => (Number.isFinite(+v) ? Math.round(+v / step) * step : null);
const sortUniq = (arr) => Array.from(new Set((arr || []).filter(Boolean))).sort();
const bool = (v) => !!v;

function safeSlice(arr, max = 256) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, max);
}

export function normalizePayload(raw = {}, meta = {}) {
  const nowServer = Date.now();
  const when = raw?.meta?.when ? +new Date(raw.meta.when) : null;
  const timeSkewMs = (when && Number.isFinite(when)) ? (nowServer - when) : null;

  /* --- ENV / META --- */
  const env = {
    ua: raw.env?.ua || meta.ua || null,
    languages: safeSlice(raw.env?.languages, 16),
    timezone: raw.env?.timezone || null,
    utcOffset: raw.env?.utcOffset || null,
    platform: raw.env?.platform || null,
    hardwareConcurrency: toInt(raw.env?.hardwareConcurrency),
    deviceMemory: toInt(raw.env?.deviceMemory),
    cookiesEnabled: bool(raw.env?.cookiesEnabled),
    dnt: raw.env?.doNotTrack ?? null,
  };

  /* --- SCREEN --- */
  const screen = {
    screen: raw.screen?.screen || null,
    avail: raw.screen?.avail || null,
    inner: raw.screen?.inner || null,
    colorDepth: toInt(raw.screen?.colorDepth),
    dpr: toFloat(raw.screen?.dpr, 2),
    touchPoints: toInt(raw.screen?.touchPoints),
  };

  /* --- STORAGE --- */
  const storage = {
    usageBytes: toInt(raw.storage?.usageBytes ?? raw.storage?.estimate?.usage),
    quotaBytes: toInt(raw.storage?.quotaBytes ?? raw.storage?.estimate?.quota),
    persisted: !!raw.storagePlus?.persisted,
    buckets: !!raw.storagePlus?.buckets?.supported,
  };

  /* --- GRAPHICS --- */
  const webgl = raw.webgl?.supported ? {
    supported: true,
    vendor: raw.webgl.vendor || null,
    renderer: raw.webgl.renderer || null,
    version: raw.webgl.version || null,
    glsl: raw.webgl.glsl || null,
    maxTexture: toInt(raw.webgl.maxTexture),
    maxAttribs: toInt(raw.webgl.maxAttribs),
    extCount: safeSlice(raw.webgl.extensionsFirst25, 256).length,
  } : { supported: false };

  const webgl2 = raw.webgl2?.supported ? {
    supported: true,
    vendor: raw.webgl2.vendor || null,
    renderer: raw.webgl2.renderer || null,
    version: raw.webgl2.version || null,
    glsl: raw.webgl2.glsl || null,
    maxTexture: toInt(raw.webgl2.maxTexture),
    maxAttribs: toInt(raw.webgl2.maxAttribs),
    drawBufs: toInt(raw.webgl2.maxDrawBuffers),
    colorAttach: toInt(raw.webgl2.maxColorAttachments),
    samples: toInt(raw.webgl2.samples),
    extCount: (raw.webgl2.extensions || []).length
  } : { supported: false };

  const webgpu = raw.webgpu?.supported ? {
    supported: true,
    featuresHash: hashList(raw.webgpu.adapter?.features),
    limits: {
      maxTextureDimension2D: toInt(raw.webgpu.adapter?.limits?.maxTextureDimension2D),
      maxColorAttachments: toInt(raw.webgpu.adapter?.limits?.maxColorAttachments),
      maxBindGroups: toInt(raw.webgpu.adapter?.limits?.maxBindGroups),
      maxVertexAttributes: toInt(raw.webgpu.adapter?.limits?.maxVertexAttributes),
      maxBufferSize: toInt(raw.webgpu.adapter?.limits?.maxBufferSize)
    }
  } : { supported: false };

  /* --- MEDIA / CODECS --- */
  const media = {
    video: Object.entries(raw.mediacap?.video || {}).reduce((acc, [k, v]) => {
      acc[k] = { supported: !!v.supported, powerEfficient: !!v.powerEfficient };
      return acc;
    }, {}),
    audio: Object.entries(raw.mediacap?.audio || {}).reduce((acc, [k, v]) => {
      acc[k] = { supported: !!v.supported, powerEfficient: !!v.powerEfficient };
      return acc;
    }, {}),
    display: raw.mediacap?.display || null
  };

  const webcodecs = raw.webcodecs?.supported ? {
    supported: true,
    video: Object.keys(raw.webcodecs.video || {}),
    audio: Object.keys(raw.webcodecs.audio || {}),
    image: Object.keys(raw.webcodecs.image || {}),
  } : { supported: false };

  const eme = raw.eme?.supported ? {
    supported: true,
    widevine: !!raw.eme.widevine?.ok,
    playready: !!raw.eme.playready?.ok
  } : { supported: false };

  /* --- PERMISSIONS / IO --- */
  const perms = raw.perms || {};
  const mediaDevices = {
    supported: !!raw.mediaDevices?.supported,
    deviceCount: toInt(raw.mediaDevices?.deviceCount),
    kinds: raw.mediaDevices?.kinds || null
  };

  /* --- TIMERS / PERF --- */
  const timers = {
    pnMinNs: toFloat(raw.timers?.performanceNow?.minDeltaNs, 3),
    pnP95Ns: toFloat(raw.timers?.performanceNow?.p95DeltaNs, 3),
    rafMeanMs: toFloat(raw.timers?.rAF?.meanDeltaMs, 3),
    rafP95Ms: toFloat(raw.timers?.rAF?.p95DeltaMs, 3),
  };

  /* --- CANVAS/AUDIO (только хэши) --- */
  const canvas = {
    hash: raw.canvas?.hash || raw.pro?.canvasGuard?.hashA || null,
    w: toInt(raw.canvas?.w),
    h: toInt(raw.canvas?.h)
  };
  const audio = {
    hash: raw.randomization?.audio?.hashes?.[0] || raw.pro?.audioGuard?.offlineHashes?.[0] || null,
    sr: toInt(raw.audioDeep?.realtime?.sampleRate) || 44100,
    len: toInt(raw.audioDeep?.offline?.[0]?.len)
  };

  /* --- INTL --- */
  const intl = {
    locale: raw.intl?.locale || raw.intlEdge?.dtfResolved?.locale || null,
    timeZone: raw.intl?.timeZone || raw.intlEdge?.dtfResolved?.timeZone || null,
    tzCount: toInt(raw.intlEdge?.tzCount)
  };

  /* --- RTC (без IP) --- */
  const rtc = {
    supported: !!raw.rtc,
    types: sortUniq(raw.rtc?.types),
    v6: !!raw.pro?.rtcDeep?.v6Present || !!raw.pro4?.webrtcPlus?.cands?.v6
  };

  /* --- Behavior (агрегаты) --- */
  const behavior = {
    pointerCount: toInt(raw.pro2?.behavior?.pointer?.count ?? raw.pro?.ioRealism?.hidGranted),
    pointerMean: toFloat(raw.pro2?.behavior?.pointer?.meanSpeed, 3),
    clicks: toInt(raw.pro2?.behavior?.clicks),
    wheels: toInt(raw.pro2?.behavior?.wheels),
    keys: toInt(raw.pro2?.behavior?.keys)
  };

  /* --- Touch soft evidence --- */
  const touchEvidence = {
    maxTouchPoints: toInt(raw.screen?.touchPoints),
    pointerEvent: !!raw.pro3?.pointerTouch?.pointerEvent,
    touchEvent: !!raw.pro3?.pointerTouch?.touchEvent,
    gestureEvent: !!raw.pro3?.pointerTouch?.gestureEvent
  };

  /* --- Консистентность / derived --- */
  const ua = env.ua || '';
  const uaLower = ua.toLowerCase();

  const uaVsWebgl = (wgl) => {
    if (!wgl?.renderer) return 'unknown';
    const r = wgl.renderer.toLowerCase();
    const ok = (
      (uaLower.includes('chrome') && r.includes('angle')) ||
      (uaLower.includes('safari') && !r.includes('angle')) ||
      (uaLower.includes('firefox') && r.includes('angle')) // на Win тоже angle
    );
    return ok ? 'ok' : 'suspect';
  };

  const intlVsTz = (intlObj) => {
    if (!intlObj?.locale || !env.timezone) return 'unknown';
    return env.timezone.toLowerCase().includes((intlObj.locale || '').slice(0,2)) ? 'ok' : 'mismatch';
  };

  const derived = {
    time: {
      clientWhen: when,
      serverReceived: nowServer,
      skewMs: timeSkewMs
    },
    consistency: {
      ua_vs_webgl_renderer: uaVsWebgl(webgl2.supported ? webgl2 : webgl),
      intl_vs_tz: intlVsTz(intl),
      mediaDevices_vs_perms: (mediaDevices.supported && raw.perms?.permissions?.microphone) ? 'ok' : 'unknown'
    },
    anomalies: {
      rafTooPerfect: timers.rafP95Ms !== null && timers.rafP95Ms < 17 ? false : false, // placeholder rule
      vpnLikely: (raw.pro4?.network?.http?.effectiveType === '4g' && raw.pro4?.network?.rttMs?.p50 >= 100) || false
    },
    touchSoft: {
      present: !!(touchEvidence.maxTouchPoints > 0 || touchEvidence.touchEvent || touchEvidence.pointerEvent),
      rule: 'absence-not-negative' // документируем политику
    },
    scores: computeScores({ webgl, webgl2, webgpu, timers, intl, env, touchEvidence })
  };

  return {
    meta: {
      when: raw.meta?.when || null,
      page: raw.meta?.page || null,
      app: raw.meta?.app || null,
      collectedAt: dayjs().toISOString()
    },
    env,
    screen,
    storage,
    webgl,
    webgl2,
    webgpu,
    media,
    webcodecs,
    eme,
    perms,
    mediaDevices,
    timers,
    canvas,
    audio,
    intl,
    rtc,
    behavior,
    touchEvidence,
    derived
  };
}

function hashList(list) {
  return Array.isArray(list) ? [...list].sort().join('|').slice(0, 4096) : '';
}

function clamp01(x) { return Math.max(0, Math.min(1, x)); }

function computeScores({ webgl, webgl2, webgpu, timers, intl, env, touchEvidence }) {
  // простые эвристики 0..100, «touch отсутствует» не штрафуем
  const hardwareRealism =
    50 +
    (webgl.supported || webgl2.supported ? 20 : 0) +
    (webgpu.supported ? 10 : 0) +
    (Number.isFinite(env.hardwareConcurrency) ? 10 : 0) +
    (Number.isFinite(env.deviceMemory) ? 10 : 0);

  const timingRealism =
    40 +
    (timers.rafP95Ms ? 20 * clamp01(18 / (timers.rafP95Ms || 18)) : 0) +
    (timers.pnP95Ns ? 20 : 0);

  const identityConsistency =
    40 +
    (env.languages?.length ? 10 : 0) +
    (intl.timeZone ? 10 : 0) +
    (env.cookiesEnabled ? 10 : 0);

  const behavior = 50 + (touchEvidence.present ? 5 : 0); // бонус за присутствие, отсутствие не штрафуем

  const total = Math.round(
    0.3 * hardwareRealism + 0.25 * timingRealism + 0.3 * identityConsistency + 0.15 * behavior
  );
  const band = total >= 80 ? 'high' : total >= 60 ? 'medium' : 'low';

  return {
    buckets: {
      hardwareRealism: Math.round(hardwareRealism),
      timingRealism: Math.round(timingRealism),
      identityConsistency: Math.round(identityConsistency),
      behavior: Math.round(behavior)
    },
    total,
    band
  };
}
