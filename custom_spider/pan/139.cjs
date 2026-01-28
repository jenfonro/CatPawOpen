// 139Yun (移动云盘/和彩云) OutLink play API.
// Keep only: POST /api/139/play

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OUTLINK_API_BASE = 'https://share-kd-njs.yun.139.com/yun-share/richlifeApp/devapp/IOutLink/';

// AES-128-CBC key (16 bytes). IV is randomly generated per request and is prepended to ciphertext.
const KEY_OUTLINK_STR = 'PVGDwmcvfs1uV3d1';
const KEY_OUTLINK = Buffer.from(KEY_OUTLINK_STR, 'utf8');

const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// X-Deviceinfo format matters; the version number does not. Keep a known-good value.
const DEFAULT_X_DEVICEINFO =
  '||9|12.27.0|chrome|143.0.0.0|pda50460feabd10141fb59a3ba787afb||windows 10|1624X1305|zh-CN|||';

function toStr(v) {
  return typeof v === 'string' ? v : v == null ? '' : String(v);
}

function normalizeBase64Input(value) {
  let s = toStr(value).trim();
  if (!s) return '';
  s = s.replace(/\s+/g, '');
  if (s.includes('-') || s.includes('_')) s = s.replace(/-/g, '+').replace(/_/g, '/');
  const mod = s.length % 4;
  if (mod === 2) s += '==';
  else if (mod === 3) s += '=';
  return s;
}

function aesCbcEncryptBase64(keyBuf, plainText) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', keyBuf, iv);
  const out = Buffer.concat([cipher.update(Buffer.from(toStr(plainText), 'utf8')), cipher.final()]);
  return Buffer.concat([iv, out]).toString('base64');
}

function aesCbcDecryptBase64(keyBuf, b64Text) {
  const raw = Buffer.from(normalizeBase64Input(b64Text), 'base64');
  if (raw.length < 17) throw new Error('ciphertext too short');
  const iv = raw.subarray(0, 16);
  const ct = raw.subarray(16);
  const decipher = crypto.createDecipheriv('aes-128-cbc', keyBuf, iv);
  const out = Buffer.concat([decipher.update(ct), decipher.final()]);
  return out.toString('utf8');
}

function md5HexLower(input) {
  return crypto.createHash('md5').update(Buffer.from(toStr(input), 'utf8')).digest('hex');
}

function calMcloudSign(plainJsonBody, ts, randStr) {
  // Compatible with OpenList-style sign behavior.
  const encoded = encodeURIComponent(toStr(plainJsonBody));
  const chars = encoded.split('');
  chars.sort();
  const sorted = chars.join('');
  const bodyB64 = Buffer.from(sorted, 'utf8').toString('base64');
  const res = md5HexLower(bodyB64) + md5HexLower(`${toStr(ts)}:${toStr(randStr)}`);
  return md5HexLower(res).toUpperCase();
}

function randomAlphaNum(len) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const n = Number.isFinite(Number(len)) ? Math.max(0, Number(len)) : 0;
  if (!n) return '';
  const bytes = crypto.randomBytes(n);
  let out = '';
  for (let i = 0; i < n; i += 1) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function formatChinaTimestamp() {
  const ms = Date.now();
  const d = new Date(ms + 8 * 60 * 60 * 1000);
  const pad = (v) => String(v).padStart(2, '0');
  const y = d.getUTCFullYear();
  const m = pad(d.getUTCMonth() + 1);
  const day = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const mm = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());
  return `${y}-${m}-${day} ${hh}:${mm}:${ss}`;
}

function stripBasicPrefix(value) {
  const s = toStr(value).trim();
  if (!s) return '';
  return s.replace(/^basic\s+/i, '').trim();
}

function decodeAccountFromAuthorization(authorization) {
  const tokenRaw = stripBasicPrefix(authorization);
  const token = normalizeBase64Input(tokenRaw);
  if (!tokenRaw) return '';

  const parseDecoded = (decodedStr) => {
    const decoded = toStr(decodedStr);
    const parts = decoded.split(':');
    return parts && parts.length >= 3 ? toStr(parts[1]).trim() : '';
  };

  // base64("xxx:<account>:<token...>")
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const account = parseDecoded(decoded);
    if (account) return account;
  } catch (_) {}

  // Some callers may persist decoded form directly.
  return parseDecoded(tokenRaw);
}

function getDbJsonPathCandidates() {
  const out = [];
  try {
    out.push(path.resolve(process.cwd(), 'db.json'));
  } catch (_) {}
  try {
    out.push(path.resolve(__dirname, '..', '..', 'db.json'));
  } catch (_) {}
  return out.filter(Boolean);
}

function readJsonFileSafe(filePath) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = raw && raw.trim() ? JSON.parse(raw) : null;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch (_) {
    return null;
  }
}

function getYidongAuthorizationFromDbFile() {
  for (const p of getDbJsonPathCandidates()) {
    const root = readJsonFileSafe(p);
    const v = root && root.yidong && typeof root.yidong === 'object' ? root.yidong.authorization : '';
    const s = toStr(v).trim();
    if (s) return s;
  }
  return '';
}

async function getYidongAuthorization(instance) {
  try {
    if (instance && instance.db && typeof instance.db.getData === 'function') {
      const v = instance.db.getData('/yidong/authorization');
      if (typeof v === 'string' && v.trim()) return v.trim();
    }
  } catch (_) {}
  return getYidongAuthorizationFromDbFile();
}

function buildMcloudHeaders({ authorization, bodyForSign }) {
  const ts = formatChinaTimestamp();
  const randStr = randomAlphaNum(16);
  const sign = calMcloudSign(toStr(bodyForSign), ts, randStr);

  return {
    Accept: 'application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    Authorization: `Basic ${stripBasicPrefix(authorization)}`,
    'Content-Type': 'application/json;charset=UTF-8',
    'Hcy-Cool-Flag': '1',
    'Mcloud-Sign': `${ts},${randStr},${sign}`,
    Origin: 'https://yun.139.com',
    Referer: 'https://yun.139.com/',
    'User-Agent': DEFAULT_UA,
    'X-Deviceinfo': DEFAULT_X_DEVICEINFO,
  };
}

async function fetchText(url, init) {
  try {
    const res = await fetch(url, { redirect: 'manual', ...init });
    const text = await res.text();
    return { status: res.status, ok: res.ok, headers: res.headers, text, url: res.url };
  } catch (e) {
    const err = e && typeof e === 'object' ? e : null;
    const cause = err && err.cause && typeof err.cause === 'object' ? err.cause : null;
    const details = [];
    if (err && err.name) details.push(err.name);
    if (err && err.message) details.push(err.message);
    if (cause && cause.code) details.push(`code=${cause.code}`);
    if (cause && cause.errno) details.push(`errno=${cause.errno}`);
    if (cause && cause.hostname) details.push(`host=${cause.hostname}`);
    const msg = details.length ? details.join(' | ') : 'fetch failed';
    throw new Error(msg);
  }
}

function safeJsonParseObject(text) {
  const s = toStr(text).trim();
  if (!s || !s.startsWith('{')) return null;
  try {
    const parsed = JSON.parse(s);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch (_) {
    return null;
  }
}

function unwrapMaybeJsonString(text) {
  const s = toStr(text).trim();
  if (!s) return '';
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    try {
      const v = JSON.parse(s);
      return typeof v === 'string' ? v : s;
    } catch (_) {
      return s;
    }
  }
  return s;
}

function looksLikeBase64(text) {
  const s = normalizeBase64Input(text);
  if (!s || s.length < 24) return false;
  if (s.includes('{') || s.includes('}') || s.includes(':')) return false;
  return /^[A-Za-z0-9+/=]+$/.test(s);
}

function decryptOutlinkResponse(rawText) {
  const raw = toStr(rawText).trim();
  const direct = safeJsonParseObject(raw);
  if (direct) return { rawText: raw, decrypted: '', parsed: direct };

  const unwrapped = unwrapMaybeJsonString(raw);
  const unwrappedJson = safeJsonParseObject(unwrapped);
  if (unwrappedJson) return { rawText: raw, decrypted: '', parsed: unwrappedJson };

  if (looksLikeBase64(unwrapped)) {
    try {
      const decrypted = aesCbcDecryptBase64(KEY_OUTLINK, unwrapped);
      const parsed = safeJsonParseObject(decrypted);
      return { rawText: raw, decrypted, parsed };
    } catch (_) {
      // ignore
    }
  }

  return { rawText: raw, decrypted: '', parsed: null };
}

function pickRedrUrl(parsed) {
  try {
    const o = parsed && typeof parsed === 'object' ? parsed : null;
    const v = o && o.data && o.data.redrUrl ? o.data.redrUrl : '';
    return typeof v === 'string' ? v.trim() : '';
  } catch (_) {
    return '';
  }
}

function parsePlayId(value) {
  const raw = toStr(value).trim();
  if (!raw) return { linkID: '', coID: '', contentId: '' };

  // Supported compact formats:
  // - linkID|contentId
  // - linkID|coID|contentId
  // - linkID|coID|contentId|name
  // - linkID:contentId
  // - contentId*linkID
  // - linkID*contentId
  if (raw.includes(':')) {
    const parts = raw.split(':').map((s) => toStr(s).trim()).filter(Boolean);
    if (parts.length >= 2) return { linkID: parts[0] || '', coID: '', contentId: parts[1] || '' };
  }
  if (raw.includes('|')) {
    const parts = raw.split('|').map((s) => toStr(s).trim());
    const linkID = parts[0] || '';
    const coID = parts.length >= 3 ? (parts[1] || '') : '';
    const contentId = parts[2] || parts[1] || '';
    return { linkID, coID, contentId };
  }
  if (raw.includes('*')) {
    const parts = raw.split('*').map((s) => toStr(s).trim()).filter(Boolean);
    if (parts.length >= 2) {
      const a = parts[0] || '';
      const b = parts[1] || '';
      const aIsDigits = /^[0-9]+$/.test(a);
      const bIsDigits = /^[0-9]+$/.test(b);
      if (aIsDigits && !bIsDigits) return { linkID: b, coID: '', contentId: a };
      if (!aIsDigits && bIsDigits) return { linkID: a, coID: '', contentId: b };
      return { linkID: a, coID: '', contentId: b };
    }
  }
  return { linkID: '', coID: '', contentId: '' };
}

function parseLinkIDFromFlag(flag) {
  const s = toStr(flag).trim();
  if (!s) return '';
  const m = /逸动-([A-Za-z0-9_]+)/.exec(s);
  return (m && m[1]) || '';
}

function normalizeRequestBody(rawBody) {
  if (rawBody == null) return {};
  if (typeof rawBody === 'object' && !Array.isArray(rawBody)) return rawBody;
  if (Buffer.isBuffer(rawBody) || rawBody instanceof Uint8Array) {
    return normalizeRequestBody(Buffer.from(rawBody).toString('utf8'));
  }
  if (typeof rawBody === 'string') {
    const s = rawBody.trim();
    if (!s) return {};
    try {
      const parsed = JSON.parse(s);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (_) {
      return {};
    }
  }
  return {};
}

async function outlinkDlFromOutLinkV3Signed({ linkID, contentId, coID, authorization }) {
  const auth = stripBasicPrefix(authorization);
  if (!auth) throw new Error('missing authorization');
  const account = decodeAccountFromAuthorization(auth);
  if (!account) throw new Error('authorization invalid (missing account)');

  const buildPayload = (useCoID) => {
    const co = toStr(coID || '').trim();
    if (useCoID && co) {
      return {
        dlFromOutLinkReqV3: { account, linkID: toStr(linkID), coIDLst: { item: [co] } },
        commonAccountInfo: { account, accountType: 1 },
      };
    }
    return {
      dlFromOutLinkReq: { contentId: toStr(contentId), linkID: toStr(linkID), account },
      commonAccountInfo: { account, accountType: 1 },
    };
  };

  const tryOnce = async (useCoID) => {
    const payload = buildPayload(useCoID);
    const plain = JSON.stringify(payload);
    const enc = aesCbcEncryptBase64(KEY_OUTLINK, plain);
    const body = JSON.stringify(enc);
    const headers = buildMcloudHeaders({ authorization: auth, bodyForSign: plain });
    const url = `${OUTLINK_API_BASE}dlFromOutLinkV3`;

    const resp = await fetchText(url, { method: 'POST', headers, body });
    const decoded = decryptOutlinkResponse(resp.text);
    const parsed = decoded.parsed;
    const urlOut = pickRedrUrl(parsed);
    return { resp, parsed, url: urlOut, rawText: decoded.rawText, decrypted: decoded.decrypted };
  };

  const first = await tryOnce(true);
  if (first.url) return first;
  const code = first.parsed && (first.parsed.code || first.parsed.resultCode);
  if (String(code) === '9530') return tryOnce(false);
  return first;
}

const apiPlugins = [
  {
    prefix: '/api/139',
    plugin: async function pan139Api(instance) {
      instance.post('/play', async (req, reply) => {
        const body = normalizeRequestBody(req && req.body);
        const flag = toStr(body.flag || '').trim();
        const id = toStr(body.id || '').trim();
        if (!id) {
          reply.code(400);
          return { ok: false, message: 'missing id' };
        }

        const parsed = parsePlayId(id);
        const linkID = toStr(parsed.linkID || parseLinkIDFromFlag(flag)).trim();
        const contentId = toStr(parsed.contentId).trim();
        const coID = toStr(parsed.coID).trim();

        if (!linkID) {
          reply.code(400);
          return { ok: false, message: 'missing linkID (from id/flag)' };
        }
        if (!contentId) {
          reply.code(400);
          return { ok: false, message: 'missing contentId (from id)' };
        }

        try {
          const authorization = await getYidongAuthorization(instance);
          const out = await outlinkDlFromOutLinkV3Signed({ linkID, contentId, coID, authorization });
          if (!out.url) {
            const code = out.parsed && (out.parsed.code || out.parsed.resultCode);
            const desc = out.parsed && (out.parsed.desc || out.parsed.message);
            reply.code(502);
            return {
              ok: false,
              message: desc ? `${toStr(code || 'error')}: ${toStr(desc)}` : toStr(code || 'failed'),
              raw: out.rawText || '',
            };
          }
          return { ok: true, parse: 0, url: out.url };
        } catch (e) {
          reply.code(502);
          return { ok: false, message: (e && e.message) || String(e) };
        }
      });
    },
  },
];

module.exports = { apiPlugins };
