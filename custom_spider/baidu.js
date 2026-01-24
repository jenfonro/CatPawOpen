// Baidu Netdisk API plugin.

import axios from 'axios';
import http from 'http';
import https from 'https';
import zlib from 'node:zlib';

const BAIDU_SCRIPT_WEB_UA =
  'Mozilla/5.0 (Linux; Android 12; V2238A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.40 Safari/537.36';
const BAIDU_SCRIPT_NETDISK_UA = 'netdisk;12.11.9;V2238A;android-android;12;JSbridge4.4.0;jointBridge;1.1.0;';
const BAIDU_PLAY_UA = 'com.android.chrome/131.0.6778.200 (Linux;Android 10) AndroidXMedia3/1.5.1';
const BAIDU_APP_ID = '250528';
const PAN_DEBUG = process.env.PAN_DEBUG === '1';

function panLog(...args) {
  if (!PAN_DEBUG) return;
  // eslint-disable-next-line no-console
  console.log('[pan]', ...args);
}

function maskForLog(value, head = 6, tail = 4) {
  const s = String(value == null ? '' : value);
  if (!s) return '';
  if (s.length <= head + tail + 3) return s;
  return `${s.slice(0, head)}...${s.slice(-tail)}`;
}

const baiduHttp = axios.create({
  httpAgent: new http.Agent({ keepAlive: true }),
  httpsAgent: new https.Agent({ keepAlive: true, rejectUnauthorized: false }),
  maxRedirects: 5,
  validateStatus: () => true,
  responseType: 'arraybuffer',
});

function looksLikeCookieString(v) {
  const s = String(v || '').trim();
  return !!(s && s.includes('='));
}

async function readDbRoot(server) {
  try {
    const db = server && server.db ? server.db : null;
    if (!db || typeof db.getData !== 'function') return {};
    const root = await db.getData('/');
    return root && typeof root === 'object' && !Array.isArray(root) ? root : {};
  } catch {
    return {};
  }
}

function getBaiduCookieFromDbRoot(root) {
  try {
    const b = root && typeof root === 'object' ? root.baidu : null;
    if (typeof b === 'string') return b.trim();
    if (!b || typeof b !== 'object' || Array.isArray(b)) return '';
    for (const v of Object.values(b)) {
      if (typeof v === 'string' && looksLikeCookieString(v)) return v.trim();
    }
  } catch {}
  return '';
}

function parseCookiePairs(cookieStr) {
  const out = {};
  const raw = String(cookieStr || '').trim();
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const s = String(part || '').trim();
    if (!s) continue;
    const idx = s.indexOf('=');
    if (idx <= 0) continue;
    const k = s.slice(0, idx).trim();
    const v = s.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = v;
  }
  return out;
}

function stringifyCookiePairs(obj) {
  if (!obj || typeof obj !== 'object') return '';
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = String(k || '').trim();
    if (!key) continue;
    parts.push(`${key}=${String(v == null ? '' : v).trim()}`);
  }
  return parts.join('; ');
}

function mergeCookies(baseCookie, extraCookie) {
  const a = parseCookiePairs(baseCookie);
  const b = parseCookiePairs(extraCookie);
  return stringifyCookiePairs({ ...a, ...b });
}

function buildBaiduScriptWebHeaders({ cookie }) {
  const headers = {
    Origin: 'https://pan.baidu.com',
    Referer: 'https://pan.baidu.com/',
    'User-Agent': BAIDU_SCRIPT_WEB_UA,
  };
  if (cookie) headers.Cookie = cookie;
  return headers;
}

function assertBaiduErrnoOk(data, okErrnos = []) {
  const n = data && typeof data === 'object' && 'errno' in data ? Number(data.errno) : 0;
  if (n === 0) return;
  if (okErrnos.includes(n)) return;
  const msg =
    (data && typeof data === 'object' && (data.show_msg || data.error_msg || data.errmsg || data.message || data.msg)) || '';
  throw new Error(`baidu errno=${Number.isFinite(n) ? n : String(data && data.errno)}${msg ? `: ${msg}` : ''}`);
}

function decodeMaybeCompressed(buf, encoding) {
  const enc = String(encoding || '').toLowerCase();
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf == null ? '' : buf);
  if (!b.length) return b;
  const isGzip = enc.includes('gzip') || (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b);
  const isBr = enc.includes('br');
  const isDeflate = enc.includes('deflate');
  try {
    if (isGzip) return zlib.gunzipSync(b);
  } catch {}
  try {
    if (isBr && typeof zlib.brotliDecompressSync === 'function') return zlib.brotliDecompressSync(b);
  } catch {}
  try {
    if (isDeflate) return zlib.inflateSync(b);
  } catch {}
  return b;
}

async function fetchText(url, init) {
  const method = String((init && init.method) || 'GET').toUpperCase();
  const headers = (init && init.headers && typeof init.headers === 'object' ? init.headers : {}) || {};
  const body = init && Object.prototype.hasOwnProperty.call(init, 'body') ? init.body : undefined;
  const res = await baiduHttp.request({
    url,
    method,
    headers,
    data: body,
  });
  const setCookie = Array.isArray(res.headers && res.headers['set-cookie'])
    ? res.headers['set-cookie'].map((x) => String(x || '')).filter(Boolean)
    : [];
  const raw = Buffer.isBuffer(res.data) ? res.data : Buffer.from(res.data == null ? '' : res.data);
  const enc = (res.headers && (res.headers['content-encoding'] || res.headers['Content-Encoding'])) || '';
  const buf = decodeMaybeCompressed(raw, enc);
  const text = buf.toString('utf8');
  return { res, text, setCookie };
}

async function fetchJson(url, init) {
  const { res, text, setCookie } = await fetchText(url, init);
  let data = null;
  try {
    data = text && text.trim() ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  const ok = res && typeof res.status === 'number' ? res.status >= 200 && res.status < 300 : false;
  if (!ok) {
    const msg = (data && (data.message || data.error_msg || data.msg)) || text || `status=${res.status}`;
    const err = new Error(`baidu http ${res.status}: ${String(msg).slice(0, 300)}`);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return { res, data, text, setCookie };
}

function normalizeBaiduErr(err) {
  const msg = (err && err.message) || String(err);
  const status = err && typeof err.status === 'number' ? err.status : 0;
  return { status, message: msg.slice(0, 400) };
}

function extractBdstoken(json) {
  if (!json || typeof json !== 'object') return '';
  const info = json.login_info && typeof json.login_info === 'object' ? json.login_info : null;
  return info && typeof info.bdstoken === 'string' ? info.bdstoken : '';
}

async function getBdstokenScript({ cookie, cookieRef }) {
  const qs = new URLSearchParams({
    clienttype: '1',
    web: '1',
    channel: 'web',
    version: '0',
  }).toString();
  const url = `https://pan.baidu.com/api/loginStatus?${qs}`;
  const { data, setCookie } = await fetchJson(url, {
    method: 'GET',
    headers: buildBaiduScriptWebHeaders({ cookie }),
  });
  try {
    if (cookieRef && setCookie && setCookie.length) cookieRef.value = mergeCookieFromSetCookie(cookieRef.value || cookie, setCookie);
  } catch {}
  const token = extractBdstoken(data);
  if (!token) throw new Error('bdstoken not found (loginStatus)');
  return token;
}

function toCreateApiPath(dirPath) {
  const p = String(dirPath || '').trim();
  if (!p) return '';
  // Match the script behavior: sending `path=//Name` for root dirs.
  if (p.startsWith('/')) return `/${p}`;
  return `//${p}`;
}

async function baiduCreateDirScript({ cookie, dirPath, bdstoken }) {
  const cookieRef = { value: String(cookie || '').trim() };
  const token = bdstoken || (await getBdstokenScript({ cookie: cookieRef.value, cookieRef }));
  const p = String(dirPath || '').trim();
  if (!p || !p.startsWith('/')) throw new Error('invalid dirPath');

  const qs = new URLSearchParams({
    a: 'commit',
    bdstoken: token,
    clienttype: '0',
    web: '1',
  }).toString();
  const url = `https://pan.baidu.com/api/create?${qs}`;
  const form = new URLSearchParams({
    path: toCreateApiPath(p),
    isdir: '1',
    block_list: '[]',
  }).toString();
  const { data, setCookie } = await fetchJson(url, {
    method: 'POST',
    headers: {
      ...buildBaiduScriptWebHeaders({ cookie: cookieRef.value }),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: form,
  });
  if (setCookie && setCookie.length) cookieRef.value = mergeCookieFromSetCookie(cookieRef.value, setCookie);
  assertBaiduErrnoOk(data, [31066, -8]);
  return { bdstoken: token, cookie: cookieRef.value, data };
}

async function baiduApiListRootScript({ cookie, cookieRef }) {
  const qs = new URLSearchParams({
    clienttype: '0',
    app_id: BAIDU_APP_ID,
    web: '1',
    order: 'time',
    desc: '1',
    num: '9999',
    page: '1',
  }).toString();
  const url = `https://pan.baidu.com/api/list?${qs}`;
  const { data, setCookie } = await fetchJson(url, {
    method: 'GET',
    headers: buildBaiduScriptWebHeaders({ cookie }),
  });
  try {
    if (cookieRef && setCookie && setCookie.length) cookieRef.value = mergeCookieFromSetCookie(cookieRef.value || cookie, setCookie);
  } catch {}
  return data;
}

function pickDirEntryFromApiList(data, dirPath) {
  const wantPath = String(dirPath || '').trim();
  if (!wantPath || !wantPath.startsWith('/')) return null;
  const wantName = wantPath.split('/').filter(Boolean).pop() || '';
  const list = data && typeof data === 'object' && Array.isArray(data.list) ? data.list : [];
  const dirs = list.filter((it) => it && typeof it === 'object' && Number(it.isdir) === 1);
  const exact =
    dirs.find((it) => String(it.path || '').trim() === wantPath) ||
    (wantName ? dirs.find((it) => String(it.server_filename || it.filename || it.name || '').trim() === wantName) : null);
  if (exact) return exact;
  return null;
}

async function baiduEnsureDir({ cookie, dirPath, bdstoken }) {
  const cookieRef = { value: String(cookie || '').trim() };
  const token = bdstoken || (await getBdstokenScript({ cookie: cookieRef.value, cookieRef }));
  const p = String(dirPath || '').trim();
  if (!p || !p.startsWith('/')) throw new Error('invalid dirPath');

  try {
    const listed = await baiduApiListRootScript({ cookie: cookieRef.value, cookieRef });
    const found = pickDirEntryFromApiList(listed, p);
    if (found) {
      return {
        bdstoken: token,
        cookie: cookieRef.value,
        data: {
          errno: 0,
          existed: true,
          path: String(found.path || p),
          fs_id: found.fs_id,
          isdir: 1,
          mtime: found.mtime,
          ctime: found.ctime,
          server_filename: found.server_filename,
        },
      };
    }
  } catch {}

  return await baiduCreateDirScript({ cookie: cookieRef.value, dirPath: p, bdstoken: token });
}

async function getBdstoken({ cookie, cookieRef }) {
  return await getBdstokenScript({ cookie, cookieRef });
}

function parseShareUrl(urlStr) {
  const raw = String(urlStr || '').trim();
  if (!raw) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  if (!(host === 'pan.baidu.com' || host.endsWith('.pan.baidu.com'))) return null;
  // Common formats:
  // - https://pan.baidu.com/s/1xxxx
  // - https://pan.baidu.com/s/xxxxxxxx (no leading 1)
  // - https://pan.baidu.com/share/init?surl=xxxx
  const m1 = u.pathname.match(/^\/s\/([^/?#]+)/);
  if (m1) {
    const shareKey = m1[1];
    const surl = shareKey && shareKey.startsWith('1') ? shareKey.slice(1) : shareKey;
    return { kind: 's', shareKey, surl, url: raw };
  }
  const surl = u.searchParams.get('surl');
  if (surl) return { kind: 'init', shareKey: '', surl, url: raw };
  return { kind: 'unknown', shareKey: '', surl: '', url: raw };
}

function mergeCookieFromSetCookie(baseCookie, setCookieArr) {
  const pairs = [];
  for (const sc of Array.isArray(setCookieArr) ? setCookieArr : []) {
    const s = String(sc || '').trim();
    if (!s) continue;
    const first = s.split(';')[0];
    if (first && first.includes('=')) pairs.push(first);
  }
  if (!pairs.length) return String(baseCookie || '').trim();
  return mergeCookies(baseCookie, pairs.join('; '));
}

function pickCookieValueFromSetCookie(setCookieArr, key) {
  const k = String(key || '').trim();
  if (!k) return '';
  for (const sc of Array.isArray(setCookieArr) ? setCookieArr : []) {
    const s = String(sc || '');
    const m = s.match(new RegExp(`(?:^|,|;\\s*)${k}=([^;]+)`));
    if (m) return m[1] || '';
  }
  return '';
}

function parseSurlFromFlag(flag) {
  const raw = String(flag || '').trim();
  if (!raw) return '';
  const m = raw.match(/百度[^-]*-([^#]+)/);
  if (m && m[1]) return String(m[1]).trim();
  const parts = raw.split('-');
  if (parts.length >= 2) return String(parts[1] || '').split('#')[0].trim();
  return '';
}

function decodePlayIdToJson(id) {
  let raw = String(id || '').trim();
  if (!raw) return null;
  const dollar = raw.lastIndexOf('$');
  if (dollar >= 0) raw = raw.slice(dollar + 1);
  raw = raw.split('|||')[0] || raw;
  raw = raw.trim();
  if (!raw) return null;
  try {
    raw = decodeURIComponent(raw);
  } catch {}
  try {
    const text = Buffer.from(raw, 'base64').toString('utf8');
    const obj = JSON.parse(text);
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : null;
  } catch {
    return null;
  }
}

function extractNameFromTvServerId(rawId) {
  const idStr = String(rawId || '');
  if (!idStr) return '';
  const delims = ['|||', '######', '@@@', '***', '___'];
  for (const d of delims) {
    const idx = idStr.indexOf(d);
    if (idx >= 0) return String(idStr.slice(idx + d.length) || '').trim();
  }
  return '';
}

async function resolveBaiduFinalUrlFromDlink(dlink) {
  const url = String(dlink || '').trim();
  if (!url) throw new Error('missing dlink');
  const res = await baiduHttp.request({
    url,
    method: 'GET',
    headers: { 'User-Agent': BAIDU_PLAY_UA, Range: 'bytes=0-0' },
    maxRedirects: 5,
  });
  const status = res && typeof res.status === 'number' ? res.status : 0;
  if (!(status >= 200 && status < 400)) throw new Error(`baidu dlink resolve http ${status || 0}`);
  const finalUrl =
    (res && res.request && res.request.res && res.request.res.responseUrl) ||
    (res && res.request && res.request._redirectable && res.request._redirectable._currentUrl) ||
    url;
  return String(finalUrl || url);
}

async function verifySharePwd({ surl, pwd, cookieRef }) {
  const p = String(pwd || '').trim();
  if (!surl) throw new Error('missing surl');
  if (!p) throw new Error('missing pwd');
  const t = String(Date.now());
  const params = new URLSearchParams({
    t,
    surl: String(surl),
  }).toString();
  const url = `https://pan.baidu.com/share/verify?${params}`;
  const body = new URLSearchParams({ pwd: p }).toString();
  const baseCookie = cookieRef && typeof cookieRef.value === 'string' ? cookieRef.value : '';
  const { data, setCookie } = await fetchJson(url, {
    method: 'POST',
    headers: {
      ...buildBaiduScriptWebHeaders({ cookie: baseCookie }),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  const bdclnd = pickCookieValueFromSetCookie(setCookie || [], 'BDCLND');
  let merged = baseCookie;
  try {
    if (setCookie && setCookie.length) merged = mergeCookieFromSetCookie(baseCookie, setCookie);
  } catch {}
  try {
    if (cookieRef) cookieRef.value = merged;
  } catch {}
  return { data, bdclnd, cookie: merged };
}

async function shareListRootScript({ baseCookie, surl, pwd }) {
  const shorturl = String(surl || '').trim();
  if (!shorturl) throw new Error('missing surl');
  const cookieRef = { value: String(baseCookie || '').trim() };
  if (!cookieRef.value) throw new Error('missing baidu cookie');
  const pass = String(pwd || '').trim();
  if (pass) await verifySharePwd({ surl: shorturl, pwd: pass, cookieRef });
  const qs = new URLSearchParams({
    desc: '1',
    showempty: '0',
    page: '1',
    num: '10000',
    order: 'time',
    shorturl,
    root: '1',
  }).toString();
  const url = `https://pan.baidu.com/share/list?${qs}`;
  const { data, setCookie } = await fetchJson(url, {
    method: 'GET',
    headers: {
      ...buildBaiduScriptWebHeaders({ cookie: cookieRef.value }),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  if (setCookie && setCookie.length) cookieRef.value = mergeCookieFromSetCookie(cookieRef.value, setCookie);
  assertBaiduErrnoOk(data);
  const shareid =
    String((data && (data.shareid || data.share_id)) || '').trim() ||
    String((data && data.data && (data.data.shareid || data.data.share_id)) || '').trim();
  const uk =
    String((data && (data.uk || data.share_uk)) || '').trim() ||
    String((data && data.data && (data.data.uk || data.data.share_uk)) || '').trim();
  return { cookie: cookieRef.value, data, ctx: { surl: shorturl, shareid, uk } };
}

async function shareListDirScript({ cookie, shareid, uk, dir }) {
  const d = String(dir || '').trim();
  if (!d || !d.startsWith('/')) throw new Error('invalid dir');
  const qs = new URLSearchParams({
    uk: String(uk || '').trim(),
    shareid: String(shareid || '').trim(),
    order: 'other',
    desc: '1',
    showempty: '0',
    page: '1',
    num: '10000',
    dir: d,
    t: String(Date.now() * 1000),
  }).toString();
  const url = `https://pan.baidu.com/share/list?${qs}`;
  const { data } = await fetchJson(url, {
    method: 'GET',
    headers: {
      ...buildBaiduScriptWebHeaders({ cookie }),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  assertBaiduErrnoOk(data);
  return data;
}

function getShareListArray(data) {
  if (!data || typeof data !== 'object') return [];
  if (Array.isArray(data.list)) return data.list;
  if (data.data && typeof data.data === 'object' && Array.isArray(data.data.list)) return data.data.list;
  return [];
}

function findShareItemByName(list, name, isDir) {
  const want = String(name || '').trim();
  if (!want) return null;
  const arr = Array.isArray(list) ? list : [];
  return (
    arr.find((it) => {
      if (!it || typeof it !== 'object') return false;
      const n = String(it.server_filename || it.filename || it.name || '').trim();
      if (n !== want) return false;
      const d = Number(it.isdir) === 1;
      return isDir ? d : !d;
    }) || null
  );
}

async function shareResolveFsidByPathScript({ baseCookie, surl, pwd, path }) {
  const full = String(path || '').trim();
  if (!full || !full.startsWith('/')) throw new Error('invalid path');
  const segs = full.split('/').filter(Boolean);
  if (!segs.length) throw new Error('invalid path');
  const fileName = segs[segs.length - 1];
  const dirSegs = segs.slice(0, -1);

  const root = await shareListRootScript({ baseCookie, surl, pwd });
  const { shareid, uk } = root.ctx || {};
  if (!shareid || !uk) throw new Error('share context missing (uk/shareid)');

  let curDir = '';
  for (const seg of dirSegs) {
    curDir = `${curDir}/${seg}`;
    const data = await shareListDirScript({ cookie: root.cookie, shareid, uk, dir: curDir });
    const list = getShareListArray(data);
    const found = findShareItemByName(list, seg, true);
    if (!found) throw new Error(`dir not found: ${curDir}`);
  }
  const finalDir = dirSegs.length ? `/${dirSegs.join('/')}` : '';
  const data = finalDir
    ? await shareListDirScript({ cookie: root.cookie, shareid, uk, dir: finalDir })
    : root.data;
  const list = getShareListArray(data);
  const file = findShareItemByName(list, fileName, false);
  if (!file) throw new Error(`file not found: ${fileName}`);
  const fsid = file.fs_id != null ? String(file.fs_id) : String(file.fsid || '');
  if (!fsid) throw new Error('fsid not found');
  return { cookie: root.cookie, uk, shareid, fsid, fileName, dir: finalDir || '/' };
}

async function shareTransferToDirScript({ baseCookie, shareid, uk, surl, pwd, fsid, destPath }) {
  const shareId = String(shareid || '').trim();
  const fromUk = String(uk || '').trim();
  const s = String(surl || '').trim();
  const pass = String(pwd || '').trim();
  const dest = String(destPath || '').trim();
  const f = String(fsid || '').trim();
  if (!shareId || !fromUk || !s || !dest || !dest.startsWith('/') || !f) throw new Error('missing share transfer parameters');

  const cookieRef = { value: String(baseCookie || '').trim() };
  if (!cookieRef.value) throw new Error('missing baidu cookie');
  if (pass) {
    const v = await verifySharePwd({ surl: s, pwd: pass, cookieRef });
    if (v && v.cookie) cookieRef.value = v.cookie;
  }

  const params = new URLSearchParams({
    shareid: shareId,
    from: fromUk,
    ondup: 'newcopy',
  }).toString();
  const url = `https://pan.baidu.com/share/transfer?${params}`;

  const form = new URLSearchParams({
    fsidlist: JSON.stringify([Number.isFinite(Number(f)) ? Number(f) : f]),
    path: dest,
  }).toString();
  const { data, setCookie } = await fetchJson(url, {
    method: 'POST',
    headers: {
      ...buildBaiduScriptWebHeaders({ cookie: cookieRef.value }),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: form,
  });
  if (setCookie && setCookie.length) cookieRef.value = mergeCookieFromSetCookie(cookieRef.value, setCookie);
  assertBaiduErrnoOk(data);
  return { bdstoken: '', cookie: cookieRef.value, data };
}

async function baiduMediaInfoScript({ cookie, path }) {
  const p = String(path || '').trim();
  if (!p || !p.startsWith('/')) throw new Error('invalid path');
  const qs = new URLSearchParams({
    type: 'M3U8_FLV_264_480',
    path: p,
    origin: 'dlna',
    check_blue: '1',
    app_id: BAIDU_APP_ID,
    devuid: 'kx1cK7VGweDrdrLiQpQRZduW5KTFvBHU|YyLyiRidC',
    clienttype: '80',
    channel: 'android_12_V2238A_bd-netdisk_1024266g',
    network_type: 'wifi',
    version: '12.11.9',
  }).toString();
  const url = `https://pan.baidu.com/api/mediainfo?${qs}`;
  const { data } = await fetchJson(url, {
    method: 'GET',
    headers: {
      Origin: 'https://pan.baidu.com',
      Referer: 'https://pan.baidu.com/',
      'User-Agent': BAIDU_SCRIPT_NETDISK_UA,
      ...(cookie ? { Cookie: cookie } : {}),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  assertBaiduErrnoOk(data);
  return data;
}

export const apiPlugins = [
  {
    prefix: '/api/baidu',
    plugin: async function baiduApi(instance) {
      instance.get('/status', async (req) => {
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        return { ok: true, hasCookie: !!cookie, features: { transferSupportsFlagId: true } };
      });

      instance.get('/auth/bdstoken', async (req, reply) => {
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const bdstoken = await getBdstoken({ cookie });
          return { ok: true, bdstoken };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/file/ensure_dir', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const name = String(body.name || '').trim();
        if (!name) {
          reply.code(400);
          return { ok: false, message: 'missing name' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        const dirPath = `/${name}`;
        try {
          const out = await baiduEnsureDir({ cookie, dirPath });
          return { ok: true, dirPath, ...out };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/play', async (req, reply) => {
        const reqId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
        const tStart = Date.now();
        let stage = 'recv';
        const body = req && typeof req.body === 'object' ? req.body : {};
        const flag = String(body.flag || '').trim();
        const id = String(body.id || '').trim();
        const destName = String(body.destName || '').trim().replace(/^\/+|\/+$/g, '');
        const destPathRaw = String(body.destPath || '').trim();

        if (!flag || !id) {
          reply.code(400);
          return { ok: false, message: 'missing flag/id' };
        }

        const dirPath = destPathRaw
          ? destPathRaw.startsWith('/') ? destPathRaw : `/${destPathRaw}`
          : destName ? `/${destName}` : '/TV_Server';
        if (!dirPath || !dirPath.startsWith('/')) {
          reply.code(400);
          return { ok: false, message: 'missing destPath/destName' };
        }

        const root = await readDbRoot(req.server);
        const baseCookie = getBaiduCookieFromDbRoot(root);
        if (!baseCookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }

        try {
          panLog(`baidu play recv id=${reqId}`, {
            dirPath,
            flag: flag.length > 80 ? `${flag.slice(0, 80)}...(${flag.length})` : flag,
            idLen: id.length,
            tvUser: String((req && req.headers && (req.headers['x-tv-user'] || req.headers['X-TV-User'])) || ''),
          });

          stage = 'decode';
          const tDecodeStart = Date.now();
          const decoded = decodePlayIdToJson(id);
          if (!decoded) {
            reply.code(400);
            return { ok: false, message: 'invalid id' };
          }
          const shareid = String(decoded.shareid || decoded.share_id || decoded.shareId || '').trim();
          const uk = String(decoded.uk || decoded.share_uk || decoded.uk_str || '').trim();
          const fsid = String(decoded.fs_id || decoded.fsid || decoded.fsId || '').trim();
          const surl = parseSurlFromFlag(flag) || String(decoded.surl || '').trim();
          const pwd = String(decoded.pwd || decoded.pass || '').trim();
          const nameHint = extractNameFromTvServerId(id);
          const fileName = String(decoded.realName || decoded.server_filename || decoded.serverFilename || nameHint || '').trim();
          panLog(`baidu play decode done id=${reqId}`, {
            ms: Date.now() - tDecodeStart,
            surl: maskForLog(surl, 4, 4),
            shareid: maskForLog(shareid),
            uk: maskForLog(uk),
            fsid: maskForLog(fsid),
            hasPwd: !!pwd,
            fileName: fileName || undefined,
          });

          if (!shareid || !uk || !fsid) {
            reply.code(400);
            return { ok: false, message: 'missing shareid/uk/fsid' };
          }
          if (!fileName) {
            reply.code(400);
            return { ok: false, message: 'missing filename' };
          }

          stage = 'ensure_dir';
          const tEnsureStart = Date.now();
          const ensured = await baiduEnsureDir({ cookie: baseCookie, dirPath });
          const ensuredPathRaw =
            ensured && ensured.data && typeof ensured.data === 'object'
              ? (ensured.data.path || ensured.data.name)
              : '';
          const ensuredPath =
            typeof ensuredPathRaw === 'string' && ensuredPathRaw.trim().startsWith('/') ? ensuredPathRaw.trim() : dirPath;
          panLog(`baidu play ensure_dir done id=${reqId}`, {
            ms: Date.now() - tEnsureStart,
            existed: !!(ensured && ensured.data && ensured.data.existed),
            path: ensuredPath,
          });

          stage = 'transfer';
          const tTransferStart = Date.now();
          const transfer = await shareTransferToDirScript({
            baseCookie: ensured.cookie || baseCookie,
            shareid,
            uk,
            surl,
            pwd,
            fsid,
            destPath: ensuredPath,
          });
          panLog(`baidu play transfer done id=${reqId}`, { ms: Date.now() - tTransferStart });

          const safeName = fileName.replace(/^\/+/, '');
          const fullPath = `${ensuredPath.replace(/\/+$/g, '')}/${safeName}`.replace(/\/{2,}/g, '/');
          stage = 'mediainfo';
          const tMediaStart = Date.now();
          const media = await baiduMediaInfoScript({ cookie: transfer.cookie || ensured.cookie || baseCookie, path: fullPath });
          const dlink =
            media &&
            typeof media === 'object' &&
            media.info &&
            typeof media.info === 'object' &&
            typeof media.info.dlink === 'string'
              ? media.info.dlink
              : '';
          if (!dlink) throw new Error('mediainfo missing dlink');
          panLog(`baidu play mediainfo done id=${reqId}`, {
            ms: Date.now() - tMediaStart,
            path: fullPath,
            dlinkHost: (() => {
              try {
                return new URL(dlink).host;
              } catch (_e) {
                return '';
              }
            })(),
          });

          stage = 'resolve_final';
          const tResolveStart = Date.now();
          const finalUrl = await resolveBaiduFinalUrlFromDlink(dlink);
          panLog(`baidu play resolve_final done id=${reqId}`, {
            ms: Date.now() - tResolveStart,
            finalHost: (() => {
              try {
                return new URL(finalUrl).host;
              } catch (_e) {
                return '';
              }
            })(),
          });
          panLog(`baidu play done id=${reqId}`, { ms: Date.now() - tStart });
          return { ok: true, parse: 0, url: finalUrl, header: { 'User-Agent': BAIDU_PLAY_UA } };
        } catch (e) {
          const message = (e && e.message) || String(e);
          panLog(`baidu play failed id=${reqId}`, { stage, ms: Date.now() - tStart, message: message.slice(0, 400) });
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/verify', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
        const pwd = String(body.pwd || body.pass || '').trim();
        if (!url) {
          reply.code(400);
          return { ok: false, message: 'missing url' };
        }
        if (!pwd) {
          reply.code(400);
          return { ok: false, message: 'missing pwd' };
        }
        try {
          const parsed = parseShareUrl(url);
          if (!parsed || !parsed.surl) {
            reply.code(400);
            return { ok: false, message: 'invalid baidu share url' };
          }
          const root = await readDbRoot(req.server);
          const baseCookie = getBaiduCookieFromDbRoot(root);
          if (!baseCookie) {
            reply.code(400);
            return { ok: false, message: 'missing baidu cookie' };
          }
          const cookieRef = { value: baseCookie };
          const out = await verifySharePwd({ surl: parsed.surl, pwd, cookieRef });
          return { ok: true, surl: parsed.surl, bdclnd: out.bdclnd };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/list', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
        const dir = String(body.dir || '').trim();
        if (!url) {
          reply.code(400);
          return { ok: false, message: 'missing url' };
        }
        try {
          const parsed = parseShareUrl(url);
          if (!parsed || !parsed.surl) {
            reply.code(400);
            return { ok: false, message: 'invalid baidu share url' };
          }
          const root = await readDbRoot(req.server);
          const baseCookie = getBaiduCookieFromDbRoot(root);
          if (!baseCookie) {
            reply.code(400);
            return { ok: false, message: 'missing baidu cookie' };
          }
          const pwd = body.pwd || body.pass;
          const rootList = await shareListRootScript({ baseCookie, surl: parsed.surl, pwd });
          const { shareid, uk } = rootList.ctx || {};
          const data = dir
            ? await shareListDirScript({ cookie: rootList.cookie, shareid, uk, dir })
            : rootList.data;
          return { ok: true, ctx: { surl: parsed.surl, shareid, uk }, data };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/resolve', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
        const filePath = String(body.path || '').trim();
        if (!url || !filePath) {
          reply.code(400);
          return { ok: false, message: 'missing url/path' };
        }
        const parsed = parseShareUrl(url);
        if (!parsed || !parsed.surl) {
          reply.code(400);
          return { ok: false, message: 'invalid baidu share url' };
        }
        const root = await readDbRoot(req.server);
        const baseCookie = getBaiduCookieFromDbRoot(root);
        if (!baseCookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const out = await shareResolveFsidByPathScript({
            baseCookie,
            surl: parsed.surl,
            pwd: body.pwd || body.pass,
            path: filePath,
          });
          return { ok: true, surl: parsed.surl, ...out };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/transfer', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const flag = String(body.flag || '').trim();
        const id = String(body.id || '').trim();
        const decoded = id ? decodePlayIdToJson(id) : null;

        const surl =
          String(body.surl || '').trim() ||
          parseSurlFromFlag(flag) ||
          String((decoded && decoded.surl) || '').trim();
        const shareid =
          String(body.shareid || body.shareId || '').trim() ||
          String((decoded && (decoded.shareid ?? decoded.share_id)) || '').trim();
        const uk =
          String(body.uk || body.from || '').trim() ||
          String((decoded && decoded.uk) || '').trim();
        const fsid =
          String(body.fsid || body.fs_id || '').trim() ||
          String((decoded && (decoded.fs_id ?? decoded.fsid)) || '').trim();
        const destPath = String(body.destPath || body.path || '').trim();
        if (!surl || !shareid || !uk || !fsid || !destPath) {
          reply.code(400);
          return {
            ok: false,
            message: 'missing parameters',
            parsed: {
              surl: surl || '',
              shareid: shareid || '',
              uk: uk || '',
              fsid: fsid || '',
              destPath: destPath || '',
              decodedKeys: decoded && typeof decoded === 'object' ? Object.keys(decoded).slice(0, 30) : [],
            },
          };
        }
        const root = await readDbRoot(req.server);
        const baseCookie = getBaiduCookieFromDbRoot(root);
        if (!baseCookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const out = await shareTransferToDirScript({
            baseCookie,
            shareid,
            uk,
            surl,
            pwd: body.pwd || body.pass || (decoded && decoded.pwd),
            fsid,
            destPath,
          });
          return { ok: true, ...out };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/file/mediainfo', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const filePath = String(body.path || '').trim();
        if (!filePath || !filePath.startsWith('/')) {
          reply.code(400);
          return { ok: false, message: 'missing path' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const data = await baiduMediaInfoScript({ cookie, path: filePath });
          return { ok: true, data };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });
    },
  },
];
