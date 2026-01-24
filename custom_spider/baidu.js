// Baidu Netdisk API plugin.

const BAIDU_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

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

function buildBaiduHeaders({ cookie, referer }) {
  const headers = {
    Accept: 'application/json, text/plain, */*',
    'X-Requested-With': 'XMLHttpRequest',
    Origin: 'https://pan.baidu.com',
    Referer: referer || 'https://pan.baidu.com/disk/main',
    'User-Agent': BAIDU_UA,
  };
  if (cookie) headers.Cookie = cookie;
  return headers;
}

async function fetchText(url, init) {
  const res = await fetch(url, { redirect: 'manual', ...init });
  const text = await res.text();
  return { res, text };
}

async function fetchJson(url, init) {
  const { res, text } = await fetchText(url, init);
  let data = null;
  try {
    data = text && text.trim() ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const msg = (data && (data.message || data.error_msg || data.msg)) || text || `status=${res.status}`;
    const err = new Error(`baidu http ${res.status}: ${String(msg).slice(0, 300)}`);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return { res, data, text };
}

function normalizeBaiduErr(err) {
  const msg = (err && err.message) || String(err);
  const status = err && typeof err.status === 'number' ? err.status : 0;
  return { status, message: msg.slice(0, 400) };
}

function extractBdstoken(json) {
  if (!json || typeof json !== 'object') return '';
  const direct = typeof json.bdstoken === 'string' ? json.bdstoken : '';
  if (direct) return direct;
  const d = json.data && typeof json.data === 'object' ? json.data : null;
  return d && typeof d.bdstoken === 'string' ? d.bdstoken : '';
}

async function baiduEnsureDir({ cookie, dirPath, bdstoken }) {
  const token = bdstoken || (await getBdstoken({ cookie }));
  const p = String(dirPath || '').trim();
  if (!p || !p.startsWith('/')) throw new Error('invalid dirPath');
  const params = new URLSearchParams({
    a: 'commit',
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
    bdstoken: token,
  }).toString();
  const url = `https://pan.baidu.com/api/create?${params}`;
  const form = new URLSearchParams({
    path: p,
    isdir: '1',
    size: '0',
    block_list: '[]',
    rtype: '1',
  }).toString();
  const { data } = await fetchJson(url, {
    method: 'POST',
    headers: {
      ...buildBaiduHeaders({ cookie, referer: 'https://pan.baidu.com/disk/main' }),
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    },
    body: form,
  });
  // errno=0 ok; errno=31066 already exists (commonly)
  return { bdstoken: token, data };
}

async function baiduDeletePaths({ cookie, paths, bdstoken }) {
  const token = bdstoken || (await getBdstoken({ cookie }));
  const list = Array.isArray(paths) ? paths.map((x) => String(x || '').trim()).filter((x) => x.startsWith('/')) : [];
  if (!list.length) return { bdstoken: token, deleted: 0, data: null };

  const params = new URLSearchParams({
    opera: 'delete',
    async: '1',
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
    bdstoken: token,
  }).toString();
  const url = `https://pan.baidu.com/api/filemanager?${params}`;
  const body = new URLSearchParams({ filelist: JSON.stringify(list) }).toString();
  const { data } = await fetchJson(url, {
    method: 'POST',
    headers: {
      ...buildBaiduHeaders({ cookie, referer: 'https://pan.baidu.com/disk/main' }),
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    },
    body,
  });
  return { bdstoken: token, deleted: list.length, data };
}

async function baiduClearDir({ cookie, dirPath, bdstoken }) {
  const token = bdstoken || (await getBdstoken({ cookie }));
  const p = String(dirPath || '').trim();
  if (!p || !p.startsWith('/')) throw new Error('invalid dirPath');
  const listed = await listMyDir({ cookie, dir: p, start: 0, limit: 200, order: 'time', desc: true, bdstoken: token });
  const arr = listed && listed.data && Array.isArray(listed.data.list) ? listed.data.list : [];
  const paths = [];
  for (const it of arr) {
    if (!it || typeof it !== 'object') continue;
    const path = String(it.path || '').trim();
    if (path && path !== p) paths.push(path);
  }
  if (!paths.length) return { bdstoken: token, cleared: 0 };
  const del = await baiduDeletePaths({ cookie, paths, bdstoken: token });
  return { bdstoken: token, cleared: paths.length, delete: del };
}

async function getBdstoken({ cookie }) {
  const qs = new URLSearchParams({
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
    version: '0',
  }).toString();
  const url = `https://pan.baidu.com/api/loginStatus?${qs}`;
  const { data } = await fetchJson(url, {
    method: 'GET',
    headers: buildBaiduHeaders({ cookie, referer: 'https://pan.baidu.com/disk/main' }),
  });
  const token = extractBdstoken(data);
  if (!token) throw new Error('bdstoken not found (loginStatus)');
  return token;
}

async function listMyDir({ cookie, dir, start, limit, order, desc, bdstoken }) {
  const token = bdstoken || (await getBdstoken({ cookie }));
  const params = new URLSearchParams({
    method: 'list',
    dir: String(dir || '/'),
    order: String(order || 'time'),
    desc: String(desc == null ? '1' : desc ? '1' : '0'),
    start: String(Number.isFinite(Number(start)) ? Number(start) : 0),
    limit: String(Number.isFinite(Number(limit)) ? Number(limit) : 100),
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
    bdstoken: token,
  }).toString();
  const url = `https://pan.baidu.com/rest/2.0/xpan/file?${params}`;
  const { data } = await fetchJson(url, {
    method: 'GET',
    headers: buildBaiduHeaders({ cookie, referer: 'https://pan.baidu.com/disk/main' }),
  });
  return { bdstoken: token, data };
}

async function fileMetas({ cookie, fsids, bdstoken, dlink }) {
  const token = bdstoken || (await getBdstoken({ cookie }));
  const ids = Array.isArray(fsids) ? fsids : typeof fsids === 'string' ? [fsids] : [];
  const cleaned = ids
    .map((x) => String(x || '').trim())
    .filter(Boolean)
    .map((x) => (x.startsWith('[') ? x : x));
  if (!cleaned.length) throw new Error('missing fsids');
  const fsidArr = cleaned.map((x) => (x.startsWith('[') ? x : Number.isFinite(Number(x)) ? Number(x) : x));
  const params = new URLSearchParams({
    method: 'filemetas',
    fsids: JSON.stringify(fsidArr),
    dlink: dlink ? '1' : '0',
    extra: '1',
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
    bdstoken: token,
  }).toString();
  const url = `https://pan.baidu.com/rest/2.0/xpan/multimedia?${params}`;
  const { data } = await fetchJson(url, {
    method: 'GET',
    headers: buildBaiduHeaders({ cookie, referer: 'https://pan.baidu.com/disk/main' }),
  });
  return { bdstoken: token, data };
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

function extractSetCookiePairs(headers) {
  const out = [];
  try {
    const any = headers && typeof headers.get === 'function' ? headers.get('set-cookie') : null;
    if (any) out.push(String(any));
  } catch {}
  return out;
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

function extractYunData(html) {
  const raw = String(html || '');
  const idx = raw.indexOf('yunData.setData(');
  if (idx < 0) return null;
  const start = raw.indexOf('{', idx);
  if (start < 0) return null;
  let depth = 0;
  let inStr = false;
  let strCh = '';
  let esc = false;
  for (let i = start; i < raw.length; i += 1) {
    const ch = raw[i];
    if (inStr) {
      if (esc) {
        esc = false;
      } else if (ch === '\\\\') {
        esc = true;
      } else if (ch === strCh) {
        inStr = false;
        strCh = '';
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = true;
      strCh = ch;
      continue;
    }
    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        const jsonLike = raw.slice(start, i + 1);
        try {
          return JSON.parse(jsonLike);
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

async function fetchSharePage({ url }) {
  const parsed = parseShareUrl(url);
  if (!parsed) throw new Error('invalid baidu share url');
  const key = parsed.shareKey || (parsed.surl ? `1${parsed.surl}` : '');
  const ref = `https://pan.baidu.com/s/${encodeURIComponent(key)}`;
  const { res, text } = await fetchText(ref, {
    method: 'GET',
    headers: buildBaiduHeaders({ cookie: '', referer: ref }),
  });
  return { res, html: text, surl: parsed.surl || '', shareKey: key };
}

async function verifySharePwd({ surl, pwd }) {
  const p = String(pwd || '').trim();
  if (!surl) throw new Error('missing surl');
  if (!p) throw new Error('missing pwd');
  const params = new URLSearchParams({
    surl: String(surl),
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
  }).toString();
  const url = `https://pan.baidu.com/share/verify?${params}`;
  const body = new URLSearchParams({ pwd: p }).toString();
  const { res, data } = await fetchJson(url, {
    method: 'POST',
    headers: {
      ...buildBaiduHeaders({ cookie: '', referer: `https://pan.baidu.com/s/1${encodeURIComponent(surl)}` }),
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    },
    body,
  });
  const setCookies = extractSetCookiePairs(res.headers);
  const bdclnd = pickCookieValueFromSetCookie(setCookies, 'BDCLND');
  return { data, bdclnd };
}

async function listShareDir({ surl, pwd, dir, page, num }) {
  // 1) Fetch share page to get uk/shareid/sign/timestamp (when present)
  const shareKey = surl ? `1${surl}` : '';
  const { html } = await fetchSharePage({ url: `https://pan.baidu.com/s/${encodeURIComponent(shareKey)}` });
  const yun = extractYunData(html) || {};
  const uk = String(yun.uk || yun.share_uk || '').trim();
  const shareid = String(yun.shareid || yun.share_id || '').trim();
  const sign = String(yun.sign || '').trim();
  const timestamp = String(yun.timestamp || yun.sign_timestamp || '').trim();

  // 2) Verify password if provided to obtain BDCLND cookie (needed for encrypted shares)
  let extraCookie = '';
  if (pwd) {
    const { bdclnd } = await verifySharePwd({ surl, pwd });
    if (bdclnd) extraCookie = `BDCLND=${bdclnd}`;
  }

  const cookie = extraCookie;
  const params = new URLSearchParams({
    uk,
    shareid,
    dir: String(dir || ''),
    page: String(Number.isFinite(Number(page)) ? Number(page) : 1),
    num: String(Number.isFinite(Number(num)) ? Number(num) : 100),
    order: 'other',
    desc: '1',
    showempty: '0',
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
  });
  if (sign) params.set('sign', sign);
  if (timestamp) params.set('timestamp', timestamp);

  const url = `https://pan.baidu.com/share/list?${params.toString()}`;
  const { data } = await fetchJson(url, {
    method: 'GET',
    headers: buildBaiduHeaders({ cookie, referer: `https://pan.baidu.com/s/${encodeURIComponent(shareKey)}` }),
  });

  return { data, ctx: { surl, uk, shareid, sign, timestamp, cookie: cookie || '' } };
}

async function shareDlink({ url, pwd, fsids, baseCookie }) {
  const parsed = parseShareUrl(url);
  if (!parsed || !parsed.surl) throw new Error('invalid baidu share url');
  const surl = parsed.surl;

  const { html } = await fetchSharePage({ url });
  const yun = extractYunData(html) || {};
  const uk = String(yun.uk || yun.share_uk || '').trim();
  const shareid = String(yun.shareid || yun.share_id || '').trim();
  const sign = String(yun.sign || '').trim();
  const timestamp = String(yun.timestamp || yun.sign_timestamp || '').trim();
  if (!uk || !shareid || !sign || !timestamp) throw new Error('share context missing (uk/shareid/sign/timestamp)');

  let shareCookie = '';
  if (pwd) {
    const { bdclnd } = await verifySharePwd({ surl, pwd });
    if (bdclnd) shareCookie = `BDCLND=${bdclnd}`;
  }

  const cookie = mergeCookies(baseCookie, shareCookie);
  const bdstoken = await getBdstoken({ cookie });

  const ids = Array.isArray(fsids) ? fsids : typeof fsids === 'string' ? [fsids] : [];
  const cleaned = ids.map((x) => String(x || '').trim()).filter(Boolean);
  if (!cleaned.length) throw new Error('missing fsids');

  const qs = new URLSearchParams({
    sign,
    timestamp,
    bdstoken,
    channel: 'chunlei',
    web: '1',
    clienttype: '0',
  }).toString();
  const apiUrl = `https://pan.baidu.com/api/sharedownload?${qs}`;
  const form = new URLSearchParams({
    encrypt: '0',
    product: 'share',
    uk,
    primaryid: shareid,
    fid_list: JSON.stringify(cleaned.map((x) => (Number.isFinite(Number(x)) ? Number(x) : x))),
  }).toString();

  const { data } = await fetchJson(apiUrl, {
    method: 'POST',
    headers: {
      ...buildBaiduHeaders({ cookie, referer: `https://pan.baidu.com/s/${encodeURIComponent(parsed.shareKey || `1${surl}`)}` }),
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    },
    body: form,
  });

  return {
    surl,
    uk,
    shareid,
    sign,
    timestamp,
    bdstoken,
    cookie,
    data,
  };
}

async function shareTransferToDir({ baseCookie, shareid, uk, surl, pwd, fs_id, destPath }) {
  const shareId = String(shareid || '').trim();
  const fromUk = String(uk || '').trim();
  const s = String(surl || '').trim();
  const pass = String(pwd || '').trim();
  const dest = String(destPath || '').trim();
  const fsid = String(fs_id || '').trim();
  if (!shareId || !fromUk || !s || !dest || !dest.startsWith('/') || !fsid) throw new Error('missing share transfer parameters');

  let extraCookie = '';
  let sekey = '';
  if (pass) {
    const { bdclnd } = await verifySharePwd({ surl: s, pwd: pass });
    if (bdclnd) {
      extraCookie = `BDCLND=${bdclnd}`;
      sekey = bdclnd;
    }
  }

  const cookie = mergeCookies(baseCookie, extraCookie);
  const bdstoken = await getBdstoken({ cookie });

  const params = new URLSearchParams({
    shareid: shareId,
    from: fromUk,
    ondup: 'overwrite',
    async: '1',
    web: '1',
    clienttype: '0',
    channel: 'chunlei',
    bdstoken,
  });
  if (sekey) params.set('sekey', sekey);
  const url = `https://pan.baidu.com/share/transfer?${params.toString()}`;

  const form = new URLSearchParams({
    fsidlist: JSON.stringify([Number.isFinite(Number(fsid)) ? Number(fsid) : fsid]),
    path: dest,
  }).toString();

  const { data } = await fetchJson(url, {
    method: 'POST',
    headers: {
      ...buildBaiduHeaders({ cookie, referer: `https://pan.baidu.com/s/1${encodeURIComponent(s)}` }),
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    },
    body: form,
  });

  return { bdstoken, cookie, data };
}

async function pickSavedFileInDir({ cookie, dirPath, fileName, bdstoken }) {
  const listed = await listMyDir({ cookie, dir: dirPath, start: 0, limit: 200, order: 'time', desc: true, bdstoken });
  const arr = listed && listed.data && Array.isArray(listed.data.list) ? listed.data.list : [];
  const want = String(fileName || '').trim();
  if (!arr.length) return null;
  if (want) {
    const found = arr.find((it) => it && typeof it === 'object' && String(it.server_filename || '').trim() === want);
    if (found) return found;
    const found2 = arr.find((it) => it && typeof it === 'object' && String(it.path || '').endsWith(`/${want}`));
    if (found2) return found2;
  }
  // fallback: pick first file (prefer non-dir)
  const file = arr.find((it) => it && typeof it === 'object' && Number(it.isdir) !== 1) || arr[0];
  return file || null;
}

export const apiPlugins = [
  {
    prefix: '/api/baidu',
    plugin: async function baiduApi(instance) {
      instance.get('/status', async (req) => {
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        return { ok: true, hasCookie: !!cookie };
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

      instance.post('/file/list', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const out = await listMyDir({
            cookie,
            dir: body.dir,
            start: body.start,
            limit: body.limit,
            order: body.order,
            desc: body.desc,
            bdstoken: body.bdstoken,
          });
          return { ok: true, ...out };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/file/info', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const out = await fileMetas({
            cookie,
            fsids: body.fsids,
            bdstoken: body.bdstoken,
            dlink: body.dlink === true,
          });
          return {
            ok: true,
            ...out,
          };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/file/download', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const out = await fileMetas({
            cookie,
            fsids: body.fsids,
            bdstoken: body.bdstoken,
            dlink: true,
          });
          const list = out && out.data && out.data.list ? out.data.list : [];
          const urls = Array.isArray(list)
            ? list
                .map((it) => (it && typeof it === 'object' ? String(it.dlink || '') : ''))
                .filter((u) => /^https?:\/\//i.test(u))
            : [];
          return {
            ok: true,
            urls,
            data: out.data,
            headers: {
              Cookie: cookie,
              Referer: 'https://pan.baidu.com/disk/main',
              'User-Agent': BAIDU_UA,
            },
          };
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

      instance.post('/file/clear', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const dirPath = String(body.dirPath || body.dir || '').trim();
        if (!dirPath || !dirPath.startsWith('/')) {
          reply.code(400);
          return { ok: false, message: 'missing dirPath' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getBaiduCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const out = await baiduClearDir({ cookie, dirPath });
          return { ok: true, ...out };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/parse', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
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
          const { html } = await fetchSharePage({ url });
          const yun = extractYunData(html);
          return { ok: true, surl: parsed.surl, yun: yun || null };
        } catch (e) {
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
          const out = await verifySharePwd({ surl: parsed.surl, pwd });
          return { ok: true, surl: parsed.surl, ...out };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/list', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
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
          const out = await listShareDir({
            surl: parsed.surl,
            pwd: body.pwd || body.pass,
            dir: body.dir,
            page: body.page,
            num: body.num,
          });
          return { ok: true, ...out };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/download', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
        if (!url) {
          reply.code(400);
          return { ok: false, message: 'missing url' };
        }
        const root = await readDbRoot(req.server);
        const baseCookie = getBaiduCookieFromDbRoot(root);
        if (!baseCookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const out = await shareDlink({
            url,
            pwd: body.pwd || body.pass,
            fsids: body.fsids || body.fs_id || body.fsid,
            baseCookie,
          });
          return {
            ok: true,
            ...out,
            headers: {
              Cookie: out.cookie,
              Referer: `https://pan.baidu.com/s/${encodeURIComponent(out.surl)}`,
              'User-Agent': BAIDU_UA,
            },
          };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });

      instance.post('/share/save', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const shareid = body.shareid || body.shareId || body.share_id;
        const uk = body.uk;
        const surl = body.surl;
        const pwd = body.pwd || body.pass;
        const fs_id = body.fs_id || body.fsId || body.fsid;
        const destPath = String(body.destPath || body.path || '').trim();
        const fileName = String(body.fileName || body.realName || body.server_filename || '').trim();
        if (!shareid || !uk || !surl || !fs_id || !destPath) {
          reply.code(400);
          return { ok: false, message: 'missing parameters' };
        }
        const root = await readDbRoot(req.server);
        const baseCookie = getBaiduCookieFromDbRoot(root);
        if (!baseCookie) {
          reply.code(400);
          return { ok: false, message: 'missing baidu cookie' };
        }
        try {
          const ensured = await baiduEnsureDir({ cookie: baseCookie, dirPath: destPath });
          const tr = await shareTransferToDir({
            baseCookie,
            shareid,
            uk,
            surl,
            pwd,
            fs_id,
            destPath,
          });
          const picked = await pickSavedFileInDir({ cookie: tr.cookie || baseCookie, dirPath: destPath, fileName, bdstoken: tr.bdstoken });
          const saved = picked
            ? {
                fs_id: picked.fs_id,
                path: picked.path,
                server_filename: picked.server_filename,
                isdir: picked.isdir,
                size: picked.size,
              }
            : null;
          return { ok: true, dirPath: destPath, ensured, transfer: tr.data, saved, cookie: tr.cookie || baseCookie, bdstoken: tr.bdstoken };
        } catch (e) {
          reply.code(502);
          return { ok: false, ...normalizeBaiduErr(e) };
        }
      });
    },
  },
];
