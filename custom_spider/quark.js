// Quark API plugin.

const QUARK_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch';

const QUARK_REFERER = 'https://pan.quark.cn';

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

function looksLikeCookieString(v) {
  const s = String(v || '').trim();
  return !!(s && s.includes('='));
}

function getQuarkCookieFromDbRoot(root) {
  try {
    const q = root && typeof root === 'object' ? root.quark : null;
    if (typeof q === 'string') return q.trim();
    if (!q || typeof q !== 'object' || Array.isArray(q)) return '';
    for (const v of Object.values(q)) {
      if (typeof v === 'string' && looksLikeCookieString(v)) return v.trim();
    }
  } catch {}
  return '';
}

function parseQuarkProxyDownUrl(urlStr) {
  if (typeof urlStr !== 'string' || !urlStr.trim()) return null;
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  const parts = u.pathname.split('/').filter(Boolean);
  const downIdx = parts.indexOf('down');
  if (downIdx < 0 || downIdx + 2 >= parts.length) return null;
  const shareId = parts[downIdx + 1] || '';
  const enc = parts[downIdx + 2] || '';
  if (!shareId || !enc) return null;
  let decoded = enc;
  try {
    decoded = decodeURIComponent(enc);
  } catch {}
  const segs = decoded.split('*');
  const stoken = segs[0] || '';
  const fid = segs[1] || '';
  const fidToken = segs[2] || '';
  if (!stoken || !fid || !fidToken) return null;
  return { shareId, stoken, fid, fidToken };
}

function parseQuarkShareUrl(urlStr) {
  const raw = String(urlStr || '').trim();
  if (!raw) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  if (host !== 'pan.quark.cn' && !host.endsWith('.quark.cn')) return null;
  const m = u.pathname.match(/^\/s\/([^/?#]+)/);
  if (!m) return { shareId: '', url: raw };
  return { shareId: m[1], url: raw };
}

async function fetchJson(url, init) {
  const res = await fetch(url, { redirect: 'manual', ...init });
  const text = await res.text();
  let data;
  try {
    data = text && text.trim() ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const msg = (data && (data.message || data.msg)) || text || `status=${res.status}`;
    const err = new Error(`quark http ${res.status}: ${String(msg).slice(0, 300)}`);
    err.status = res.status;
    throw err;
  }
  if (data && typeof data === 'object' && 'code' in data && Number(data.code) !== 0) {
    throw new Error(`quark api code=${data.code} message=${String(data.message || '').slice(0, 300)}`);
  }
  return data;
}

function buildQuarkHeaders(cookie) {
  return {
    Accept: 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    Origin: QUARK_REFERER,
    Referer: QUARK_REFERER,
    'User-Agent': QUARK_UA,
    ...(cookie ? { Cookie: cookie } : {}),
  };
}

function collectFirstStringByKey(root, keyLower) {
  const queue = [root];
  const seen = new Set();
  let steps = 0;
  while (queue.length && steps < 5000) {
    steps += 1;
    const v = queue.shift();
    if (!v) continue;
    if (typeof v !== 'object') continue;
    if (seen.has(v)) continue;
    seen.add(v);
    if (Array.isArray(v)) {
      for (const it of v) queue.push(it);
      continue;
    }
    for (const [k, val] of Object.entries(v)) {
      if (String(k || '').toLowerCase() === keyLower && typeof val === 'string' && val.trim()) return val.trim();
      queue.push(val);
    }
  }
  return '';
}

async function quarkListDir({ pdirFid, cookie, size }) {
  const headers = buildQuarkHeaders(cookie);
  const fid = String(pdirFid == null ? '0' : pdirFid).trim() || '0';
  const sz = Number.isFinite(Number(size)) ? Math.max(1, Math.min(500, Number(size))) : 200;
  const url =
    `https://drive.quark.cn/1/clouddrive/file/sort?pr=ucpro&fr=pc` +
    `&pdir_fid=${encodeURIComponent(fid)}` +
    `&_fetch_total=1&_size=${encodeURIComponent(String(sz))}` +
    `&_sort=file_type:asc,file_name:asc`;
  return await fetchJson(url, { method: 'GET', headers });
}

async function ensureFolderFid({ name, cookie }) {
  const folderName = String(name || '').trim();
  if (!folderName) throw new Error('missing folder name');

  const headers = buildQuarkHeaders(cookie);
  const sortResp = await quarkListDir({ pdirFid: '0', cookie, size: 500 });
  const list =
    (sortResp && sortResp.data && (sortResp.data.list || sortResp.data.items || sortResp.data.files)) ||
    (sortResp && sortResp.list) ||
    [];
  if (Array.isArray(list)) {
    for (const it of list) {
      if (!it || typeof it !== 'object') continue;
      const isDir = it.dir === true || it.file_type === 0 || it.type === 'folder' || it.kind === 'folder';
      const nm = String(it.file_name || it.name || '').trim();
      if (!isDir) continue;
      if (nm === folderName) {
        const fid = String(it.fid || it.file_id || it.id || '').trim();
        if (fid) return fid;
      }
    }
  }

  // Create folder.
  const createUrl = `https://drive.quark.cn/1/clouddrive/file?pr=ucpro&fr=pc`;
  const body = { pdir_fid: '0', file_name: folderName, dir_path: '', dir_init_lock: false };
  const createResp = await fetchJson(createUrl, { method: 'POST', headers, body: JSON.stringify(body) });
  const fid =
    String(
      (createResp && createResp.data && (createResp.data.fid || createResp.data.file_id || createResp.data.id)) ||
        ''
    ).trim();
  if (!fid) throw new Error('create folder: fid not found');
  return fid;
}

async function quarkDeleteFiles({ fids, cookie }) {
  const list = Array.isArray(fids) ? fids.map((x) => String(x || '').trim()).filter(Boolean) : [];
  if (!list.length) return { ok: true, deleted: 0 };
  const headers = buildQuarkHeaders(cookie);
  const url = 'https://drive.quark.cn/1/clouddrive/file/delete?pr=ucpro&fr=pc';
  const body = { action_type: 2, filelist: list, exclude_fids: [] };
  const resp = await fetchJson(url, { method: 'POST', headers, body: JSON.stringify(body) });
  return { ok: true, deleted: list.length, resp };
}

async function quarkClearDir({ pdirFid, cookie }) {
  const fid = String(pdirFid == null ? '0' : pdirFid).trim() || '0';
  if (fid === '0') throw new Error('refuse to clear root (pdir_fid=0)');
  const sortResp = await quarkListDir({ pdirFid: fid, cookie, size: 500 });
  const list =
    (sortResp && sortResp.data && (sortResp.data.list || sortResp.data.items || sortResp.data.files)) ||
    (sortResp && sortResp.list) ||
    [];
  const fids = [];
  if (Array.isArray(list)) {
    for (const it of list) {
      if (!it || typeof it !== 'object') continue;
      const id = String(it.fid || it.file_id || it.id || '').trim();
      if (id && id !== '0') fids.push(id);
    }
  }
  if (!fids.length) return { ok: true, cleared: 0 };
  const del = await quarkDeleteFiles({ fids, cookie });
  return { ok: true, cleared: fids.length, delete: del };
}

async function tryGetShareStoken({ shareId, passcode, cookie }) {
  const pwdId = String(shareId || '').trim();
  if (!pwdId) throw new Error('missing shareId');
  const headers = buildQuarkHeaders(cookie);
  const pc = String(passcode || '').trim();

  const attempts = [
    async () =>
      await fetchJson('https://drive.quark.cn/1/clouddrive/share/sharepage/token?pr=ucpro&fr=pc', {
        method: 'POST',
        headers,
        body: JSON.stringify(pc ? { pwd_id: pwdId, passcode: pc } : { pwd_id: pwdId }),
      }),
    async () =>
      await fetchJson(`https://drive.quark.cn/1/clouddrive/share/sharepage/detail?pr=ucpro&fr=pc&pwd_id=${encodeURIComponent(pwdId)}`, {
        method: 'GET',
        headers,
      }),
    async () =>
      await fetchJson('https://drive.quark.cn/1/clouddrive/share/sharepage/detail?pr=ucpro&fr=pc', {
        method: 'POST',
        headers,
        body: JSON.stringify(pc ? { pwd_id: pwdId, passcode: pc, pdir_fid: '0' } : { pwd_id: pwdId, pdir_fid: '0' }),
      }),
  ];

  let lastErr = null;
  for (const fn of attempts) {
    try {
      const data = await fn();
      const stoken =
        collectFirstStringByKey(data, 'stoken') ||
        collectFirstStringByKey(data && data.data ? data.data : null, 'stoken');
      if (stoken) return { stoken, raw: data };
    } catch (e) {
      lastErr = e;
    }
  }
  if (lastErr) throw lastErr;
  throw new Error('stoken not found');
}

async function quarkShareSave({ shareId, stoken, fid, fidToken, toPdirFid, cookie }) {
  const headers = buildQuarkHeaders(cookie);
  const pwdId = String(shareId || '').trim();
  const sToken = String(stoken || '').trim();
  const fId = String(fid || '').trim();
  const fToken = String(fidToken || '').trim();
  const toPdir = String(toPdirFid || '').trim() || '0';
  if (!pwdId || !sToken || !fId || !fToken) throw new Error('missing quark share parameters');
  if (toPdir === '0') throw new Error('missing to_pdir_fid');

  const saveUrl = 'https://drive.quark.cn/1/clouddrive/share/sharepage/save?pr=ucpro&fr=pc';
  const taskUrlBase = 'https://drive.quark.cn/1/clouddrive/task?pr=ucpro&fr=pc';
  const saveBody = {
    fid_list: [fId],
    fid_token_list: [fToken],
    to_pdir_fid: toPdir,
    pwd_id: pwdId,
    stoken: sToken,
    pdir_fid: '0',
    scene: 'link',
    share_id: pwdId,
  };
  const saveResp = await fetchJson(saveUrl, { method: 'POST', headers, body: JSON.stringify(saveBody) });
  const taskId =
    (saveResp && saveResp.data && (saveResp.data.task_id || saveResp.data.taskId || saveResp.data.taskID)) || '';
  const taskID = String(taskId || '').trim();
  if (!taskID) throw new Error('quark save: task_id not found');

  const deadline = Date.now() + 30_000;
  let lastTask = null;
  while (Date.now() < deadline) {
    lastTask = await fetchJson(`${taskUrlBase}&task_id=${encodeURIComponent(taskID)}`, { method: 'GET', headers });
    const data = lastTask && lastTask.data && typeof lastTask.data === 'object' ? lastTask.data : null;
    const state = data ? Number(data.state ?? data.status ?? -1) : -1;
    const finished =
      state === 2 ||
      state === 3 ||
      state === 100 ||
      (data && data.finished === true) ||
      (data && data.finish === true) ||
      (data && Number(data.finish) === 1);
    if (finished) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  return { ok: true, task: lastTask, toPdirFid: toPdir };
}

async function getShareDetail({ shareId, stoken, passcode, cookie, pdirFid }) {
  const pwdId = String(shareId || '').trim();
  if (!pwdId) throw new Error('missing shareId');
  let sToken = String(stoken || '').trim();
  let raw = null;
  if (!sToken) {
    const out = await tryGetShareStoken({ shareId: pwdId, passcode, cookie });
    sToken = out.stoken;
    raw = out.raw;
  }
  const headers = buildQuarkHeaders(cookie);
  const dir = String(pdirFid || '0').trim() || '0';
  const url = 'https://drive.quark.cn/1/clouddrive/share/sharepage/detail?pr=ucpro&fr=pc';
  const body = { pwd_id: pwdId, stoken: sToken, pdir_fid: dir, _fetch_total: 1, _size: 200 };
  const detail = await fetchJson(url, { method: 'POST', headers, body: JSON.stringify(body) });
  return { shareId: pwdId, stoken: sToken, detail, raw };
}

async function quarkFileInfo({ fid, cookie }) {
  const headers = buildQuarkHeaders(cookie);
  const fId = String(fid || '').trim();
  if (!fId) throw new Error('missing fid');
  const urls = [
    `https://drive.quark.cn/1/clouddrive/file/info?pr=ucpro&fr=pc&fid=${encodeURIComponent(fId)}`,
    `https://drive.quark.cn/1/clouddrive/file?pr=ucpro&fr=pc&fid=${encodeURIComponent(fId)}`,
  ];
  let lastErr = null;
  for (const u of urls) {
    try {
      return await fetchJson(u, { method: 'GET', headers });
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('file info failed');
}

async function quarkDirectDownload({ fid, fidToken, cookie, want }) {
  const headers = buildQuarkHeaders(cookie);
  const fId = String(fid || '').trim();
  const fToken = String(fidToken || '').trim();
  if (!fId) throw new Error('missing fid');
  const wantMode = String(want || 'download_url').trim() || 'download_url';
  const url = 'https://drive.quark.cn/1/clouddrive/file/download?pr=ucpro&fr=pc';
  // Quark API variants:
  // - some deployments accept `{ fid }`
  // - others require `{ fids: [...] }` and return 400 "Bad Parameter: [fids is empty!]" when missing.
  const body = { fid: fId, fids: [fId] };
  if (fToken) {
    body.fid_token = fToken;
    body.fid_token_list = [fToken];
  }
  const resp = await fetchJson(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const data = resp && resp.data;
  let out = '';
  if (Array.isArray(data)) {
    for (const it of data) {
      if (!it || typeof it !== 'object') continue;
      out = it[wantMode] || it.download_url || it.play_url || it.url || '';
      if (typeof out === 'string' && out.trim()) break;
      out = '';
    }
  } else if (data && typeof data === 'object') {
    out = data[wantMode] || data.download_url || data.play_url || data.url || '';
  }
  const dl = String(out || '').trim();
  if (!dl) throw new Error('direct download url not found');
  return dl;
}

async function resolveDownloadUrl({ shareId, stoken, fid, fidToken, toPdirFid, cookie, want }) {
  const toPdir = String(toPdirFid || '').trim() || '0';
  if (toPdir === '0') throw new Error('missing to_pdir_fid');
  await quarkShareSave({ shareId, stoken, fid, fidToken, toPdirFid: toPdir, cookie });

  // After save, pick the saved file from destination folder and request a direct url for it.
  const sortResp = await quarkListDir({ pdirFid: toPdir, cookie, size: 200 });
  const list =
    (sortResp && sortResp.data && (sortResp.data.list || sortResp.data.items || sortResp.data.files)) ||
    (sortResp && sortResp.list) ||
    [];
  let picked = null;
  if (Array.isArray(list)) {
    for (const it of list) {
      if (!it || typeof it !== 'object') continue;
      const isDir = it.dir === true || it.file_type === 0 || it.type === 'folder' || it.kind === 'folder';
      if (isDir) continue;
      const id = String(it.fid || it.file_id || it.id || '').trim();
      if (!id) continue;
      picked = it;
      break;
    }
  }
  const pickedFid = picked ? String(picked.fid || picked.file_id || picked.id || '').trim() : '';
  const pickedToken = picked ? String(picked.fid_token || picked.fidToken || picked.token || '').trim() : '';
  if (!pickedFid) throw new Error('quark save ok but destination folder is empty');
  return await quarkDirectDownload({ fid: pickedFid, fidToken: pickedToken, cookie, want });
}

export const apiPlugins = [
  {
    prefix: '/api/quark',
    plugin: async function quarkApi(instance) {
      instance.get('/status', async (req) => {
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        return { ok: true, hasCookie: !!(cookie && cookie.trim()) };
      });

      instance.post('/file/list', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        try {
          const data = await quarkListDir({ pdirFid: body.pdir_fid ?? body.pdirFid ?? '0', cookie, size: body.size });
          return { ok: true, data };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg.slice(0, 400) };
        }
      });

      instance.post('/file/info', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const fid = String(body.fid || '').trim();
        if (!fid) {
          reply.code(400);
          return { ok: false, message: 'missing fid' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        try {
          const data = await quarkFileInfo({ fid, cookie });
          return { ok: true, data };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg.slice(0, 400) };
        }
      });

      instance.post('/file/download', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const fid = String(body.fid || '').trim();
        if (!fid) {
          reply.code(400);
          return { ok: false, message: 'missing fid' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        try {
          const url = await quarkDirectDownload({
            fid,
            fidToken: body.fidToken || body.fid_token,
            cookie,
            want: body.want || 'download_url',
          });
          return {
            ok: true,
            url,
            headers: {
              Cookie: cookie,
              Referer: 'https://pan.quark.cn',
              'User-Agent': QUARK_UA,
            },
          };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg.slice(0, 400) };
        }
      });

      instance.post('/share/parse', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
        if (!url) {
          reply.code(400);
          return { ok: false, message: 'missing url' };
        }
        const parsed = parseQuarkShareUrl(url);
        if (!parsed || !parsed.shareId) {
          reply.code(400);
          return { ok: false, message: 'invalid quark share url' };
        }
        return { ok: true, shareId: parsed.shareId };
      });

      instance.post('/share/stoken', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const shareId = String(body.shareId || body.pwd_id || body.share_id || '').trim();
        if (!shareId) {
          reply.code(400);
          return { ok: false, message: 'missing shareId' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        try {
          const out = await tryGetShareStoken({ shareId, passcode: body.passcode || body.pwd, cookie });
          return { ok: true, shareId, stoken: out.stoken };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg.slice(0, 400) };
        }
      });

      instance.post('/share/detail', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const shareId = String(body.shareId || body.pwd_id || body.share_id || '').trim();
        if (!shareId) {
          reply.code(400);
          return { ok: false, message: 'missing shareId' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        try {
          const out = await getShareDetail({
            shareId,
            stoken: body.stoken,
            passcode: body.passcode || body.pwd,
            pdirFid: body.pdir_fid ?? body.pdirFid ?? '0',
            cookie,
          });
          return { ok: true, ...out };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg.slice(0, 400) };
        }
      });

      instance.post('/share/parse_down', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const url = String(body.url || '').trim();
        const parsed = parseQuarkProxyDownUrl(url);
        if (!parsed) {
          reply.code(400);
          return { ok: false, message: 'invalid down url' };
        }
        return { ok: true, ...parsed };
      });

      instance.post('/file/ensure_dir', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const name = String(body.name || '').trim();
        if (!name) {
          reply.code(400);
          return { ok: false, message: 'missing name' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        const fid = await ensureFolderFid({ name, cookie });
        return { ok: true, fid };
      });

      instance.post('/file/clear', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const fid = String(body.fid || '').trim();
        if (!fid) {
          reply.code(400);
          return { ok: false, message: 'missing fid' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        try {
          const out = await quarkClearDir({ pdirFid: fid, cookie });
          return { ok: true, ...out };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg.slice(0, 400) };
        }
      });

      instance.post('/share/save', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const shareId = String(body.shareId || body.pwd_id || body.share_id || '').trim();
        const stoken = String(body.stoken || '').trim();
        const fid = String(body.fid || '').trim();
        const fidToken = String(body.fidToken || body.fid_token || '').trim();
        const toPdirFid = String(body.toPdirFid || body.to_pdir_fid || '').trim();
        if (!shareId || !stoken || !fid || !fidToken || !toPdirFid) {
          reply.code(400);
          return { ok: false, message: 'missing parameters' };
        }
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        try {
          const out = await quarkShareSave({ shareId, stoken, fid, fidToken, toPdirFid, cookie });
          return { ok: true, ...out };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg.slice(0, 400) };
        }
      });

      instance.post('/share/download', async (req, reply) => {
        const body = req && typeof req.body === 'object' ? req.body : {};
        const root = await readDbRoot(req.server);
        const cookie = getQuarkCookieFromDbRoot(root);
        if (!cookie) {
          reply.code(400);
          return { ok: false, message: 'missing quark cookie' };
        }
        const downUrl = String(body.downUrl || body.down_url || body.url || '').trim();
        const parsedDown = downUrl ? parseQuarkProxyDownUrl(downUrl) : null;

        const shareId = String(body.shareId || body.pwd_id || body.share_id || (parsedDown ? parsedDown.shareId : '') || '').trim();
        const stoken = String(body.stoken || (parsedDown ? parsedDown.stoken : '') || '').trim();
        const fid = String(body.fid || (parsedDown ? parsedDown.fid : '') || '').trim();
        const fidToken = String(body.fidToken || body.fid_token || (parsedDown ? parsedDown.fidToken : '') || '').trim();
        const toPdirFid = String(body.toPdirFid || body.to_pdir_fid || '').trim();
        const want = String(body.want || 'download_url').trim();
        try {
          const url = await resolveDownloadUrl({ shareId, stoken, fid, fidToken, toPdirFid, cookie, want });
          return {
            ok: true,
            url,
            headers: {
              Cookie: cookie,
              Referer: QUARK_REFERER,
              'User-Agent': QUARK_UA,
            },
          };
        } catch (e) {
          const msg = (e && e.message) || String(e);
          reply.code(502);
          return { ok: false, message: msg };
        }
      });
    },
  },
];
