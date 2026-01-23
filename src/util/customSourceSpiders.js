import fs from 'fs';
import path from 'path';
import vm from 'vm';
import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { createRequire } from 'module';
import { fileURLToPath, pathToFileURL } from 'url';
import { getCurrentTvUser, sanitizeTvUsername } from './tvUserContext.js';

let cache = {
    dirPath: '',
    files: [],
    spiders: [],
    errors: {},
    byFile: {},
    webPlugins: [],
    webErrors: {},
    webByFile: {},
    websiteBundles: [],
    websiteErrors: {},
    websiteByFile: {},
};

let dbJsonCache = {
    path: '',
    mtimeMs: 0,
    size: 0,
    data: null,
};

const directLinkConfigState = {
    path: '',
    mtimeMs: 0,
    size: 0,
    config: { directLinkEnabled: true, rewriteBase: '' },
};

const customScriptManifestCache = new Map();

function readCustomScriptManifest(filePath) {
    const filename = typeof filePath === 'string' ? filePath : '';
    if (!filename) return null;
    const manifestPath = `${filename}.manifest.json`;
    try {
        if (!fs.existsSync(manifestPath)) return null;
        const st = fs.statSync(manifestPath);
        const cached = customScriptManifestCache.get(manifestPath);
        if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) return cached.data;

        const raw = fs.readFileSync(manifestPath, 'utf8');
        const parsed = raw && raw.trim() ? JSON.parse(raw) : null;
        const data = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
        customScriptManifestCache.set(manifestPath, { mtimeMs: st.mtimeMs, size: st.size, data });
        return data;
    } catch (_e) {
        return null;
    }
}

function normalizeCustomScriptFormat(value) {
    const v = String(value || '').trim().toLowerCase();
    if (!v) return 'vm';
    if (v === 'vm') return 'vm';
    if (v === 'esm' || v === 'module') return 'esm';
    if (v === 'cjs' || v === 'commonjs') return 'cjs';
    return 'vm';
}

const spiderAutoInitState = new Map();

function parseStandardSpiderPath(pathname) {
    const raw = typeof pathname === 'string' ? pathname : '';
    if (!raw) return null;
    const m = raw.match(/^\/spider\/([^/]+)\/([^/]+)\/(init|home|category|detail|play|search)$/);
    if (!m) return null;
    const key = m[1];
    const type = m[2];
    const action = m[3];
    return { base: `/spider/${key}/${type}`, key, type, action };
}

async function ensureSpiderInitOnceForRequest(req) {
    if (!req || !req.raw) return;
    const skip = req.headers && (req.headers['x-cp-skip-auto-init'] || req.headers['X-CP-SKIP-AUTO-INIT']);
    if (String(skip || '') === '1') return;

    const rawUrl = String(req.raw.url || '');
    const pathname = rawUrl.split('?')[0] || '';
    const parsed = parseStandardSpiderPath(pathname);
    if (!parsed) return;
    if (parsed.action === 'init') return;

    const user = sanitizeTvUsername(getCurrentTvUser());
    const cacheKey = `${user}:${parsed.base}`;
    const cur = spiderAutoInitState.get(cacheKey) || { done: false, inflight: null, noInit: false, nextRetryAtMs: 0 };
    if (cur.done || cur.noInit) return;
    if (cur.nextRetryAtMs && Date.now() < Number(cur.nextRetryAtMs)) return;
    if (cur.inflight) {
        await cur.inflight;
        return;
    }

    const tvUserHeader = user ? { 'X-TV-User': user } : {};
    const inflight = (async () => {
        try {
            const res = await req.server.inject({
                method: 'POST',
                url: `${parsed.base}/init`,
                headers: {
                    'content-type': 'application/json',
                    'x-cp-skip-auto-init': '1',
                    ...tvUserHeader,
                },
                payload: {},
            });
            if (res && res.statusCode === 404) {
                cur.noInit = true;
                return;
            }
            if (res && res.statusCode >= 200 && res.statusCode < 300) {
                cur.done = true;
                return;
            }
            // Avoid spamming init on every request when init keeps failing.
            cur.nextRetryAtMs = Date.now() + 60 * 1000;
        } catch (_) {}
    })();

    cur.inflight = inflight;
    spiderAutoInitState.set(cacheKey, cur);
    try {
        await inflight;
    } finally {
        cur.inflight = null;
        spiderAutoInitState.set(cacheKey, cur);
    }
}

function markSpiderAutoInitDoneFromInitResponse(req, reply) {
    try {
        if (!req || !req.raw || !reply) return;
        const rawUrl = String(req.raw.url || '');
        const pathname = rawUrl.split('?')[0] || '';
        const parsed = parseStandardSpiderPath(pathname);
        if (!parsed || parsed.action !== 'init') return;

        const user = sanitizeTvUsername(getCurrentTvUser());
        const cacheKey = `${user}:${parsed.base}`;
        const cur = spiderAutoInitState.get(cacheKey) || { done: false, inflight: null, noInit: false, nextRetryAtMs: 0 };
        const code = Number(reply.statusCode || 0);
        if (code >= 200 && code < 300) {
            cur.done = true;
            cur.noInit = false;
            cur.nextRetryAtMs = 0;
        }
        spiderAutoInitState.set(cacheKey, cur);
    } catch (_) {}
}

function getEmbeddedRootDir() {
    // When bundled by esbuild (cjs), `__dirname` points to `dist/`.
    // When packaged by pkg, `__dirname` points into `/snapshot/.../dist`.
    // In dev (esm), fall back to `process.cwd()`.
    try {
        // eslint-disable-next-line no-undef
        if (typeof __dirname !== 'undefined') return path.resolve(__dirname, '..');
    } catch (_) {}
    return process.cwd();
}

function getExternalRootDir() {
    // For pkg executables, use the executable directory as the writable root.
    try {
        if (process && process.pkg && typeof process.execPath === 'string' && process.execPath) {
            return path.dirname(process.execPath);
        }
    } catch (_) {}
    return '';
}

function getConfigJsonPath() {
    const external = getExternalRootDir();
    if (external) return path.resolve(external, 'config.json');
    return path.resolve(getEmbeddedRootDir(), 'config.json');
}

function getGlobalPanDirNameForCurrentUser() {
    // Global per-pan destination folder base name (shared by Quark/Baidu/etc).
    // Final folder name is `${base}_${TVUser}`.
    const base = String('TV_Server')
        .trim()
        .replace(/[^a-zA-Z0-9._-]+/g, '_')
        .replace(/^_+|_+$/g, '') || 'TV_Server';
    const user = sanitizeTvUsername(getCurrentTvUser());
    return `${base}_${user}`;
}

function normalizeHttpBase(value) {
    if (typeof value !== 'string') return '';
    const trimmed = value.trim();
    if (!trimmed) return '';
    try {
        const u = new URL(trimmed);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
        return u.toString().replace(/\/+$/g, '');
    } catch (_) {
        return '';
    }
}

function getDirectLinkConfig() {
    const cfgPath = getConfigJsonPath();
    try {
        const st = fs.statSync(cfgPath);
        if (
            directLinkConfigState &&
            directLinkConfigState.config &&
            directLinkConfigState.path === cfgPath &&
            directLinkConfigState.mtimeMs === st.mtimeMs &&
            directLinkConfigState.size === st.size
        ) {
            return directLinkConfigState.config;
        }

        const raw = fs.readFileSync(cfgPath, 'utf8');
        const parsed = raw && raw.trim() ? JSON.parse(raw) : null;
        const root = parsed && typeof parsed === 'object' ? parsed : null;
        const directLink =
            root && root.directLink && typeof root.directLink === 'object' && !Array.isArray(root.directLink) ? root.directLink : null;
        const directLinkEnabled =
            directLink && Object.prototype.hasOwnProperty.call(directLink, 'enabled') ? !!directLink.enabled : true;
        const cfg = { directLinkEnabled, rewriteBase: normalizeHttpBase(root && root.rewriteBase) };

        directLinkConfigState.path = cfgPath;
        directLinkConfigState.mtimeMs = st.mtimeMs;
        directLinkConfigState.size = st.size;
        directLinkConfigState.config = cfg;
        return cfg;
    } catch (_e) {
        return directLinkConfigState && directLinkConfigState.config ? directLinkConfigState.config : { directLinkEnabled: true, rewriteBase: '' };
    }
}

async function quarkResolveDownloadUrlViaApi({ shareId, stoken, fid, fidToken, toPdirFid, rawHeader, scriptContext, want }) {
    const fetchImpl = globalThis.fetch;
    if (typeof fetchImpl !== 'function') throw new Error('fetch is not available');
    const QUARK_DEBUG = process.env.CATPAW_DEBUG === '1';
    const mask = (v) => {
        const s = String(v || '').trim();
        if (!s) return '';
        if (s.length <= 12) return s;
        return `${s.slice(0, 6)}...${s.slice(-6)}`;
    };
    const log = (...args) => {
        if (!QUARK_DEBUG) return;
        // eslint-disable-next-line no-console
        console.log('[quarkApi]', ...args);
    };

    const pwdId = String(shareId || '').trim();
    const sToken = String(stoken || '').trim();
    const fId = String(fid || '').trim();
    const fToken = String(fidToken || '').trim();
    const toPdir = String(toPdirFid || '').trim() || '0';
    const wantMode = String(want || 'download_url').trim() || 'download_url';
    if (!pwdId || !sToken || !fId || !fToken) throw new Error('missing quark share parameters');
    if (toPdir === '0') throw new Error('quark to_pdir_fid is 0 (destination folder not initialized)');
    const ctxHasWKt = !!(scriptContext && typeof scriptContext.WKt === 'function');

    const headers = {
        Accept: 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        Origin: 'https://pan.quark.cn',
        Referer: 'https://pan.quark.cn',
    };
    if (rawHeader && typeof rawHeader === 'object') {
        const ua = rawHeader['User-Agent'] || rawHeader['user-agent'];
        const ref = rawHeader.Referer || rawHeader.referer;
        const ck = rawHeader.Cookie || rawHeader.cookie;
        const auth = rawHeader.Authorization || rawHeader.authorization;
        if (typeof ua === 'string' && ua.trim()) headers['User-Agent'] = ua.trim();
        if (typeof ref === 'string' && ref.trim()) headers.Referer = ref.trim();
        if (typeof ck === 'string' && ck.trim()) headers.Cookie = ck.trim();
        if (typeof auth === 'string' && auth.trim()) headers.Authorization = auth.trim();
    }

    const fetchJson = async (url, init) => {
        const res = await fetchImpl(url, { redirect: 'manual', ...init });
        const text = await res.text();
        let data;
        try {
            data = text && text.trim() ? JSON.parse(text) : null;
        } catch (_) {
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
    };

    const fetchJsonWithText = async (url, init) => {
        const res = await fetchImpl(url, { redirect: 'manual', ...init });
        const text = await res.text();
        let data;
        try {
            data = text && text.trim() ? JSON.parse(text) : null;
        } catch (_) {
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
        return { data, text };
    };

    const saveUrl = 'https://drive.quark.cn/1/clouddrive/share/sharepage/save?pr=ucpro&fr=pc';
    const taskUrlBase = 'https://drive.quark.cn/1/clouddrive/task?pr=ucpro&fr=pc';
    const dlUrl = 'https://drive.quark.cn/1/clouddrive/file/download?pr=ucpro&fr=pc';

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
    log('save ok', { shareId: mask(pwdId), toPdir: mask(toPdir), taskId: mask(taskID) });

    const excludeValues = [
        taskID,
        fId,
        fToken,
        pwdId,
        sToken,
        toPdir,
        scriptContext && scriptContext.UW ? String(scriptContext.UW) : '',
        scriptContext && scriptContext.s8 ? String(scriptContext.s8) : '',
    ]
        .map((v) => String(v || '').trim())
        .filter(Boolean);
    const excludeSet = new Set(excludeValues);
    const isBadFid = (v) => {
        const s = String(v || '').trim();
        if (!s) return true;
        if (excludeSet.has(s)) return true;
        // Folder fid sometimes leaks into task payload; avoid using "obviously wrong" candidates.
        if (scriptContext && typeof scriptContext === 'object') {
            const uw = scriptContext.UW ? String(scriptContext.UW) : '';
            const s8 = scriptContext.s8 ? String(scriptContext.s8) : '';
            if (uw && s === uw) return true;
            if (s8 && s === s8) return true;
        }
        return false;
    };

    const findFirstByKeys = (root, keys) => {
        if (!root || typeof root !== 'object') return '';
        const lower = new Set(keys.map((k) => String(k).toLowerCase()));
        const queue = [{ v: root, d: 0 }];
        const seen = new Set();
        const maxDepth = 10;
        while (queue.length) {
            const { v, d } = queue.shift();
            if (!v || typeof v !== 'object') continue;
            if (seen.has(v)) continue;
            seen.add(v);
            if (Array.isArray(v)) {
                if (d < maxDepth) for (const item of v) queue.push({ v: item, d: d + 1 });
                continue;
            }
            for (const [k, val] of Object.entries(v)) {
                if (lower.has(String(k).toLowerCase())) {
                    if (typeof val === 'string' && val.trim()) return val.trim();
                    if (typeof val === 'number' && Number.isFinite(val)) return String(val);
                    if (Array.isArray(val) && val.length) {
                        const first = val[0];
                        if (typeof first === 'string' && first.trim()) return first.trim();
                        if (typeof first === 'number' && Number.isFinite(first)) return String(first);
                    }
                }
                if (d < maxDepth) queue.push({ v: val, d: d + 1 });
            }
        }
        return '';
    };

    const collectCandidates = (root, { excludeValues }) => {
        const candidates = [];
        const excludes = new Set((excludeValues || []).map((v) => String(v || '').trim()).filter(Boolean));
        const queue = [{ v: root, key: '', d: 0 }];
        const seen = new Set();
        const maxDepth = 10;
        const isHex32 = (s) => /^[0-9a-f]{32}$/i.test(s);
        while (queue.length) {
            const { v, key, d } = queue.shift();
            if (!v) continue;
            if (typeof v === 'string') {
                const s = v.trim();
                if (!s || excludes.has(s)) continue;
                // Prefer fid-like keys or hex32 values.
                const k = String(key || '').toLowerCase();
                if (k.includes('fid') || k.includes('file')) candidates.push({ s, score: 3 });
                else if (isHex32(s)) candidates.push({ s, score: 2 });
                continue;
            }
            if (typeof v === 'number' && Number.isFinite(v)) {
                const s = String(v);
                if (!excludes.has(s)) candidates.push({ s, score: 1 });
                continue;
            }
            if (typeof v !== 'object') continue;
            if (seen.has(v)) continue;
            seen.add(v);
            if (d >= maxDepth) continue;
            if (Array.isArray(v)) {
                for (const item of v) queue.push({ v: item, key, d: d + 1 });
                continue;
            }
            for (const [k, val] of Object.entries(v)) queue.push({ v: val, key: k, d: d + 1 });
        }
        candidates.sort((a, b) => b.score - a.score);
        const uniq = [];
        const seenStr = new Set();
        for (const c of candidates) {
            if (seenStr.has(c.s)) continue;
            seenStr.add(c.s);
            uniq.push(c.s);
        }
        return uniq;
    };

    const pickSavedFidAndState = (taskResp) => {
        const data = taskResp && typeof taskResp === 'object' ? taskResp.data : null;
        if (!data || typeof data !== 'object') return { fid: '', fidToken: '', state: -1, finished: false };

        const pickHex32FromSubtree = (root, { excludeValues } = {}) => {
            const candidates = collectCandidates(root, { excludeValues: excludeValues || [] });
            return candidates.find((s) => /^[0-9a-f]{32}$/i.test(s)) || '';
        };

        const extractSavedFidFromSaveAs = (saveAs, { excludeValues: ev } = {}) => {
            const excludeValues = Array.isArray(ev) ? ev : [];
            if (!saveAs) return '';
            const pickFidFromArr = (arr) => {
                if (!Array.isArray(arr) || !arr.length) return '';
                const v = arr[0];
                if (typeof v === 'string') return v.trim();
                if (typeof v === 'number' && Number.isFinite(v)) return String(v);
                if (v && typeof v === 'object') {
                    const a = v.fid || v.file_id || v.fileId || v.id;
                    if (typeof a === 'string' && a.trim()) return a.trim();
                    if (typeof a === 'number' && Number.isFinite(a)) return String(a);
                }
                return '';
            };

            // Common shapes:
            // - { save_as_fids: [fid], ... }
            // - { save_as_fid: fid, ... }
            // - [ { fid: ... } ]
            if (Array.isArray(saveAs)) {
                for (const item of saveAs) {
                    if (!item || typeof item !== 'object') continue;
                    const direct =
                        (typeof item.fid === 'string' && item.fid.trim()) ||
                        (typeof item.file_id === 'string' && item.file_id.trim()) ||
                        (typeof item.fileId === 'string' && item.fileId.trim()) ||
                        '';
                    if (direct && !isBadFid(direct)) return String(direct).trim();
                    const byKeys = findFirstByKeys(item, ['save_as_fids', 'save_as_fid', 'fid', 'file_id', 'fileId', 'id']);
                    if (byKeys && !isBadFid(byKeys)) return byKeys;
                    const hex = pickHex32FromSubtree(item, { excludeValues });
                    if (hex && !isBadFid(hex)) return hex;
                }
                return '';
            }

            if (typeof saveAs === 'object') {
                let fid = '';
                fid = pickFidFromArr(saveAs.save_as_fids);
                if (!fid && 'save_as_fid' in saveAs) fid = typeof saveAs.save_as_fid === 'string' ? saveAs.save_as_fid.trim() : '';
                if (!fid && Array.isArray(saveAs.fids)) fid = pickFidFromArr(saveAs.fids);
                if (!fid && Array.isArray(saveAs.fid_list)) fid = pickFidFromArr(saveAs.fid_list);

                if (!fid) {
                    fid = findFirstByKeys(saveAs, ['save_as_fids', 'save_as_fid', 'fids', 'fid_list', 'fid', 'file_id', 'fileId', 'id']);
                }
                if (!fid) {
                    fid = pickHex32FromSubtree(saveAs, { excludeValues });
                }
                return fid && !isBadFid(fid) ? fid : '';
            }

            return '';
        };

        const extractSavedFidTokenFromSaveAs = (saveAs) => {
            if (!saveAs) return '';
            const tok = findFirstByKeys(saveAs, [
                'fid_token',
                'fidToken',
                'file_token',
                'fileToken',
                'fid_token_list',
                'file_token_list',
                'file_tokens',
            ]);
            const t = String(tok || '').trim();
            if (!t) return '';
            // Avoid returning known unrelated ids/tokens.
            if (t === taskID || t === fId || t === fToken || t === pwdId || t === sToken) return '';
            return t;
        };

        const readNum = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' ? Number(v) : NaN);
        let state = -1;
        if (Number.isFinite(readNum(data.status))) state = readNum(data.status);
        if (state < 0 && Number.isFinite(readNum(data.state))) state = readNum(data.state);
        if (state < 0 && data.task && typeof data.task === 'object') {
            if (Number.isFinite(readNum(data.task.status))) state = readNum(data.task.status);
            if (state < 0 && Number.isFinite(readNum(data.task.state))) state = readNum(data.task.state);
        }

        let finished = false;
        if (typeof data.finish === 'boolean') finished = data.finish;
        else if (data.task && typeof data.task === 'object' && typeof data.task.finish === 'boolean') finished = data.task.finish;

        const pickFidFromArr = (arr) => {
            if (!Array.isArray(arr) || !arr.length) return '';
            const v = arr[0];
            const s = typeof v === 'string' ? v.trim() : '';
            return isBadFid(s) ? '' : s;
        };
        let fid = '';
        let fidToken = '';
        if (data.save_as && typeof data.save_as === 'object') {
            fid = pickFidFromArr(data.save_as.save_as_fids);
            fidToken = extractSavedFidTokenFromSaveAs(data.save_as);
        }
        if (!fid) fid = pickFidFromArr(data.save_as_fids);
        if (!fid && data.result && typeof data.result === 'object') {
            if (typeof data.result.fid === 'string' && data.result.fid.trim() && !isBadFid(data.result.fid)) fid = data.result.fid.trim();
            if (!fid && typeof data.result.file_id === 'string' && data.result.file_id.trim() && !isBadFid(data.result.file_id))
                fid = data.result.file_id.trim();
        }

        if (!fid && data.save_as) {
            fid = extractSavedFidFromSaveAs(data.save_as, { excludeValues });
        }

        if (!fidToken) {
            if (data.save_as) fidToken = extractSavedFidTokenFromSaveAs(data.save_as);
            if (!fidToken) fidToken = extractSavedFidTokenFromSaveAs(data);
        }

        if (!fid) {
            // Fallback for different task response shapes (minified scripts may use different field names).
            // Avoid generic keys like "fid"/"file_id" here because they often refer to the *source* fid,
            // which still can't be downloaded until it is saved into the user's drive.
            fid = findFirstByKeys(data, [
                'save_as_fids',
                'save_as_fid',
                'save_fid',
                'saved_fid',
                'save_as_fid_list',
                'save_as_fids_list',
            ]);
        }
        if (fid && isBadFid(fid)) fid = '';

        return { fid, fidToken, state, finished };
    };

    let savedFid = '';
    let savedFidToken = '';
    let lastLoggedFid = '';
    let lastPicked = null;
    let lastTaskResp = null;
    const deadline = Date.now() + 60_000;
    let retryIndex = 0;
    while (Date.now() < deadline) {
        // Quark task endpoint returns progressively richer payloads as retry_index increases (seen in some bundles).
        const u = `${taskUrlBase}&task_id=${encodeURIComponent(taskID)}&retry_index=${retryIndex}`;
        retryIndex += 1;
        const taskResp = await fetchJson(u, { method: 'GET', headers });
        lastTaskResp = taskResp;
        const picked = pickSavedFidAndState(taskResp);
        lastPicked = picked;
        if (picked && picked.fid) savedFid = picked.fid;
        if (picked && picked.fidToken) savedFidToken = String(picked.fidToken || '').trim();
        if (picked && picked.fid && picked.fid !== lastLoggedFid) {
            lastLoggedFid = picked.fid;
            log('task picked fid', {
                fid: mask(picked.fid),
                finished: !!picked.finished,
                state: picked.state,
                retryIndex,
            });
        }
        // Prefer the explicit finish flag when available.
        if (picked && picked.finished && savedFid) break;
        // Some variants expose only status/state.
        if (picked && picked.state === 2 && savedFid) break;
        await new Promise((r) => setTimeout(r, 500));
    }
    if (!savedFid) {
        const finished = !!(lastPicked && lastPicked.finished);
        const state = lastPicked && typeof lastPicked.state === 'number' ? lastPicked.state : -1;

        const msg = finished || state === 2 ? 'quark task finished but saved fid not found' : 'quark task timeout waiting for save';
        const hintObj = lastTaskResp && typeof lastTaskResp === 'object' ? lastTaskResp.data : null;
        const hint =
            hintObj && typeof hintObj === 'object'
                ? (() => {
                      const saveAs = hintObj.save_as;
                      const saveAsType = Array.isArray(saveAs) ? 'array' : saveAs === null ? 'null' : typeof saveAs;
                      const saveAsKeys =
                          saveAs && typeof saveAs === 'object' && !Array.isArray(saveAs) ? Object.keys(saveAs).slice(0, 20) : undefined;
                      const saveAs0Keys =
                          Array.isArray(saveAs) && saveAs[0] && typeof saveAs[0] === 'object' ? Object.keys(saveAs[0]).slice(0, 20) : undefined;
                      const base = {
                          retryIndex,
                          finish: hintObj.finish,
                          status: hintObj.status,
                          state: hintObj.state,
                          keys: Object.keys(hintObj).slice(0, 20),
                          save_as: saveAs ? { type: saveAsType, keys: saveAsKeys, firstKeys: saveAs0Keys } : undefined,
                          task:
                              hintObj.task && typeof hintObj.task === 'object'
                                  ? {
                                        finish: hintObj.task.finish,
                                        status: hintObj.task.status,
                                        state: hintObj.task.state,
                                        keys: Object.keys(hintObj.task).slice(0, 20),
                                    }
                                  : undefined,
                      };
                      try {
                          return JSON.stringify(base, null, 0);
                      } catch (_) {
                          return '';
                      }
                  })()
                : '';
        throw new Error(`${msg}${hint ? ` (${hint})` : ''}`);
    }

    log('task ok', { savedFid: mask(savedFid), savedFidToken: mask(savedFidToken) });

    try {
        rememberQuarkSavedFile({
            shareId: pwdId,
            stoken: sToken,
            fid: fId,
            fidToken: fToken,
            toPdirFid: toPdir,
            rawHeader,
            savedFid,
            savedFidToken,
        });
    } catch (_) {}

    if (wantMode === 'saved_fid') return savedFid;

    let wktFailureHint = '';
    let wktTokenCandidate = '';

    // Optional fallback: some bundles expose `WKt(...)` to perform extra Quark token/conversation flows.
    // IMPORTANT: do NOT call WKt() on every play. It can trigger many noisy Quark API requests (401/404 logs).
    // Only use it as a last resort when our explicit save+task+file/download flow can't obtain a download_url.
    const tryWktFallback = async () => {
        if (!ctxHasWKt) return { url: '', tokenCandidate: '', hint: '' };
        if (!scriptContext || typeof scriptContext.WKt !== 'function') return { url: '', tokenCandidate: '', hint: '' };

        const maskFid = (v) => {
            const s = typeof v === 'string' ? v : String(v || '');
            if (s.length <= 12) return s;
            return `${s.slice(0, 6)}...${s.slice(-6)}`;
        };

        const wktArgs = [savedFidToken, fToken, fId].map((x) => String(x || '').trim()).filter(Boolean);
        let lastNonUrl = '';
        let lastType = '';
        for (const arg of wktArgs) {
            try {
                const u = await scriptContext.WKt(arg);
                lastType = typeof u;
                if (typeof u === 'string') {
                    const trimmed = u.trim();
                    if (trimmed.startsWith('//')) return { url: `https:${trimmed}`, tokenCandidate: '', hint: '' };
                    if (/^https?:\/\//i.test(trimmed)) return { url: trimmed, tokenCandidate: '', hint: '' };
                    if (trimmed) lastNonUrl = trimmed;
                }
            } catch (e) {
                const msg = e && e.message ? String(e.message) : String(e || 'unknown');
                return {
                    url: '',
                    tokenCandidate: '',
                    hint: `wktErr(${msg.slice(0, 200)})`,
                };
            }
        }

        const head = (() => {
            if (!lastNonUrl) return '';
            const noQuery = lastNonUrl.split('?')[0];
            return noQuery.length > 200 ? `${noQuery.slice(0, 200)}...` : noQuery;
        })();
        const len = typeof lastNonUrl === 'string' ? lastNonUrl.length : 0;
        const tokenCandidate = (() => {
            const trimmed = String(lastNonUrl || '').trim();
            if (!trimmed) return '';
            if (trimmed.length > 200) return '';
            if (/\s/.test(trimmed)) return '';
            return trimmed;
        })();
        return {
            url: '',
            tokenCandidate,
            hint: `wktNonUrl(type=${lastType} len=${len} head=${JSON.stringify(head)} wktArgs=${JSON.stringify(wktArgs.map(maskFid))} savedFid=${maskFid(savedFid)})`,
        };
    };

    const extractDownloadUrl = (root, rawText) => {
        const isHttpUrl = (s) => typeof s === 'string' && /^https?:\/\//i.test(s.trim());
        const queue = [root];
        const seen = new Set();
        const maxNodes = 4000;
        let nodes = 0;
        while (queue.length && nodes < maxNodes) {
            const v = queue.shift();
            nodes += 1;
            if (!v) continue;
            if (typeof v === 'string') continue;
            if (typeof v !== 'object') continue;
            if (seen.has(v)) continue;
            seen.add(v);
            if (Array.isArray(v)) {
                for (const item of v) queue.push(item);
                continue;
            }
            for (const [k, val] of Object.entries(v)) {
                const key = String(k || '').toLowerCase();
                if ((key === 'download_url' || key === 'downloadurl' || key.endsWith('_download_url')) && isHttpUrl(val)) {
                    return String(val).trim();
                }
                if (key.includes('download_url') && isHttpUrl(val)) return String(val).trim();
                if (typeof val === 'object' && val) queue.push(val);
                else if (typeof val === 'string' && key.includes('download_url') && isHttpUrl(val)) return val.trim();
            }
        }
        if (typeof rawText === 'string' && rawText.includes('download_url')) {
            const m = rawText.match(/"download_url"\s*:\s*"([^"]+)"/);
            if (m && isHttpUrl(m[1])) return m[1].trim();
        }
        return '';
    };

    let lastDlHint = '';
    let lastDlTextHead = '';

    const downloadTokenCandidates = (() => {
        const out = [];
        const push = (v) => {
            const s = String(v || '').trim();
            if (!s) return;
            if (s === savedFid) return;
            if (out.includes(s)) return;
            out.push(s);
        };
        push(wktTokenCandidate);
        push(savedFidToken);
        push(fToken);
        // Also try "no token" download for cases where the saved file is already in the user's drive
        // and Quark accepts fids-only.
        out.push('');
        return out;
    })();

    const tryDownloadOnce = async (token) => {
        log('download try', { fid: mask(savedFid), token: mask(token || '') });
        const dlBody = { fids: [savedFid] };
        if (token) {
            dlBody.file_tokens = [token];
            dlBody.fid_token_list = [token];
        }
        const { data: dlResp, text } = await fetchJsonWithText(dlUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(dlBody),
        });
        lastDlTextHead = typeof text === 'string' ? text.slice(0, 300) : '';
        const url =
            extractDownloadUrl(dlResp && typeof dlResp === 'object' ? dlResp.data : dlResp, text) || extractDownloadUrl(dlResp, text);
        if (url) {
            log('download ok', { host: (() => { try { return new URL(url).host; } catch (_) { return ''; } })() });
            return url;
        }
        const hintObj = dlResp && typeof dlResp === 'object' ? dlResp.data : null;
        if (Array.isArray(hintObj)) lastDlHint = JSON.stringify({ type: 'array', len: hintObj.length });
        else if (hintObj && typeof hintObj === 'object') lastDlHint = JSON.stringify({ type: 'object', keys: Object.keys(hintObj).slice(0, 20) });
        else lastDlHint = '';
        log('download miss', { hint: lastDlHint, textHead: lastDlTextHead ? `${lastDlTextHead.slice(0, 80)}...` : '' });
        return '';
    };

    // Pass A: quick sweep all candidates once (fast fail on token mismatch without long waits).
    for (const token of downloadTokenCandidates.length ? downloadTokenCandidates : ['']) {
        const url = await tryDownloadOnce(token);
        if (url) return url;
    }

    // Pass B: short readiness window (covers backend propagation delay after save-task).
    // Keep it bounded to avoid "卡很久", but long enough for Quark eventual consistency.
    const dlDeadline = Date.now() + 12000;
    const primaryTokens = downloadTokenCandidates.filter((t) => typeof t === 'string' && t.trim()).slice(0, 3);
    primaryTokens.push('');
    let dlAttempt = 0;
    while (Date.now() < dlDeadline) {
        const token = primaryTokens[dlAttempt % primaryTokens.length];
        dlAttempt += 1;
        const url = await tryDownloadOnce(token);
        if (url) return url;
        await new Promise((r) => setTimeout(r, 300));
    }

    // Last resort: ask the bundle to do its internal token/conversation flow (WKt),
    // then retry file/download once with the returned token candidate.
    if (ctxHasWKt) {
        const { url, tokenCandidate, hint } = await tryWktFallback();
        if (url) return url;
        if (hint) wktFailureHint = hint;
        if (tokenCandidate) {
            wktTokenCandidate = tokenCandidate;
            const url2 = await tryDownloadOnce(tokenCandidate);
            if (url2) return url2;
        }
    }

    const headNote = lastDlTextHead ? ` textHead=${JSON.stringify(lastDlTextHead)}` : '';
    const fidNote = savedFid ? ` fid=${savedFid}` : '';
    throw new Error(
        `quark download: download_url not found${lastDlHint ? ` (${lastDlHint})` : ''}${
            wktFailureHint ? ` (${wktFailureHint})` : ''
        }${fidNote}${headNote} (ctxHasWKt=${ctxHasWKt} tokens=${JSON.stringify(primaryTokens.map(mask))})`
    );
}

function parseQuarkProxyDownUrl(urlStr) {
    if (typeof urlStr !== 'string' || !urlStr.trim()) return null;
    let u;
    try {
        u = new URL(urlStr);
    } catch (_) {
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
    } catch (_) {}
    const segs = decoded.split('*');
    // Some bundles encode quark share tokens as: "<stoken>*<fid>*<fid_token>" (no shareId in this segment).
    const stoken = segs[0] || '';
    const fid = segs[1] || '';
    const fidToken = segs[2] || '';
    if (!stoken || !fid || !fidToken) return null;
    return { shareId, stoken, fid, fidToken };
}

const BAIDU_PROXY_TTL_MS = 60 * 60 * 1000;
const baiduProxyState = {
    registered: false,
    map: new Map(), // token -> { url, headers, ts }
};

// Some custom bundles contain the real Quark `download_url` resolver (`WKt`).
// The play-rewrite hook is installed only once per Fastify instance, so we keep a module-level
// reference to the bundle that actually provides Quark resolving.
const quarkRuntime = {
    ctx: null,
    fromFile: '',
};

const QUARK_DIRECT_URL_TTL_MS = (() => {
    const v = Number.parseInt(process.env.CATPAW_QUARK_DIRECT_URL_TTL_MS || '', 10);
    // Keep TTL short: download_url may expire quickly; this cache is mainly for request de-duplication.
    return Number.isFinite(v) && v >= 0 ? v : 30_000;
})();

const quarkDirectUrlCache = {
    map: new Map(), // key -> { ts, url, promise }
    maxEntries: 200,
};

const quarkSavedFileCache = {
    map: new Map(), // key -> { ts, fid, token }
    maxEntries: 300,
    ttlMs: 10 * 60 * 1000,
};

function pruneQuarkDirectUrlCache() {
    const now = Date.now();
    for (const [key, entry] of quarkDirectUrlCache.map.entries()) {
        if (!entry || typeof entry !== 'object') {
            quarkDirectUrlCache.map.delete(key);
            continue;
        }
        const ts = typeof entry.ts === 'number' ? entry.ts : 0;
        if (!ts || now - ts > QUARK_DIRECT_URL_TTL_MS) quarkDirectUrlCache.map.delete(key);
    }
    if (quarkDirectUrlCache.map.size <= quarkDirectUrlCache.maxEntries) return;
    const items = Array.from(quarkDirectUrlCache.map.entries()).sort(
        (a, b) => (a[1] && a[1].ts ? a[1].ts : 0) - (b[1] && b[1].ts ? b[1].ts : 0)
    );
    const overflow = items.length - quarkDirectUrlCache.maxEntries;
    for (let i = 0; i < overflow; i += 1) quarkDirectUrlCache.map.delete(items[i][0]);
}

function pruneQuarkSavedFileCache() {
    const now = Date.now();
    for (const [key, entry] of quarkSavedFileCache.map.entries()) {
        if (!entry || typeof entry !== 'object') {
            quarkSavedFileCache.map.delete(key);
            continue;
        }
        const ts = typeof entry.ts === 'number' ? entry.ts : 0;
        if (!ts || now - ts > quarkSavedFileCache.ttlMs) quarkSavedFileCache.map.delete(key);
    }
    if (quarkSavedFileCache.map.size <= quarkSavedFileCache.maxEntries) return;
    const items = Array.from(quarkSavedFileCache.map.entries()).sort(
        (a, b) => (a[1] && a[1].ts ? a[1].ts : 0) - (b[1] && b[1].ts ? b[1].ts : 0)
    );
    const overflow = items.length - quarkSavedFileCache.maxEntries;
    for (let i = 0; i < overflow; i += 1) quarkSavedFileCache.map.delete(items[i][0]);
}

function getQuarkAuthKey(rawHeader) {
    const raw = rawHeader && typeof rawHeader === 'object' ? rawHeader : {};
    const cookie = raw.Cookie || raw.cookie || '';
    const auth = raw.Authorization || raw.authorization || '';
    const seed = `${String(cookie || '')}\n${String(auth || '')}`;
    if (!seed.trim()) return '';
    try {
        return crypto.createHash('sha1').update(seed).digest('hex').slice(0, 12);
    } catch (_) {
        return '';
    }
}

function getQuarkSavedFileKey({ shareId, stoken, fid, fidToken, toPdirFid, rawHeader }) {
    const authKey = getQuarkAuthKey(rawHeader);
    const fromFile = quarkRuntime.fromFile || '';
    return [
        'quark_saved',
        String(shareId || ''),
        String(stoken || ''),
        String(fid || ''),
        String(fidToken || ''),
        String(toPdirFid || ''),
        authKey,
        fromFile,
    ].join('|');
}

function rememberQuarkSavedFile({ shareId, stoken, fid, fidToken, toPdirFid, rawHeader, savedFid, savedFidToken }) {
    pruneQuarkSavedFileCache();
    const sf = String(savedFid || '').trim();
    if (!sf) return;
    const key = getQuarkSavedFileKey({ shareId, stoken, fid, fidToken, toPdirFid, rawHeader });
    quarkSavedFileCache.map.set(key, { ts: Date.now(), fid: sf, token: String(savedFidToken || '').trim() });
}

function getRememberedQuarkSavedFile({ shareId, stoken, fid, fidToken, toPdirFid, rawHeader }) {
    pruneQuarkSavedFileCache();
    const key = getQuarkSavedFileKey({ shareId, stoken, fid, fidToken, toPdirFid, rawHeader });
    const entry = quarkSavedFileCache.map.get(key);
    if (!entry || typeof entry !== 'object') return null;
    const ts = typeof entry.ts === 'number' ? entry.ts : 0;
    if (!ts || Date.now() - ts > quarkSavedFileCache.ttlMs) return null;
    const savedFid = String(entry.fid || '').trim();
    if (!savedFid) return null;
    return { fid: savedFid, token: String(entry.token || '').trim() };
}

async function quarkDownloadUrlFromSavedFileViaApi({ savedFid, savedFidToken, rawHeader, scriptContext }) {
    const fetchImpl = globalThis.fetch;
    if (typeof fetchImpl !== 'function') throw new Error('fetch is not available');
    const QUARK_DEBUG = process.env.CATPAW_DEBUG === '1';
    const mask = (v) => {
        const s = String(v || '').trim();
        if (!s) return '';
        if (s.length <= 12) return s;
        return `${s.slice(0, 6)}...${s.slice(-6)}`;
    };
    const log = (...args) => {
        if (!QUARK_DEBUG) return;
        // eslint-disable-next-line no-console
        console.log('[quarkApi]', ...args);
    };

    const fid = String(savedFid || '').trim();
    if (!fid) throw new Error('missing saved fid');
    const token = String(savedFidToken || '').trim();

    const headers = {
        Accept: 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        Origin: 'https://pan.quark.cn',
        Referer: 'https://pan.quark.cn',
    };
    if (rawHeader && typeof rawHeader === 'object') {
        const ua = rawHeader['User-Agent'] || rawHeader['user-agent'];
        const ref = rawHeader.Referer || rawHeader.referer;
        const ck = rawHeader.Cookie || rawHeader.cookie;
        const auth = rawHeader.Authorization || rawHeader.authorization;
        if (typeof ua === 'string' && ua.trim()) headers['User-Agent'] = ua.trim();
        if (typeof ref === 'string' && ref.trim()) headers.Referer = ref.trim();
        if (typeof ck === 'string' && ck.trim()) headers.Cookie = ck.trim();
        if (typeof auth === 'string' && auth.trim()) headers.Authorization = auth.trim();
    }

    const dlUrl = 'https://drive.quark.cn/1/clouddrive/file/download?pr=ucpro&fr=pc';

    const fetchJsonWithText = async (url, init) => {
        const res = await fetchImpl(url, { redirect: 'manual', ...init });
        const text = await res.text();
        let data;
        try {
            data = text && text.trim() ? JSON.parse(text) : null;
        } catch (_) {
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
        return { data, text };
    };

    const extractDownloadUrl = (root, rawText) => {
        const isHttpUrl = (s) => {
            if (typeof s !== 'string') return false;
            const t = s.trim();
            if (!t) return false;
            if (t.startsWith('//')) return true;
            return /^https?:\/\//i.test(t);
        };
        const queue = [root];
        const seen = new Set();
        const maxNodes = 5000;
        let nodes = 0;
        while (queue.length && nodes < maxNodes) {
            const v = queue.shift();
            nodes += 1;
            if (!v) continue;
            if (typeof v === 'string') continue;
            if (typeof v !== 'object') continue;
            if (seen.has(v)) continue;
            seen.add(v);
            if (Array.isArray(v)) {
                for (const item of v) queue.push(item);
                continue;
            }
            for (const [k, val] of Object.entries(v)) {
                const key = String(k || '').toLowerCase();
                if ((key === 'download_url' || key === 'downloadurl' || key.endsWith('_download_url')) && isHttpUrl(val)) {
                    const t = String(val).trim();
                    return t.startsWith('//') ? `https:${t}` : t;
                }
                if (key.includes('download_url') && isHttpUrl(val)) {
                    const t = String(val).trim();
                    return t.startsWith('//') ? `https:${t}` : t;
                }
                if (typeof val === 'object' && val) queue.push(val);
                else if (typeof val === 'string' && key.includes('download_url') && isHttpUrl(val)) {
                    const t = val.trim();
                    return t.startsWith('//') ? `https:${t}` : t;
                }
            }
        }
        if (typeof rawText === 'string' && rawText.includes('download_url')) {
            const m = rawText.match(/"download_url"\s*:\s*"([^"]+)"/);
            if (m && isHttpUrl(m[1])) {
                const t = m[1].trim();
                return t.startsWith('//') ? `https:${t}` : t;
            }
        }
        return '';
    };

    const ctxHasWKt = !!(scriptContext && typeof scriptContext.WKt === 'function');
    const tryWktFallback = async () => {
        if (!ctxHasWKt) return { url: '', tokenCandidate: '', hint: '' };
        if (!scriptContext || typeof scriptContext.WKt !== 'function') return { url: '', tokenCandidate: '', hint: '' };
        const args = [token].map((x) => String(x || '').trim()).filter(Boolean);
        let lastNonUrl = '';
        let lastType = '';
        for (const arg of args) {
            try {
                const u = await scriptContext.WKt(arg);
                lastType = typeof u;
                if (typeof u === 'string') {
                    const trimmed = u.trim();
                    if (trimmed.startsWith('//')) return { url: `https:${trimmed}`, tokenCandidate: '', hint: '' };
                    if (/^https?:\/\//i.test(trimmed)) return { url: trimmed, tokenCandidate: '', hint: '' };
                    if (trimmed) lastNonUrl = trimmed;
                }
            } catch (e) {
                lastType = typeof e;
                lastNonUrl = String((e && e.message) || e || '').slice(0, 120);
            }
        }
        const hint = lastNonUrl ? `WKt returned non-url (${lastType}): ${lastNonUrl}` : '';
        return { url: '', tokenCandidate: lastNonUrl, hint };
    };

    const tokenCandidates = [];
    if (token) tokenCandidates.push(token);
    tokenCandidates.push('');

    const tryDownloadOnce = async (tkn) => {
        log('download(saved) try', { fid: mask(fid), token: mask(tkn || '') });
        const body = { fids: [fid] };
        if (tkn) {
            body.file_tokens = [tkn];
            body.fid_token_list = [tkn];
        }
        const { data: dlResp, text } = await fetchJsonWithText(dlUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
        });
        const url = extractDownloadUrl(dlResp && typeof dlResp === 'object' ? dlResp.data : dlResp, text) || extractDownloadUrl(dlResp, text);
        if (url) return url;
        return '';
    };

    for (const tkn of tokenCandidates) {
        const url = await tryDownloadOnce(tkn);
        if (url) return url;
    }

    const deadline = Date.now() + 8000;
    let attempt = 0;
    while (Date.now() < deadline) {
        const tkn = tokenCandidates[attempt % tokenCandidates.length];
        attempt += 1;
        const url = await tryDownloadOnce(tkn);
        if (url) return url;
        await new Promise((r) => setTimeout(r, 300));
    }

    if (ctxHasWKt) {
        const { url, tokenCandidate } = await tryWktFallback();
        if (url) return url;
        if (tokenCandidate) {
            const url2 = await tryDownloadOnce(tokenCandidate);
            if (url2) return url2;
        }
    }

    throw new Error(`quark download(saved): download_url not found (fid=${fid})`);
}

async function resolveQuarkDirectUrlCached({
    shareId,
    stoken,
    fid,
    fidToken,
    toPdirFid,
    rawHeader,
    scriptContext,
    want,
}) {
    pruneQuarkDirectUrlCache();

    const authKey = getQuarkAuthKey(rawHeader);
    const fromFile = quarkRuntime.fromFile || '';
    const wantMode = String(want || 'download_url').trim() || 'download_url';
    const key = [
        'quark',
        wantMode,
        String(shareId || ''),
        String(stoken || ''),
        String(fid || ''),
        String(fidToken || ''),
        String(toPdirFid || ''),
        authKey,
        fromFile,
    ].join('|');

    const now = Date.now();
    const existing = quarkDirectUrlCache.map.get(key);
    if (existing && typeof existing === 'object') {
        const ts = typeof existing.ts === 'number' ? existing.ts : 0;
        if (existing.url && ts && now - ts <= QUARK_DIRECT_URL_TTL_MS) return existing.url;
        if (existing.promise && typeof existing.promise.then === 'function') return await existing.promise;
    }

    const promise = (async () => {
        try {
            const url = await quarkResolveDownloadUrlViaApi({
                shareId,
                stoken,
                fid,
                fidToken,
                toPdirFid,
                rawHeader,
                scriptContext,
                want: wantMode,
            });
            quarkDirectUrlCache.map.set(key, { ts: Date.now(), url: String(url || ''), promise: null });
            return url;
        } catch (err) {
            quarkDirectUrlCache.map.delete(key);
            throw err;
        }
    })();

    quarkDirectUrlCache.map.set(key, { ts: now, url: '', promise });
    return await promise;
}

function pruneBaiduProxyMap() {
    const now = Date.now();
    for (const [token, entry] of baiduProxyState.map.entries()) {
        if (!entry || typeof entry !== 'object') {
            baiduProxyState.map.delete(token);
            continue;
        }
        const ts = typeof entry.ts === 'number' ? entry.ts : 0;
        if (!ts || now - ts > BAIDU_PROXY_TTL_MS) baiduProxyState.map.delete(token);
    }
}

function putBaiduProxyEntry(url, headers) {
    pruneBaiduProxyMap();
    const tokenBytes = crypto.randomBytes(12);
    const token = tokenBytes.toString('hex');
    baiduProxyState.map.set(token, { url, headers, ts: Date.now() });
    return token;
}

function getBaiduProxyEntry(token) {
    pruneBaiduProxyMap();
    const entry = baiduProxyState.map.get(token);
    if (!entry || typeof entry !== 'object' || !entry.url) return null;
    // Sliding expiration: refresh token lifetime on access so long videos don't require a re-play within 60min.
    entry.ts = Date.now();
    baiduProxyState.map.set(token, entry);
    return entry;
}

export function registerGlobalBaiduProxy(fastify) {
    if (!fastify) return;
    if (baiduProxyState.registered) return;
    baiduProxyState.registered = true;

    const sendProxy = async (req, reply, targetUrl, headers) => {
        const hopByHop = new Set([
            'connection',
            'keep-alive',
            'proxy-authenticate',
            'proxy-authorization',
            'te',
            'trailer',
            'transfer-encoding',
            'upgrade',
        ]);

        const follow = async (urlStr, redirectsLeft) => {
            const urlObj = new URL(urlStr);
            const client = urlObj.protocol === 'https:' ? https : http;
            return await new Promise((resolve, reject) => {
                const upstreamReq = client.request(
                    urlObj,
                    {
                        method: 'GET',
                        headers,
                    },
                    (upRes) => {
                        const status = Number(upRes.statusCode || 0);
                        const loc = upRes.headers && upRes.headers.location ? String(upRes.headers.location) : '';
                        const isRedirect = status >= 300 && status < 400 && !!loc;
                        if (isRedirect && redirectsLeft > 0) {
                            upRes.resume();
                            upRes.on('end', () => {
                                try {
                                    const nextUrl = new URL(loc, urlObj).toString();
                                    resolve({ redirect: nextUrl });
                                } catch (e) {
                                    reject(e);
                                }
                            });
                            return;
                        }
                        resolve({ res: upRes });
                    }
                );

                const abort = () => {
                    try {
                        upstreamReq.destroy();
                    } catch (_) {}
                };
                try {
                    req.raw.once('close', abort);
                    req.raw.once('aborted', abort);
                } catch (_) {}

                upstreamReq.setTimeout(600000, () => {
                    upstreamReq.destroy(new Error('Upstream timeout'));
                });
                upstreamReq.on('error', reject);
                upstreamReq.end();
            }).then(async (out) => {
                if (out && out.redirect) return await follow(out.redirect, redirectsLeft - 1);
                return out;
            });
        };

        let upstream;
        try {
            upstream = await follow(targetUrl, 10);
        } catch (err) {
            const msg = (err && err.message) || String(err);
            reply.code(502);
            return { statusCode: 502, error: 'Bad Gateway', message: `Baidu proxy request failed: ${msg}` };
        }

        const upRes = upstream && upstream.res ? upstream.res : null;
        if (!upRes) {
            reply.code(502);
            return { statusCode: 502, error: 'Bad Gateway', message: 'Baidu proxy request failed: empty response' };
        }

        // Use a hijacked raw stream pipe to avoid situations where Fastify ends the response without piping
        // upstream bytes (observed as `206` with `content-length: 0` and no download progress).
        try {
            reply.hijack();
        } catch (_) {}

        const status = Number(upRes.statusCode || 200) || 200;
        try {
            reply.raw.statusCode = status;
        } catch (_) {}

        // CORS headers
        try {
            reply.raw.setHeader('Access-Control-Allow-Origin', '*');
            reply.raw.setHeader('Access-Control-Allow-Headers', 'Range, If-Range, Content-Type');
            reply.raw.setHeader('Access-Control-Expose-Headers', 'Accept-Ranges, Content-Range, Content-Length');
            reply.raw.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        } catch (_) {}

        // Upstream headers
        try {
            const h = upRes.headers || {};
            Object.keys(h).forEach((k) => {
                const key = String(k || '');
                const lower = key.toLowerCase();
                if (!key) return;
                if (lower.startsWith('access-control-')) return;
                if (hopByHop.has(lower)) return;
                if (lower === 'cache-control' || lower === 'pragma' || lower === 'expires') return;
                try {
                    reply.raw.setHeader(key, h[k]);
                } catch (_) {}
            });
        } catch (_) {}

        // Force no-cache for streaming proxies to prevent intermediaries from caching a single range and reusing it.
        try {
            reply.raw.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
            reply.raw.setHeader('Pragma', 'no-cache');
            reply.raw.setHeader('Expires', '0');
            reply.raw.setHeader('X-Accel-Buffering', 'no');
        } catch (_) {}

        try {
            if (reply && reply.raw && typeof reply.raw.flushHeaders === 'function') reply.raw.flushHeaders();
        } catch (_) {}

        try {
            const onAbort = () => {
                try {
                    upRes.destroy();
                } catch (_) {}
            };
            req.raw.once('close', onAbort);
            req.raw.once('aborted', onAbort);
        } catch (_) {}

        upRes.on('error', () => {
            try {
                reply.raw.destroy();
            } catch (_) {}
        });
        upRes.on('end', () => {
            try {
                reply.raw.end();
            } catch (_) {}
        });
        upRes.on('data', (chunk) => {
            try {
                const ok = reply.raw.write(chunk);
                if (!ok) upRes.pause();
            } catch (_) {}
        });
        reply.raw.on('drain', () => {
            try {
                upRes.resume();
            } catch (_) {}
        });
        try {
            upRes.resume();
        } catch (_) {}
        return;
    };

    fastify.route({
        method: 'OPTIONS',
        url: '/spider/proxy/baidu/:token',
        handler: async (_req, reply) => {
            try {
                reply.header('Access-Control-Allow-Origin', '*');
                reply.header('Access-Control-Allow-Headers', 'Range, If-Range, Content-Type');
                reply.header('Access-Control-Expose-Headers', 'Accept-Ranges, Content-Range, Content-Length');
                reply.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
            } catch (_) {}
            reply.code(204);
            return '';
        },
    });

    fastify.route({
        method: 'GET',
        url: '/spider/proxy/baidu/:token',
        handler: async (req, reply) => {
            let token = String((req.params && req.params.token) || '').trim();
            token = token.replace(/\.(mp4|bin)$/i, '').trim();
            if (!token) {
                reply.code(400);
                return { statusCode: 400, error: 'Bad Request', message: 'Missing token' };
            }

            const entry = getBaiduProxyEntry(token);
            if (!entry) {
                reply.code(410);
                return { statusCode: 410, error: 'Gone', message: 'Proxy token expired' };
            }

            const target = String(entry.url || '');
            if (!/^https?:\/\//i.test(target)) {
                baiduProxyState.map.delete(token);
                reply.code(400);
                return { statusCode: 400, error: 'Bad Request', message: 'Invalid url' };
            }

            const outHeaders = {};
            try {
                const raw = entry.headers && typeof entry.headers === 'object' ? entry.headers : {};
                const ua = raw['User-Agent'] || raw['user-agent'];
                const ref = raw.Referer || raw.referer;
                const ck = raw.Cookie || raw.cookie;
                if (typeof ua === 'string' && ua.trim()) outHeaders['User-Agent'] = ua.trim();
                if (typeof ref === 'string' && ref.trim()) outHeaders.Referer = ref.trim();
                if (typeof ck === 'string' && ck.trim()) outHeaders.Cookie = ck.trim();
            } catch (_) {}
            outHeaders.Accept = '*/*';
            outHeaders['Accept-Encoding'] = 'identity';

            // If a baidu cookie is configured globally, use it as fallback.
            try {
                if (!outHeaders.Cookie) {
                    const cookie = fastify && fastify.config && fastify.config.baidu ? fastify.config.baidu.cookie : '';
                    if (typeof cookie === 'string' && cookie.trim()) outHeaders.Cookie = cookie.trim();
                }
            } catch (_) {}

            const range = req.headers && req.headers.range ? String(req.headers.range) : '';
            if (range) outHeaders.Range = range;
            const ifRange = req.headers && req.headers['if-range'] ? String(req.headers['if-range']) : '';
            if (ifRange) outHeaders['If-Range'] = ifRange;

            return await sendProxy(req, reply, target, outHeaders);
        },
    });
}

function getPansListCached() {
    const root = readDbJsonSafeCached();
    const list = root && root.pans && typeof root.pans === 'object' && Array.isArray(root.pans.list) ? root.pans.list : null;
    return Array.isArray(list) ? list : null;
}

function getDbJsonPath() {
    if (!getDbJsonPath.state) getDbJsonPath.state = { path: '', ts: 0 };
    const state = getDbJsonPath.state;
    const now = Date.now();
    if (state.path) {
        try {
            if (fs.existsSync(state.path)) return state.path;
        } catch (_) {}
        if (now - state.ts < 2000) return state.path;
    }

    const p = path.resolve(process.cwd(), 'db.json');
    state.path = p;
    state.ts = now;
    return p;
}

function readDbJsonSafeCached() {
    const dbPath = getDbJsonPath();
    try {
        const st = fs.statSync(dbPath);
        if (dbJsonCache.path === dbPath && dbJsonCache.mtimeMs === st.mtimeMs && dbJsonCache.size === st.size) {
            return dbJsonCache.data;
        }
        const raw = fs.readFileSync(dbPath, 'utf8');
        const parsed = raw && raw.trim() ? JSON.parse(raw) : null;
        dbJsonCache.path = dbPath;
        dbJsonCache.mtimeMs = st.mtimeMs;
        dbJsonCache.size = st.size;
        dbJsonCache.data = parsed && typeof parsed === 'object' ? parsed : null;
        return dbJsonCache.data;
    } catch (_) {
        dbJsonCache.path = dbPath;
        dbJsonCache.mtimeMs = 0;
        dbJsonCache.size = 0;
        dbJsonCache.data = null;
        return null;
    }
}

function findPanCookieInDbJson(panKey) {
    const root = readDbJsonSafeCached();
    if (!root || typeof root !== 'object') return '';
    const pan = String(panKey || '').trim().toLowerCase();
    if (!pan) return '';

    const tryGet = (obj, keys) => {
        let cur = obj;
        for (const k of keys) {
            if (!cur || typeof cur !== 'object') return '';
            cur = cur[k];
        }
        return typeof cur === 'string' ? cur.trim() : '';
    };

    let cookie = '';
    // Common layouts.
    cookie = tryGet(root, [panKey, 'cookie']) || tryGet(root, [pan, 'cookie']) || tryGet(root, ['pans', pan, 'cookie']);
    if (cookie) return cookie;
    cookie = tryGet(root, [panKey, 'ck']) || tryGet(root, [pan, 'ck']) || tryGet(root, ['pans', pan, 'ck']);
    if (cookie) return cookie;

    // Common "token-hash -> cookie" layout (used by some bundles / website UIs):
    // {
    //   "quark": { "<md5(token)>": "a=b; c=d; ..." },
    //   "uc":    { "<md5(token)>": "..." }
    // }
    const looksLikeCookieString = (s) => {
        const v = typeof s === 'string' ? s.trim() : '';
        if (!v) return false;
        // Cookies are typically long and contain key=value pairs separated by ';'
        if (!v.includes('=') || !v.includes(';')) return false;
        if (v.length < 30) return false;
        return true;
    };
    const looksLikeQuarkCookie = (s) => {
        const v = typeof s === 'string' ? s : '';
        return (
            looksLikeCookieString(v) &&
            (v.includes('__puus=') || v.includes('__pus=') || v.includes('ctoken=') || v.includes('b-user-id=') || v.includes('isQuark='))
        );
    };
    const looksLikeUcCookie = (s) => {
        const v = typeof s === 'string' ? s : '';
        // UC cookie formats vary; keep it permissive.
        return looksLikeCookieString(v) && (v.includes('uc') || v.includes('UC') || v.includes('__puus=') || v.includes('utoken='));
    };
    const pickLongest = (arr) =>
        arr
            .filter((v) => typeof v === 'string')
            .map((v) => v.trim())
            .filter(Boolean)
            .sort((a, b) => b.length - a.length)[0] || '';
    const pickFromMap = (obj, panName) => {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return '';
        const vals = [];
        for (const v of Object.values(obj)) {
            if (typeof v !== 'string') continue;
            const s = v.trim();
            if (!s) continue;
            if (panName === 'quark') {
                if (looksLikeQuarkCookie(s)) vals.push(s);
            } else if (panName === 'uc') {
                if (looksLikeUcCookie(s)) vals.push(s);
            } else {
                if (looksLikeCookieString(s)) vals.push(s);
            }
        }
        return vals.length ? pickLongest(vals) : '';
    };
    // Try both exact key and normalized key.
    try {
        cookie = pickFromMap(root[panKey], pan);
        if (cookie) return cookie;
    } catch (_) {}
    try {
        cookie = pickFromMap(root[pan], pan);
        if (cookie) return cookie;
    } catch (_) {}

    // pans.list = [{key, cookie, ...}]
    try {
        const list = root && root.pans && typeof root.pans === 'object' ? root.pans.list : null;
        if (Array.isArray(list)) {
            for (const it of list) {
                if (!it || typeof it !== 'object') continue;
                const k = String(it.key || it.id || it.pan || '').trim().toLowerCase();
                if (k !== pan) continue;
                const c = typeof it.cookie === 'string' ? it.cookie.trim() : '';
                if (c) return c;
            }
        }
    } catch (_) {}

    return '';
}

export function getCustomSourceStatus() {
    return {
        loader: {
            node: process.version,
            supportsCompileFunction: typeof vm.compileFunction === 'function',
        },
        quarkResolver: {
            hasWKt: !!(quarkRuntime.ctx && typeof quarkRuntime.ctx.WKt === 'function'),
            fromFile: quarkRuntime.fromFile || '',
            directUrlCache: {
                ttlMs: QUARK_DIRECT_URL_TTL_MS,
                size: quarkDirectUrlCache.map.size,
            },
        },
        dirPath: cache.dirPath,
        files: cache.files.slice(),
        count: Array.isArray(cache.spiders) ? cache.spiders.length : 0,
        errors: cache.errors || {},
        byFile: cache.byFile || {},
        webPlugins: Array.isArray(cache.webPlugins) ? cache.webPlugins.length : 0,
        webErrors: cache.webErrors || {},
        webByFile: cache.webByFile || {},
        websiteBundles: Array.isArray(cache.websiteBundles) ? cache.websiteBundles.length : 0,
        websiteErrors: cache.websiteErrors || {},
        websiteByFile: cache.websiteByFile || {},
    };
}

export function getCustomSourceWebPlugins() {
    return Array.isArray(cache.webPlugins) ? cache.webPlugins : [];
}

export function getCustomSourceWebsiteBundles() {
    return Array.isArray(cache.websiteBundles) ? cache.websiteBundles : [];
}

function isSpiderLike(value) {
    if (!value || typeof value !== 'object') return false;
    if (typeof value.api !== 'function') return false;
    if (!value.meta || typeof value.meta !== 'object') return false;
    if (typeof value.meta.key !== 'string' || !value.meta.key.trim()) return false;
    if (typeof value.meta.name !== 'string' || !value.meta.name.trim()) return false;
    if (!Number.isFinite(Number(value.meta.type))) return false;
    return true;
}

function collectSpidersDeep(seedValues) {
    const spiders = [];
    const visited = new Set();
    const queue = Array.isArray(seedValues) ? seedValues.slice() : [seedValues];

    const enqueue = (val) => {
        if (!val) return;
        const t = typeof val;
        if (t !== 'object' && t !== 'function') return;
        if (visited.has(val)) return;
        visited.add(val);
        queue.push(val);
    };

    while (queue.length) {
        const current = queue.shift();
        if (!current) continue;

        if (isSpiderLike(current)) {
            spiders.push(current);
            continue;
        }

        if (Array.isArray(current)) {
            if (current.length > 200) continue;
            current.forEach(enqueue);
            continue;
        }

        if (current instanceof Date) continue;
        if (current instanceof RegExp) continue;
        if (Buffer.isBuffer(current)) continue;

        let values;
        try {
            const keys = Object.keys(current);
            if (keys.length > 200) continue;
            values = keys.map((k) => current[k]);
        } catch (_) {
            values = null;
        }
        if (values) values.forEach(enqueue);
    }

    const uniq = new Map();
    spiders.forEach((s) => {
        const key = s.meta.key;
        const type = String(s.meta.type);
        const id = `${key}:${type}`;
        if (!uniq.has(id)) uniq.set(id, s);
    });
    return Array.from(uniq.values());
}

function resolveCustomSourceDirCandidates() {
    const candidates = [];
    const externalRoot = getExternalRootDir();
    if (externalRoot) candidates.push(path.resolve(externalRoot, 'custom_spider'));
    candidates.push(path.resolve(getEmbeddedRootDir(), 'custom_spider'));
    candidates.push(path.resolve(process.cwd(), 'custom_spider'));
    return Array.from(new Set(candidates.filter(Boolean)));
}

function listCustomScriptFiles(dirPath) {
    if (!dirPath || !fs.existsSync(dirPath)) return [];
    const out = [];
    const stack = [dirPath];
    while (stack.length) {
        const cur = stack.pop();
        let entries;
        try {
            entries = fs.readdirSync(cur, { withFileTypes: true });
        } catch (_) {
            continue;
        }
        entries.forEach((ent) => {
            const name = ent.name || '';
            if (!name || name.startsWith('.') || name.startsWith('_')) return;
            const full = path.join(cur, name);
            if (ent.isDirectory()) {
                stack.push(full);
                return;
            }
            if (!ent.isFile()) return;
            const lower = name.toLowerCase();
            if (!(lower.endsWith('.js') || lower.endsWith('.mjs') || lower.endsWith('.cjs'))) return;
            out.push(full);
        });
    }
    return out.sort((a, b) => a.localeCompare(b, 'en'));
}

function unwrapIife(bundleCode) {
    if (typeof bundleCode !== 'string') return '';
    const startIdx = bundleCode.indexOf('(function');
    if (startIdx < 0) return '';
    const openBraceIdx = bundleCode.indexOf('{', startIdx);
    if (openBraceIdx < 0) return '';
    let closeIdx = bundleCode.lastIndexOf('})();');
    if (closeIdx < 0) closeIdx = bundleCode.lastIndexOf('})()');
    if (closeIdx < 0) return '';
    if (closeIdx <= openBraceIdx) return '';
    return bundleCode.slice(openBraceIdx + 1, closeIdx);
}

function detectWebPluginSymbols(bundleCode) {
    if (typeof bundleCode !== 'string' || !bundleCode) return new Map();
    const targets = ['/website', '/imageProxy', '/danmu', '/danmusearch', '/danmuput'];
    const map = new Map();

    const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const findLast = (re, input) => {
        let m = null;
        let last = null;
        // eslint-disable-next-line no-cond-assign
        while ((m = re.exec(input))) last = m;
        return last;
    };

    targets.forEach((prefix) => {
        const escaped = escapeRe(prefix);
        const re = new RegExp(
            `\\.register\\(\\s*([A-Za-z_$][\\w$]*)\\s*,\\s*\\{[^}]*\\bprefix\\s*:\\s*['\\"]${escaped}['\\"][^}]*\\}\\s*\\)`,
            'g'
        );
        const last = findLast(re, bundleCode);
        if (last && last[1]) map.set(prefix, last[1]);
    });

    return map;
}

function extractIifeBodyWithAcorn(bundleCode, requireFunc) {
    if (typeof bundleCode !== 'string' || !bundleCode.trim()) return '';
    let acorn;
    try {
        acorn = requireFunc('acorn');
    } catch (_) {
        acorn = null;
    }
    if (!acorn || typeof acorn.parseExpressionAt !== 'function') return '';

    const firstNonWs = bundleCode.search(/\S/);
    if (firstNonWs < 0) return '';

    let expr;
    try {
        expr = acorn.parseExpressionAt(bundleCode, firstNonWs, { ecmaVersion: 'latest' });
    } catch (_) {
        expr = null;
    }
    if (!expr) return '';

    const getBodyNode = (fnNode) => {
        if (!fnNode) return null;
        const body = fnNode.body;
        return body && body.type === 'BlockStatement' ? body : null;
    };

    let bodyNode = null;
    if (expr.type === 'CallExpression') {
        bodyNode = getBodyNode(expr.callee);
    } else if (expr.type === 'FunctionExpression' || expr.type === 'ArrowFunctionExpression') {
        bodyNode = getBodyNode(expr);
    }
    if (!bodyNode || typeof bodyNode.start !== 'number' || typeof bodyNode.end !== 'number') return '';
    if (bodyNode.end <= bodyNode.start + 2) return '';
    return bundleCode.slice(bodyNode.start + 1, bodyNode.end - 1);
}

function extractWebsiteWebPlugins(websiteBundleFn, requireFunc, filePath) {
    if (typeof websiteBundleFn !== 'function') return [];
    let bundleCode = '';
    try {
        bundleCode = websiteBundleFn();
    } catch (err) {
        const msg = (err && err.message) || String(err);
        throw new Error(`websiteBundle() threw: ${msg}`);
    }
    if (typeof bundleCode !== 'string' || !bundleCode.trim()) {
        throw new Error('websiteBundle() returned empty content');
    }
    const detected = detectWebPluginSymbols(bundleCode);
    // Some bundles are not immediately invoked; reliably extract the wrapper function body via the JS engine.
    let inner = extractIifeBodyWithAcorn(bundleCode, requireFunc);
    // Fallback to heuristic for legacy bundles.
    if (!inner.trim()) inner = unwrapIife(bundleCode);
    if (!inner.trim()) {
        throw new Error('websiteBundle parse failed: cannot extract IIFE body');
    }

    const ctx = buildVmContext(requireFunc, filePath);
    try {
        ctx.websiteBundle = websiteBundleFn;
        ctx.globalThis.websiteBundle = websiteBundleFn;
    } catch (_) {}

    // Provide minimal browser-like globals so mixed (web+node) bundles can be evaluated enough to expose route plugins.
    // This does NOT attempt to run the UI; it only prevents crashes from top-level references.
    try {
        if (!ctx.React) {
            ctx.React = {
                createContext: () => ({}),
                createElement: () => null,
                useState: () => [null, () => {}],
                useEffect: () => {},
                useMemo: (fn) => (typeof fn === 'function' ? fn() : null),
                useCallback: (fn) => fn,
                useRef: () => ({ current: null }),
            };
        }
        if (!ctx.ReactDOM) {
            ctx.ReactDOM = {
                createRoot: () => ({ render: () => {} }),
                hydrateRoot: () => ({ render: () => {} }),
            };
        }
        if (!ctx.antd) ctx.antd = {};
        if (!ctx.axios) {
            const noop = async () => ({ data: null, status: 200, headers: {} });
            ctx.axios = Object.assign(noop, {
                create: () => ({ get: noop, post: noop, put: noop, delete: noop, request: noop, defaults: {} }),
                get: noop,
                post: noop,
                put: noop,
                delete: noop,
            });
        }
        if (!ctx.dayjs) ctx.dayjs = () => ({ format: () => '' });
        if (!ctx.navigator) ctx.navigator = { userAgent: 'node' };
        if (!ctx.document) {
            ctx.document = {
                getElementById: () => ({}),
                createElement: () => ({ style: {}, addEventListener: () => {}, setAttribute: () => {} }),
                createRange: () => ({ selectNodeContents: () => {} }),
                getSelection: () => ({
                    rangeCount: 0,
                    removeAllRanges: () => {},
                    addRange: () => {},
                    type: '',
                    removeRange: () => {},
                }),
                body: { appendChild: () => {}, removeChild: () => {} },
            };
        }
        if (!ctx.window) ctx.window = ctx;
        ctx.window.React = ctx.React;
        ctx.window.ReactDOM = ctx.ReactDOM;
        ctx.window.antd = ctx.antd;
        ctx.window.axios = ctx.axios;
        ctx.window.dayjs = ctx.dayjs;
        ctx.window.navigator = ctx.navigator;
        ctx.window.document = ctx.document;
        if (!ctx.prompt) ctx.prompt = () => null;
        if (!ctx.clipboardData) ctx.clipboardData = { clearData: () => {}, setData: () => {} };
    } catch (_) {}

    const candidates = new Map();
    const addCandidate = (prefix, symbol) => {
        if (!prefix || typeof prefix !== 'string') return;
        if (!symbol || typeof symbol !== 'string') return;
        candidates.set(prefix, symbol);
    };

    // Known names used by earlier scripts.
    addCandidate('/website', 'Yne');
    addCandidate('/imageProxy', 'XUe');
    addCandidate('/danmu', '$Ue');
    addCandidate('/danmusearch', 'Xne');
    addCandidate('/danmuput', 'ZUe');

    // Also accept renamed/minified symbols detected from `.register(fn, {prefix:"/xxx"})`.
    for (const [prefix, symbol] of detected.entries()) addCandidate(prefix, symbol);

    // Compile as a function to allow top-level `return` statements in the bundle body.
    // Use `try/finally` to ensure we always capture candidates even if the bundle returns early.
    const captureLines = ['globalThis.__cp_web_plugins = globalThis.__cp_web_plugins || {};'];
    for (const [prefix, symbol] of candidates.entries()) {
        captureLines.push(
            `try { globalThis.__cp_web_plugins[${JSON.stringify(prefix)}] = (${symbol}); } catch (e) {}`
        );
    }
    const compiled = vm.compileFunction(`try {\n${inner}\n} finally {\n${captureLines.join('\n')}\n}`, [], {
        parsingContext: ctx,
        filename: `${filePath}:websiteBundle`,
    });
    compiled();

    const captured = ctx.__cp_web_plugins || (ctx.globalThis && ctx.globalThis.__cp_web_plugins) || {};
    const plugins = [];
    for (const [prefix, symbol] of candidates.entries()) {
        const fn = captured[prefix];
        if (typeof fn !== 'function') continue;
        plugins.push({ prefix, plugin: fn, symbol });
    }

    if (!plugins.length) {
        const prefixes = Array.from(candidates.keys());
        throw new Error(
            `websiteBundle executed but no web plugins found (candidate prefixes: ${prefixes.join(',') || 'none'})`
        );
    }

    return plugins;
}

function buildVmContext(requireFunc, filePath) {
    const { URL, URLSearchParams, TextEncoder, TextDecoder } = globalThis;

    let webStreams = {};
    try {
        try {
            webStreams = requireFunc('node:stream/web');
        } catch (_) {
            webStreams = requireFunc('stream/web');
        }
    } catch (_) {
        webStreams = {};
    }
    const ReadableStream = globalThis.ReadableStream || webStreams.ReadableStream;
    const WritableStream = globalThis.WritableStream || webStreams.WritableStream;
    const TransformStream = globalThis.TransformStream || webStreams.TransformStream;
    const TextEncoderStream = globalThis.TextEncoderStream || webStreams.TextEncoderStream;
    const TextDecoderStream = globalThis.TextDecoderStream || webStreams.TextDecoderStream;

    let undici = null;
    try {
        undici = requireFunc('undici');
    } catch (_) {
        undici = null;
    }

    let bufferBlob = null;
    try {
        bufferBlob = requireFunc('buffer').Blob;
    } catch (_) {
        bufferBlob = null;
    }

    const fetch = globalThis.fetch || (undici && undici.fetch);
    const Headers = globalThis.Headers || (undici && undici.Headers);
    const Request = globalThis.Request || (undici && undici.Request);
    const Response = globalThis.Response || (undici && undici.Response);
    const FormData = globalThis.FormData || (undici && undici.FormData);
    const Blob = globalThis.Blob || bufferBlob || (undici && undici.Blob);
    const AbortController = globalThis.AbortController || (undici && undici.AbortController);
    const AbortSignal = globalThis.AbortSignal || (undici && undici.AbortSignal);
    const DOMException = globalThis.DOMException || (undici && undici.DOMException);
    const queueMicrotask = globalThis.queueMicrotask || ((fn) => Promise.resolve().then(fn));
    const crypto = globalThis.crypto;
    const structuredClone = globalThis.structuredClone;
    const performance = globalThis.performance;
    const setImmediate = globalThis.setImmediate;
    const clearImmediate = globalThis.clearImmediate;
    const EventTarget = globalThis.EventTarget;
    const CustomEvent = globalThis.CustomEvent;
    const Event =
        globalThis.Event ||
        (function () {
            function Event(type, init) {
                this.type = String(type || '');
                this.bubbles = !!(init && init.bubbles);
                this.cancelable = !!(init && init.cancelable);
                this.composed = !!(init && init.composed);
                this.defaultPrevented = false;
                this.target = null;
                this.currentTarget = null;
                this.eventPhase = 0;
                this.timeStamp = Date.now();
            }
            Event.prototype.preventDefault = function () {
                if (this.cancelable) this.defaultPrevented = true;
            };
            Event.prototype.stopPropagation = function () {};
            Event.prototype.stopImmediatePropagation = function () {};
            return Event;
        })();

    const filename = filePath ? path.resolve(filePath) : '';
    const dirname = filename ? path.dirname(filename) : process.cwd();

    const baseMessageToDart = async () => [];
    const ctx = {
        console,
        process,
        Buffer,
        __filename: filename,
        __dirname: dirname,
        URL,
        URLSearchParams,
        TextEncoder,
        TextDecoder,
        ReadableStream,
        WritableStream,
        TransformStream,
        TextEncoderStream,
        TextDecoderStream,
        fetch,
        Headers,
        Request,
        Response,
        FormData,
        Blob,
        AbortController,
        AbortSignal,
        DOMException,
        queueMicrotask,
        crypto,
        structuredClone,
        performance,
        setImmediate,
        clearImmediate,
        Event,
        EventTarget,
        CustomEvent,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        atob: (s) => Buffer.from(String(s || ''), 'base64').toString('binary'),
        btoa: (s) => Buffer.from(String(s || ''), 'binary').toString('base64'),
        require: requireFunc,
        module: { exports: {} },
        exports: {},
        // Some bundles keep cookies in a global string (e.g. `Wo`) and call `.replace(...)` on it.
        // Initialize to empty string to avoid TypeError when no cookie is set yet.
        Wo: '',
        // Some custom bundles call `messageToDart(...)` directly (not via fastify instance).
        // In server-only mode there is no Dart side; keep it as a safe noop.
        messageToDart: baseMessageToDart,
        // Some custom bundles assume the app runtime provides global pan helpers.
        // Provide safe defaults so video spiders can parse/share pan links without crashing.
        Pans: getPansListCached() || [],
        getPanName: (key) => {
            const k = String(key || '');
            const list = getPansListCached() || globalThis.Pans || [];
            const found = Array.isArray(list) ? list.find((it) => it && String(it.key) === k) : null;
            if (found && typeof found.name === 'string' && found.name) return found.name;
            const defaults = {
                ali: '阿里',
                quark: '夸克',
                uc: 'UC',
                tianyi: '天翼',
                yidong: '移动',
                baidu: '百度',
                '123': 'Pan123',
                '115': 'Pan115',
                '123miao': '123原画(秒传)',
            };
            return defaults[k] || k;
        },
        getPanEnabled: (key) => {
            const k = String(key || '');
            const list = getPansListCached() || globalThis.Pans || [];
            const found = Array.isArray(list) ? list.find((it) => it && String(it.key) === k) : null;
            if (found && typeof found.enable === 'boolean') return found.enable;
            return true;
        },
        catServerFactory: () => {
            throw new Error('catServerFactory is not available in custom_source spider loader');
        },
        catDartServerPort: () => 0,
    };
    const context = vm.createContext(ctx);
    // Ensure `globalThis` inside vm points to the contextified global object.
    try {
        context.globalThis = context;
        context.global = context;
        context.window = context;
    } catch (_) {}

    // Prevent scripts from overwriting critical shims.
    try {
        Object.defineProperty(context, 'messageToDart', {
            value: baseMessageToDart,
            writable: false,
            configurable: false,
            enumerable: true,
        });
        Object.defineProperty(context.globalThis, 'messageToDart', {
            value: baseMessageToDart,
            writable: false,
            configurable: false,
            enumerable: true,
        });
    } catch (_) {}
    return context;
}

function sameFiles(prevFiles, nextFiles) {
    if (!Array.isArray(prevFiles) || !Array.isArray(nextFiles)) return false;
    if (prevFiles.length !== nextFiles.length) return false;
    for (let i = 0; i < prevFiles.length; i += 1) {
        if (prevFiles[i].path !== nextFiles[i].path) return false;
        if (prevFiles[i].mtimeMs !== nextFiles[i].mtimeMs) return false;
        // Some file sync tools may preserve mtime; include size to avoid stale cache.
        if (prevFiles[i].size !== nextFiles[i].size) return false;
    }
    return true;
}

function collectFileStats(filePaths) {
    return filePaths
        .map((p) => {
            try {
                const st = fs.statSync(p);
                return { path: p, mtimeMs: st.mtimeMs, size: st.size };
            } catch (_) {
                return null;
            }
        })
        .filter(Boolean);
}

async function loadOneFile(filePath) {
    const manifest = readCustomScriptManifest(filePath) || null;
    const scriptEnabled = manifest && Object.prototype.hasOwnProperty.call(manifest, 'enabled') ? !!manifest.enabled : true;
    const scriptFormat = normalizeCustomScriptFormat(manifest && manifest.format);
    if (!scriptEnabled) {
        return { spiders: [], webPlugins: [], webError: 'disabled by manifest', websiteJs: '' };
    }

    if (scriptFormat === 'esm' || scriptFormat === 'cjs') {
        try {
            let mod = null;
            if (scriptFormat === 'esm') {
                const href = pathToFileURL(filePath).href;
                // Bypass ESM import cache when the file changes.
                const st = fs.statSync(filePath);
                mod = await import(`${href}?mtime=${encodeURIComponent(String(st.mtimeMs))}`);
            } else {
                const req = createRequire(filePath);
                mod = req(filePath);
            }

            const seed = [];
            if (mod && typeof mod === 'object') seed.push(mod);
            if (mod && typeof mod === 'object') seed.push(...Object.values(mod));

            const spiders = collectSpidersDeep(seed).map((spider) => {
                try {
                    if (spider && typeof spider === 'object') {
                        // Will be overwritten by outer loader with the relative path within custom_spider dir.
                        spider.__customFile = path.basename(filePath);
                        spider.__customFormat = scriptFormat;
                    }
                } catch (_) {}
                return spider;
            });

            // Optional exports for non-bundled scripts.
            const webPlugins = [];
            let webError = '';
            try {
                const exportedWebPlugins =
                    (mod && mod.webPlugins) || (mod && mod.default && mod.default.webPlugins) || null;
                if (Array.isArray(exportedWebPlugins)) {
                    exportedWebPlugins.forEach((p) => {
                        if (!p || typeof p !== 'object') return;
                        if (typeof p.prefix !== 'string' || !p.prefix) return;
                        if (typeof p.plugin !== 'function') return;
                        webPlugins.push({ prefix: p.prefix, plugin: p.plugin });
                    });
                }
            } catch (e) {
                webError = (e && e.message) || String(e);
            }

            let websiteJs = '';
            try {
                const websiteBundle = (mod && mod.websiteBundle) || (mod && mod.default && mod.default.websiteBundle) || null;
                if (typeof websiteBundle === 'string') websiteJs = websiteBundle;
                else if (typeof websiteBundle === 'function') websiteJs = String(websiteBundle() || '');
            } catch (_) {}

            return { spiders, webPlugins, webError, websiteJs };
        } catch (err) {
            const msg = (err && err.message) || String(err);
            return { spiders: [], webPlugins: [], webError: `load ${scriptFormat} failed: ${msg}`, websiteJs: '' };
        }
    }

    const code = fs.readFileSync(filePath, 'utf8');
    const baseRequire = createRequire(filePath);

    const BAIDU_DEBUG = process.env.CATPAW_DEBUG === '1';
    const baiduLog = (...args) => {
        if (!BAIDU_DEBUG) return;
        // eslint-disable-next-line no-console
        console.log('[baidu]', ...args);
    };
    const baiduDebugState = { ts: 0 };

    const buildHttpProxy = (mod, scheme) => {
        const normalizeOpts = (opts) => {
            const o = opts && typeof opts === 'object' ? opts : {};
            const headers = (o.headers && typeof o.headers === 'object' ? o.headers : {});

            const getHeader = (name) => {
                const lower = String(name || '').toLowerCase();
                for (const [k, v] of Object.entries(headers)) {
                    if (String(k || '').toLowerCase() === lower) return v;
                }
                return undefined;
            };
            const deleteHeader = (name) => {
                const lower = String(name || '').toLowerCase();
                for (const k of Object.keys(headers)) {
                    if (String(k || '').toLowerCase() === lower) delete headers[k];
                }
            };
            const hasCookie = () => {
                const v = getHeader('cookie');
                return typeof v === 'string' && !!v.trim();
            };
            const setHeaderIfMissing = (name, value) => {
                if (!value) return;
                const cur = getHeader(name);
                if (typeof cur === 'string' && cur.trim()) return;
                headers[name] = value;
            };

            const host =
                (typeof o.hostname === 'string' && o.hostname) ||
                (typeof o.host === 'string' && o.host) ||
                (typeof o.servername === 'string' && o.servername) ||
                '';
            const hostname = String(host).split(':')[0].trim().toLowerCase();
            const isBaidu = hostname === 'pan.baidu.com' || hostname.endsWith('.pan.baidu.com');
            const isBaiduPcs = hostname === 'pcs.baidu.com' || hostname.endsWith('.pcs.baidu.com');
            const isQuark = hostname === 'pan.quark.cn' || hostname === 'drive.quark.cn' || hostname.endsWith('.quark.cn');
            const isUc = hostname === 'drive.uc.cn' || hostname.endsWith('.uc.cn');

            const parseCookie = (cookieStr) => {
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
            };
            const stringifyCookie = (cookieObj) => {
                if (!cookieObj || typeof cookieObj !== 'object') return '';
                const parts = [];
                for (const [k, v] of Object.entries(cookieObj)) {
                    const key = String(k || '').trim();
                    if (!key) continue;
                    parts.push(`${key}=${String(v == null ? '' : v).trim()}`);
                }
                return parts.join('; ');
            };
            const mergeCookiePreferDb = (existingCookie, dbCookie) => {
                const existingMap = parseCookie(existingCookie);
                const dbMap = parseCookie(dbCookie);
                const preferDbKeys = new Set([
                    'BDUSS',
                    'STOKEN',
                    'BAIDUID',
                    'PSTM',
                    'PANWEB',
                    'HOSUPPORT',
                    'USERID',
                    'UID',
                    'BDUSS_BFESS',
                ]);
                const merged = { ...existingMap };
                for (const [k, v] of Object.entries(dbMap)) {
                    if (!k) continue;
                    if (preferDbKeys.has(k) || !(k in merged)) merged[k] = v;
                }
                return stringifyCookie(merged);
            };

            // Ensure Quark/UC cookies exist. Some bundles:
            // - omit Cookie entirely (guest)
            // - or accidentally keep only playback cookie (Video-Auth) after a /play flow
            // The latter breaks directory APIs like `/1/clouddrive/file/sort` and causes outer HTTP 500.
            try {
                if (isQuark) {
                    const cookieFromDb = findPanCookieInDbJson('quark');
                    if (cookieFromDb) {
                        const existingCookie = getHeader('cookie') || headers.Cookie || '';
                        if (!String(existingCookie || '').trim()) {
                            setHeaderIfMissing('Cookie', cookieFromDb);
                        } else {
                            // After /play, some flows keep only `Video-Auth=...` and lose login cookies.
                            // Fix: merge the configured login cookie back, while preserving Video-Auth pairs.
                            const s = String(existingCookie || '');
                            const hasVideoAuth = /(?:^|;\s*)video-auth=/i.test(s);
                            const hasLoginMarkers = /(?:^|;\s*)(ctoken|__uid|b-user-id|__puus|__pus|tfstk|isg)=/i.test(s);
                            if (hasVideoAuth && !hasLoginMarkers) {
                                const pairs = s.match(/(?:^|;\s*)video-auth=[^;]*/gi) || [];
                                const mergedCookie = [String(cookieFromDb || '').trim()]
                                    .concat(pairs.map((p) => String(p || '').trim()).filter(Boolean))
                                    .filter(Boolean)
                                    .join('; ');
                                if (mergedCookie) {
                                    deleteHeader('cookie');
                                    headers.Cookie = mergedCookie;
                                }
                            }
                        }
                    }
                }
            } catch (_) {}
            try {
                if (!hasCookie() && isUc) {
                    const cookieFromDb = findPanCookieInDbJson('uc');
                    if (cookieFromDb) setHeaderIfMissing('Cookie', cookieFromDb);
                }
            } catch (_) {}

            if (isBaidu || isBaiduPcs) {
                // Ensure Baidu account cookie exists (BDUSS/STOKEN). Also preserve share-session cookies (e.g. BDCLND).
                const cookieFromDb = findPanCookieInDbJson('baidu');
                if (cookieFromDb) {
                    const existingCookie = getHeader('cookie');
                    const mergedCookie = mergeCookiePreferDb(existingCookie, cookieFromDb);
                    if (mergedCookie) {
                        deleteHeader('cookie');
                        headers.Cookie = mergedCookie;
                    }
                }
                if (BAIDU_DEBUG) {
                    const now = Date.now();
                    if (now - baiduDebugState.ts > 60_000) {
                        baiduDebugState.ts = now;
                        const dbPath = getDbJsonPath();
                        const dbExists = (() => {
                            try {
                                return !!(dbPath && fs.existsSync(dbPath));
                            } catch (_) {
                                return false;
                            }
                        })();
                        const curCookie = getHeader('cookie') || headers.Cookie || '';
                        baiduLog('cookie', {
                            dbPath,
                            dbExists,
                            hasDbCookie: !!cookieFromDb,
                            dbHasBduss: /(?:^|;\\s*)BDUSS=/.test(cookieFromDb),
                            dbHasStoken: /(?:^|;\\s*)STOKEN=/.test(cookieFromDb),
                            mergedHasBduss: /(?:^|;\\s*)BDUSS=/.test(String(curCookie || '')),
                            mergedHasStoken: /(?:^|;\\s*)STOKEN=/.test(String(curCookie || '')),
                        });
                    }
                }

                // Baidu often checks Referer/Origin + UA.
                if (isBaidu) {
                    setHeaderIfMissing('Referer', 'https://pan.baidu.com/disk/main');
                    setHeaderIfMissing('Origin', 'https://pan.baidu.com');
                    setHeaderIfMissing('X-Requested-With', 'XMLHttpRequest');
                }
                setHeaderIfMissing(
                    'User-Agent',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                );
                setHeaderIfMissing('Accept', 'application/json, text/plain, */*');
            }

            // Some Baidu endpoints rely on common query params; add them when missing.
            try {
                if (isBaidu && typeof o.path === 'string' && o.path) {
                    const [pathname, query] = o.path.split('?');
                    const p = String(pathname || '');
                    // Force loginStatus to use params that typically return `bdstoken`.
                    if (p === '/api/loginStatus') {
                        const params = new URLSearchParams(query || '');
                        params.set('web', '1');
                        params.set('clienttype', '0');
                        params.set('channel', 'chunlei');
                        if (!params.has('version')) params.set('version', '0');
                        const qs = params.toString();
                        o.path = qs ? `${p}?${qs}` : p;
                    } else if (p.includes('/api/') || p.includes('/share/') || p.includes('/rest/') || p.includes('/xpan/')) {
                        const params = new URLSearchParams(query || '');
                        if (!params.has('web')) params.set('web', '1');
                        if (!params.has('clienttype')) params.set('clienttype', '0');
                        if (!params.has('channel')) params.set('channel', 'chunlei');
                        const qs = params.toString();
                        o.path = qs ? `${p}?${qs}` : p;
                    }
                }
            } catch (_) {}

            o.headers = headers;
            return o;
        };

        const normalizeArgs = (args) => {
            const list = Array.from(args || []);
            let cb = null;
            if (list.length && typeof list[list.length - 1] === 'function') cb = list.pop();

            let url = null;
            let opts = null;
            if (list.length && (typeof list[0] === 'string' || list[0] instanceof URL)) {
                url = list.shift();
            }
            if (list.length && list[0] && typeof list[0] === 'object') opts = list.shift();

            // Remaining args are ignored (node supports more forms, but axios uses opts+cb).
            return { url, opts, cb };
        };

        const request = (...args) => {
            const { url, opts, cb } = normalizeArgs(args);
            let finalOpts = opts && typeof opts === 'object' ? { ...opts } : {};
            try {
                if (url) {
                    const u = url instanceof URL ? url : new URL(String(url));
                    finalOpts = {
                        ...finalOpts,
                        protocol: finalOpts.protocol || u.protocol,
                        hostname: finalOpts.hostname || u.hostname,
                        port: finalOpts.port || (u.port || undefined),
                        path: finalOpts.path || `${u.pathname || ''}${u.search || ''}`,
                    };
                }
            } catch (_) {}
            if (!finalOpts.protocol) finalOpts.protocol = `${scheme}:`;

            const patched = normalizeOpts(finalOpts);

            if (BAIDU_DEBUG) {
                const host = String(patched.hostname || patched.host || '').split(':')[0];
                if (host.endsWith('baidu.com')) {
                    const headers = patched.headers && typeof patched.headers === 'object' ? patched.headers : {};
                    const cookieStr = Object.keys(headers)
                        .filter((k) => String(k).toLowerCase() === 'cookie')
                        .map((k) => String(headers[k] || ''))
                        .join('; ');
                    const hasCookie = !!cookieStr.trim();
                    const hasBduss = /(?:^|;\\s*)BDUSS=/.test(cookieStr);
                    const hasStoken = /(?:^|;\\s*)STOKEN=/.test(cookieStr);
                    baiduLog('request', {
                        method: String(patched.method || 'GET').toUpperCase(),
                        host,
                        path: String(patched.path || ''),
                        hasCookie,
                        hasBduss,
                        hasStoken,
                    });
                }
            }

            const req = cb ? mod.request(patched, cb) : mod.request(patched);
            try {
                if (BAIDU_DEBUG) {
                    req.on('response', (res) => {
                        try {
                            const host = String(patched.hostname || patched.host || '').split(':')[0];
                            if (!host.endsWith('baidu.com')) return;
                            baiduLog('response', {
                                host,
                                path: String(patched.path || ''),
                                statusCode: res && res.statusCode,
                            });
                            // Best-effort JSON errno logging for debugging token/transfer issues.
                            try {
                                const p = String(patched.path || '');
                                const shouldLogBody =
                                    p.startsWith('/api/loginStatus') ||
                                    p.startsWith('/share/transfer') ||
                                    p.startsWith('/api/gettemplatevariable') ||
                                    p.startsWith('/api/share') ||
                                    p.startsWith('/api/mediainfo');
                                if (!shouldLogBody) return;
                                const chunks = [];
                                let total = 0;
                                let truncated = false;
                                const LIMIT = 128 * 1024;
                                res.on('data', (c) => {
                                    try {
                                        if (!c) return;
                                        const buf = Buffer.isBuffer(c) ? c : Buffer.from(String(c));
                                        total += buf.length;
                                        if (total > LIMIT) {
                                            truncated = true;
                                            return;
                                        }
                                        chunks.push(buf);
                                    } catch (_) {}
                                });
                                res.on('end', () => {
                                    try {
                                        if (truncated) return;
                                        if (!chunks.length) return;
                                        const enc = String((res && res.headers && (res.headers['content-encoding'] || res.headers['Content-Encoding'])) || '')
                                            .trim()
                                            .toLowerCase();
                                        const buf = Buffer.concat(chunks);
                                        let rawBuf = buf;
                                        try {
                                            if (enc === 'gzip') rawBuf = zlib.gunzipSync(buf);
                                            else if (enc === 'deflate') rawBuf = zlib.inflateSync(buf);
                                            else if (enc === 'br') rawBuf = zlib.brotliDecompressSync(buf);
                                        } catch (_) {
                                            rawBuf = buf;
                                        }
                                        const raw = rawBuf.toString('utf8');
                                        const trimmed = raw.trim();
                                        if (!trimmed) return;
                                        let json = null;
                                        try {
                                            json = JSON.parse(trimmed);
                                        } catch (_) {
                                            return;
                                        }
                                        const errno =
                                            json && json.errno != null ? json.errno : json && json.error_code != null ? json.error_code : json && json.error != null ? json.error : undefined;
                                        const msg =
                                            json && json.msg != null ? json.msg : json && json.message != null ? json.message : json && json.error_msg != null ? json.error_msg : undefined;
                                        const hasBdstoken = !!(json && (json.bdstoken || (json.data && json.data.bdstoken)));
                                        baiduLog('json', {
                                            path: p,
                                            errno: typeof errno === 'number' || typeof errno === 'string' ? errno : undefined,
                                            msg: typeof msg === 'string' ? msg : undefined,
                                            hasBdstoken,
                                        });
                                    } catch (_) {}
                                });
                            } catch (_) {}
                        } catch (_) {}
                    });
                }
            } catch (_) {}
            return req;
        };

        const get = (...args) => {
            const req = request(...args);
            try {
                req.end();
            } catch (_) {}
            return req;
        };

        return new Proxy(mod, {
            get(target, prop, receiver) {
                if (prop === 'request') return request;
                if (prop === 'get') return get;
                return Reflect.get(target, prop, receiver);
            },
        });
    };

    let wrappedHttp = null;
    let wrappedHttps = null;
    try {
        const httpMod = baseRequire('node:http');
        wrappedHttp = buildHttpProxy(httpMod, 'http');
    } catch (_) {
        try {
            const httpMod = baseRequire('http');
            wrappedHttp = buildHttpProxy(httpMod, 'http');
        } catch (_) {
            wrappedHttp = null;
        }
    }
    try {
        const httpsMod = baseRequire('node:https');
        wrappedHttps = buildHttpProxy(httpsMod, 'https');
    } catch (_) {
        try {
            const httpsMod = baseRequire('https');
            wrappedHttps = buildHttpProxy(httpsMod, 'https');
        } catch (_) {
            wrappedHttps = null;
        }
    }

    const requireFunc = (() => {
        const fn = (id) => {
            const key = String(id || '');
            if (wrappedHttp && (key === 'http' || key === 'node:http')) return wrappedHttp;
            if (wrappedHttps && (key === 'https' || key === 'node:https')) return wrappedHttps;
            return baseRequire(id);
        };
        // Preserve common require properties for compatibility.
        try {
            fn.resolve = baseRequire.resolve;
            fn.main = baseRequire.main;
            fn.extensions = baseRequire.extensions;
            fn.cache = baseRequire.cache;
        } catch (_) {}
        return fn;
    })();
    const context = buildVmContext(requireFunc, filePath);
    const quarkStateByUser = new Map();
    let quarkActiveUser = '';
    const quarkInitByUser = new Map(); // user -> { ts, promise }
    const QUARK_INIT_COOLDOWN_MS = (() => {
        const v = Number.parseInt(process.env.CATPAW_QUARK_INIT_COOLDOWN_MS || '', 10);
        return Number.isFinite(v) && v >= 0 ? v : 60_000;
    })();
    const QUARK_DEBUG = process.env.CATPAW_DEBUG === '1';
    const quarkMask = (v) => {
        const s = String(v || '').trim();
        if (!s) return '';
        if (s.length <= 12) return s;
        return `${s.slice(0, 6)}...${s.slice(-6)}`;
    };
    const quarkLog = (...args) => {
        if (!QUARK_DEBUG) return;
        // eslint-disable-next-line no-console
        console.log('[quark]', ...args);
    };

    const syncCookieFromRawHeader = (rawHeader) => {
        if (!rawHeader || typeof rawHeader !== 'object') return;
        const ck = rawHeader.Cookie || rawHeader.cookie;
        if (typeof ck !== 'string' || !ck.trim()) return;
        try {
            context.Wo = ck.trim();
            if (context.globalThis) context.globalThis.Wo = context.Wo;
        } catch (_) {}
    };

    const getPanDirNameForCurrentUser = () => getGlobalPanDirNameForCurrentUser();

    const syncQuarkVarsForCurrentUser = () => {
        const hasQuarkBindings =
            typeof context.WKt === 'function' || typeof context.KBe === 'function' || typeof context.fKt === 'function' || typeof context.MBe === 'function';
        const user = sanitizeTvUsername(getCurrentTvUser());
        if (!hasQuarkBindings) return user;
        const dirName = getPanDirNameForCurrentUser();
        try {
            context.LBe = dirName;
            if (context.globalThis) context.globalThis.LBe = dirName;
        } catch (_) {}
        try {
            context.DBe = dirName;
            if (context.globalThis) context.globalThis.DBe = dirName;
        } catch (_) {}
        // Some bundles use different global names for the folder.
        try {
            if (typeof context.mBe === 'string') {
                context.mBe = dirName;
                if (context.globalThis) context.globalThis.mBe = dirName;
            }
        } catch (_) {}
        try {
            if (typeof context.gBe === 'string') {
                context.gBe = dirName;
                if (context.globalThis) context.globalThis.gBe = dirName;
            }
        } catch (_) {}
        const prev = quarkStateByUser.get(user) || null;

        // Only overwrite fid state when:
        // - switching users (to avoid leaking folder fids across users), or
        // - we already have persisted state for this user.
        const switchingUser = !!(quarkActiveUser && quarkActiveUser !== user);
        if (switchingUser || (prev && (prev.s8 || prev.UW))) {
            if (prev && prev.s8) {
                try {
                    context.s8 = prev.s8;
                    if (context.globalThis) context.globalThis.s8 = prev.s8;
                } catch (_) {}
            } else {
                try {
                    context.s8 = undefined;
                    if (context.globalThis) context.globalThis.s8 = undefined;
                } catch (_) {}
            }
            if (prev && prev.UW) {
                try {
                    context.UW = prev.UW;
                    if (context.globalThis) context.globalThis.UW = prev.UW;
                } catch (_) {}
            } else {
                try {
                    context.UW = undefined;
                    if (context.globalThis) context.globalThis.UW = undefined;
                } catch (_) {}
            }
        }

        quarkActiveUser = user;
        return user;
    };

    const persistQuarkVarsForUser = (user) => {
        if (!user) return;
        try {
            const s8 = context.s8;
            const UW = context.UW;
            const prev = quarkStateByUser.get(user) || {};
            const next = { ...prev };
            if (s8) next.s8 = String(s8);
            if (UW) next.UW = String(UW);
            quarkStateByUser.set(user, next);
        } catch (_) {}
    };

    const ensureQuarkDestForCurrentUser = () => {
        const user = syncQuarkVarsForCurrentUser();
        // IMPORTANT: do NOT auto-run `fKt()` here.
        // `fKt()` and related init flows can trigger many Quark API requests (and lots of 401/404 logs)
        // especially when the user cookie isn't ready yet.
        // Let the script decide when it needs to init; we only bind per-user vars and restore cached fids.
        try {
            if ((!context.UW || String(context.UW) === '0') && context.s8 && String(context.s8) !== '0') {
                context.UW = String(context.s8);
                if (context.globalThis) context.globalThis.UW = context.UW;
            }
        } catch (_) {}
        persistQuarkVarsForUser(user);
    };

    const maybeInitQuarkDestForCurrentUser = async (rawHeader) => {
        try {
            syncCookieFromRawHeader(rawHeader);
        } catch (_) {}
        // If cookie is missing from headers, try to load it from db.json (TV_Server persists it there).
        try {
            const ck = typeof context.Wo === 'string' ? context.Wo.trim() : '';
            if (!ck) {
                const fromDb = findPanCookieInDbJson('quark');
                if (fromDb) syncCookieFromRawHeader({ Cookie: fromDb });
            }
        } catch (_) {}
        try {
            ensureQuarkDestForCurrentUser();
        } catch (_) {}

        // Without a cookie, Quark init cannot succeed; avoid noisy retries.
        try {
            const ck = typeof context.Wo === 'string' ? context.Wo.trim() : '';
            if (!ck) return;
        } catch (_) {}

        // Only init if we have Quark bindings and no destination fid yet.
        const hasInitFn = typeof context.fKt === 'function';
        if (!hasInitFn) return;
        const curUw = context.UW ? String(context.UW) : '';
        const curS8 = context.s8 ? String(context.s8) : '';
        if ((curUw && curUw !== '0') || (curS8 && curS8 !== '0')) return;

        const user = sanitizeTvUsername(getCurrentTvUser());
        const now = Date.now();
        const prev = quarkInitByUser.get(user) || null;
        if (prev && prev.promise) {
            await prev.promise;
            return;
        }
        if (prev && prev.ts && now - prev.ts < QUARK_INIT_COOLDOWN_MS) return;

        const promise = (async () => {
            try {
                // Let the script perform its own Quark folder init (should set UW/s8).
                quarkLog('init start', { user, file: path.basename(filePath), dir: getGlobalPanDirNameForCurrentUser() });
                await context.fKt();
                quarkLog('init done', {
                    user,
                    UW: quarkMask(context.UW),
                    s8: quarkMask(context.s8),
                });
            } finally {
                quarkInitByUser.set(user, { ts: Date.now(), promise: null });
            }
        })();
        quarkInitByUser.set(user, { ts: now, promise });
        await promise;

        try {
            ensureQuarkDestForCurrentUser();
        } catch (_) {}
    };

    const script = new vm.Script(code, { filename: filePath });
    const timeoutMs = Number.parseInt(process.env.CATPAW_CUSTOM_SOURCE_TIMEOUT_MS || '', 10);
    script.runInContext(context, { timeout: Number.isFinite(timeoutMs) ? timeoutMs : 120000 });

    // Some bundled scripts expect an internal persistent store (`kO`) to exist and call `kO.push(...)`.
    // In server-only mode the store may be null, causing crashes like:
    // "TypeError: Cannot read properties of null (reading 'push')".
    // Provide a minimal shim so the bundle won't crash. (It only affects persistence of refreshed cookie tokens.)
    try {
        const hasK0Binding = context && Object.prototype.hasOwnProperty.call(context, 'kO');
        const hasPush = hasK0Binding && context.kO && typeof context.kO.push === 'function';
        if (hasK0Binding && !hasPush) {
            const shim = {
                push: async () => null,
                getData: async () => ({}),
                getObjectDefault: async (_path, def) => (def == null ? {} : def),
                delete: async () => null,
            };
            context.kO = shim;
            if (context.globalThis) context.globalThis.kO = shim;
        }
    } catch (_) {}

    // Initialize per-user Quark vars once for the default (no-header) user context (usually `test`).
    // This helps scripts that run immediate init code at load time avoid using root/default folders.
    try {
        syncQuarkVarsForCurrentUser();
    } catch (_) {}
    // Capture the Quark resolver context if the bundle provides it (some bundles expose `WKt`).
    // This avoids relying on whichever spider happened to install the global onSend hook first.
    try {
        if (typeof context.WKt === 'function') {
            quarkRuntime.ctx = context;
            quarkRuntime.fromFile = path.basename(filePath);
        }
    } catch (_) {}

    // Some bundles expect init config `hl.baiduuk` to be an array and call `.includes(...)`.
    // Some init config endpoints omit this field, causing runtime crashes in `/play`.
    // Patch the global `hl` binding (when present) so any assignment guarantees `baiduuk` is always an array.
    try {
        let currentHl = context.hl;
        const normalizeHl = (v) => {
            if (!v || typeof v !== 'object') return v;
            if (!Array.isArray(v.baiduuk)) v.baiduuk = [];
            return v;
        };
        currentHl = normalizeHl(currentHl);
        Object.defineProperty(context, 'hl', {
            configurable: true,
            enumerable: true,
            get() {
                return currentHl;
            },
            set(v) {
                currentHl = normalizeHl(v);
            },
        });
        if (context.globalThis) {
            Object.defineProperty(context.globalThis, 'hl', {
                configurable: true,
                enumerable: true,
                get() {
                    return currentHl;
                },
                set(v) {
                    currentHl = normalizeHl(v);
                },
            });
        }
    } catch (_) {}

    // Quark directory init: when folder already exists Quark may return "same name conflict" (23008).
    // Do not fail hard; let the script proceed (it may list/resolve afterwards).
    try {
        const parsePayloadObj = (payload) => {
            if (!payload) return null;
            if (typeof payload === 'string') {
                const text = payload.trim();
                if (!text) return null;
                if (!text.startsWith('{') || !text.endsWith('}')) return null;
                try {
                    const obj = JSON.parse(text);
                    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : null;
                } catch (_) {
                    return null;
                }
            }
            if (typeof payload === 'object' && !Array.isArray(payload)) return payload;
            return null;
        };

        const findQuarkRootDirFidByName = async (dirName) => {
            const fetchImpl = globalThis.fetch;
            if (typeof fetchImpl !== 'function') return '';
            const name = String(dirName || '').trim();
            if (!name) return '';
            const cookie = typeof context.Wo === 'string' ? context.Wo.trim() : '';
            if (!cookie) return '';

            // Best-effort: Quark list root dir to locate an existing folder fid when create hits 23008.
            const url = new URL('https://drive.quark.cn/1/clouddrive/file/sort');
            url.searchParams.set('pr', 'ucpro');
            url.searchParams.set('fr', 'pc');
            url.searchParams.set('pdir_fid', '0');
            url.searchParams.set('_page', '1');
            url.searchParams.set('_size', '200');
            url.searchParams.set('_fetch_total', '1');
            url.searchParams.set('_sort', 'updated_at:desc');

            let data = null;
            try {
                const res = await fetchImpl(url.toString(), {
                    method: 'GET',
                    redirect: 'manual',
                    headers: {
                        Accept: 'application/json, text/plain, */*',
                        Referer: 'https://pan.quark.cn',
                        Origin: 'https://pan.quark.cn',
                        Cookie: cookie,
                    },
                });
                const text = await res.text();
                if (!res.ok) return '';
                data = text && text.trim() ? JSON.parse(text) : null;
            } catch (_) {
                data = null;
            }
            if (!data) return '';

            const queue = [data];
            const seen = new Set();
            const maxNodes = 5000;
            let nodes = 0;
            while (queue.length && nodes < maxNodes) {
                const v = queue.shift();
                nodes += 1;
                if (!v) continue;
                if (typeof v !== 'object') continue;
                if (seen.has(v)) continue;
                seen.add(v);
                if (Array.isArray(v)) {
                    for (const item of v) queue.push(item);
                    continue;
                }
                const fileName =
                    typeof v.file_name === 'string'
                        ? v.file_name
                        : typeof v.fileName === 'string'
                          ? v.fileName
                          : typeof v.name === 'string'
                            ? v.name
                            : '';
                if (fileName && fileName.trim() === name) {
                    const fid =
                        (typeof v.fid === 'string' && v.fid.trim()) ||
                        (typeof v.file_id === 'string' && v.file_id.trim()) ||
                        (typeof v.fileId === 'string' && v.fileId.trim()) ||
                        '';
                    if (fid) return fid.trim();
                }
                for (const val of Object.values(v)) queue.push(val);
            }
            return '';
        };

        const wrapCreateDirFn = (fnName) => {
            if (typeof context[fnName] !== 'function') return;
            const original = context[fnName];
            context[fnName] = async (url, payload, ...rest) => {
                const obj = parsePayloadObj(payload);
                const getErrCode = (err) => {
                    try {
                        const data = err && err.response && err.response.data;
                        const code = data && typeof data === 'object' ? data.code : null;
                        return code == null ? '' : String(code);
                    } catch (_) {
                        return '';
                    }
                };
                const isNameConflict = (err) => getErrCode(err) === '23008';
                const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                try {
                    return await original(url, payload, ...rest);
                } catch (err) {
                    // Quark dir init may return "same name conflict" when the folder already exists.
                    // Avoid failing hard; return a minimal success so the script can proceed to list/resolve.
                    if (
                        obj &&
                        typeof obj.file_name === 'string' &&
                        obj.pdir_fid !== undefined &&
                        obj.file_name === getPanDirNameForCurrentUser() &&
                        isNameConflict(err)
                    ) {
                        // Small backoff in case Quark reports a transient conflict.
                        for (let i = 0; i < 3; i += 1) {
                            await sleep(200 * (i + 1));
                            try {
                                return await original(url, payload, ...rest);
                            } catch (err2) {
                                if (!isNameConflict(err2)) throw err2;
                            }
                        }

                        // If the dir already exists, try to resolve its fid so later save calls won't fall back to root.
                        try {
                            const fid = await findQuarkRootDirFidByName(obj.file_name);
                            if (fid) {
                                context.s8 = fid;
                                context.UW = fid;
                                if (context.globalThis) {
                                    context.globalThis.s8 = fid;
                                    context.globalThis.UW = fid;
                                }
                            }
                        } catch (_) {}

                        return { data: { code: 0 } };
                    }
                    throw err;
                }
            };
            if (context.globalThis) context.globalThis[fnName] = context[fnName];
        };

        // Different bundles may use different function names for Quark directory init.
        wrapCreateDirFn('fa');
        wrapCreateDirFn('ws');
    } catch (_) {}

    // Some bundled scripts assume certain helper functions always return arrays and call `.filter/.map` directly.
    // In server-only mode, those helpers may return `null` (e.g. when a platform bridge is missing), causing crashes.
    // Patch known globals to make them null-safe without modifying user scripts.
    try {
        if (typeof context.VBe === 'function') {
            const original = context.VBe;
            context.VBe = async (...args) => {
                const out = await original(...args);
                if (out == null) return [];
                return out;
            };
            if (context.globalThis) context.globalThis.VBe = context.VBe;
        }
    } catch (_) {}

    // Some scripts run a Quark "self-check/refresh" task (`MBe`) that may delete files in the
    // configured destination folder. If the destination folder fid (`s8`) is missing, some APIs default to root.
    // Guard against accidental root cleanup by skipping the task when a safe folder fid cannot be resolved.
    try {
        if (typeof context.fKt === 'function') {
            const original = context.fKt;
            context.fKt = async (...args) => {
                const user = syncQuarkVarsForCurrentUser();
                const res = await original(...args);
                try {
                    if ((!context.UW || String(context.UW) === '0') && context.s8 && String(context.s8) !== '0') {
                        context.UW = String(context.s8);
                        if (context.globalThis) context.globalThis.UW = context.UW;
                    }
                } catch (_) {}
                persistQuarkVarsForUser(user);
                return res;
            };
            if (context.globalThis) context.globalThis.fKt = context.fKt;
        }
    } catch (_) {}

    try {
        if (typeof context.fKt === 'function' && typeof context.MBe === 'function') {
            const original = context.MBe;
            context.MBe = async (...args) => {
                try {
                    syncQuarkVarsForCurrentUser();
                } catch (_) {}
                if (!context.s8 || String(context.s8) === '0') return;
                return await original(...args);
            };
            if (context.globalThis) context.globalThis.MBe = context.MBe;
        }
    } catch (_) {}

    // Normalize Quark proxy errors so callers can distinguish "stoken expired" from generic failures.
    // Applies ONLY to Quark proxy handler (`KBe`), other pans have different error codes.
    try {
                if (typeof context.KBe === 'function') {
                    const original = context.KBe;
                    context.KBe = async (req, reply, ...rest) => {
                // Ensure per-user Quark work directory (e.g. /TV_Server/admin) is selected for this request.
                // Pass username via header `X-TV-User` or query `__tvuser`.
                    try {
                        syncCookieFromRawHeader(req && req.headers ? req.headers : null);
                        await maybeInitQuarkDestForCurrentUser(req && req.headers ? req.headers : null);
                        ensureQuarkDestForCurrentUser();
                    } catch (_) {}

                const normalizeMsg = (e) => {
                    const resp = e && typeof e === 'object' ? e.response : null;
                    const data = resp && typeof resp === 'object' ? resp.data : null;
                    const message =
                        (data && typeof data === 'object' && typeof data.message === 'string' && data.message) ||
                        (e && e.message) ||
                        String(e);
                    const code = data && typeof data === 'object' ? String(data.code || '') : '';
                    return { code, message };
                };
                const isStokenExpired = (e) => {
                    const { code, message } = normalizeMsg(e);
                    return code === '41016' || String(message || '').includes('分享的stoken过期');
                };
                const sendStokenExpired = () => {
                    try {
                        reply.code(410);
                        reply.send({
                            statusCode: 410,
                            error: 'Gone',
                            pan: 'quark',
                            code: 41016,
                            message: 'stoken 过期，需要重新 detail/play 获取新的链接（或检查夸克 Cookie 是否有效）',
                        });
                    } catch (_) {}
                };
                try {
                    return await original(req, reply, ...rest);
                } catch (err) {
                    // Retry once: blank the embedded stoken so the script can re-fetch a fresh one internally.
                    if (isStokenExpired(err)) {
                        try {
                            const fileId = String(req && req.params ? req.params.fileId || '' : '');
                            if (fileId && !fileId.startsWith('*')) {
                                const parts = fileId.split('*');
                                if (parts.length >= 3) req.params.fileId = `*${parts.slice(1).join('*')}`;
                            }
                        } catch (_) {}
                        try {
                            return await original(req, reply, ...rest);
                        } catch (err2) {
                            if (isStokenExpired(err2)) {
                                sendStokenExpired();
                                return;
                            }
                            const { message } = normalizeMsg(err2);
                            try {
                                reply.code(502);
                                reply.send({
                                    statusCode: 502,
                                    error: 'Bad Gateway',
                                    pan: 'quark',
                                    message: `Quark proxy failed after stoken refresh retry: ${message}`,
                                });
                            } catch (_) {}
                            return;
                        }
                    }

                    const { message } = normalizeMsg(err);
                    if (String(message || '').includes('download_url')) {
                        try {
                            reply.code(502);
                            reply.send({
                                statusCode: 502,
                                error: 'Bad Gateway',
                                pan: 'quark',
                                message:
                                    'Quark proxy failed to derive download_url (likely missing/expired quark cookie or quark API init failed)',
                            });
                        } catch (_) {}
                        return;
                    }
                    throw err;
                }
            };
            if (context.globalThis) context.globalThis.KBe = context.KBe;
        }
    } catch (_) {}

    const spiders = collectSpidersDeep(Object.values(context)).map((spider) => {
        try {
            if (spider && typeof spider.api === 'function') {
                const originalApi = spider.api;
                spider.api = async (instance, opts) => {
                    instance.addHook('onRequest', async (req, _reply) => {
                        try {
                            await ensureSpiderInitOnceForRequest(req);
                        } catch (_) {}
                    });

                    if (!instance.__cp_auto_init_mark) {
                        instance.__cp_auto_init_mark = true;
                        instance.addHook('onSend', async (req, reply, payload) => {
                            try {
                                markSpiderAutoInitDoneFromInitResponse(req, reply);
                            } catch (_) {}
                            return payload;
                        });
                    }

                    // Ensure Quark directory vars are bound for this request/user before any handlers run.
                    instance.addHook('onRequest', async (req, _reply) => {
                        try {
                            ensureQuarkDestForCurrentUser();
                        } catch (_) {}
                        try {
                            const rawUrl = String((req && req.raw && req.raw.url) || '');
                            const requestPath = rawUrl.split('?')[0] || '';
                            // /play is where Quark save/download flows typically happen; ensure UW/s8 are initialized upfront
                            // so the script won't save into root.
                            if (requestPath.endsWith('/play')) {
                                if (QUARK_DEBUG) {
                                    quarkLog('onRequest /play', {
                                        user: sanitizeTvUsername(getCurrentTvUser()),
                                        file: path.basename(filePath),
                                        UW: quarkMask(context.UW),
                                        s8: quarkMask(context.s8),
                                        hasCookie: !!(req && req.headers && (req.headers.cookie || req.headers.Cookie)),
                                    });
                                }
                                await maybeInitQuarkDestForCurrentUser(req && req.headers ? req.headers : null);
                            }
                        } catch (_) {}
                    });

                    if (!instance.__cp_baidu_play_rewrite) {
                        instance.__cp_baidu_play_rewrite = true;
                        instance.addHook('onSend', async (req, reply, payload) => {
                            try {
                                const rawUrl = String((req && req.raw && req.raw.url) || '');
                                const requestPath = rawUrl.split('?')[0] || '';
                                if (!requestPath.endsWith('/play')) return payload;

		                                const raw = Buffer.isBuffer(payload)
		                                    ? payload.toString('utf8')
		                                    : typeof payload === 'string'
		                                      ? payload
		                                      : null;
		                                if (typeof raw !== 'string') return payload;
		                                const hasBaidu = raw.includes('baidupcs.com');
		                                const hasQuark = raw.includes('/proxy/quark');
		                                const hasLocalBase =
		                                    raw.includes('127.0.0.1') || raw.includes('0.0.0.0') || raw.toLowerCase().includes('localhost');
		                                if (!hasBaidu && !hasQuark && !hasLocalBase) return payload;

			                                const data = JSON.parse(raw);
			                                const urlVal = data && typeof data === 'object' ? data.url : null;
			                                if (!data || typeof data !== 'object' || (typeof urlVal !== 'string' && !Array.isArray(urlVal))) return payload;

		                                const rawHeader = data.header && typeof data.header === 'object' ? data.header : null;
			                                const ua = rawHeader && rawHeader['User-Agent'] ? String(rawHeader['User-Agent']) : '';

			                                const cfg = getDirectLinkConfig();
			                                const directLinkEnabled = !!(cfg && cfg.directLinkEnabled);
			                                const needsBaiduRewrite = hasBaidu && !directLinkEnabled;
		                                const q = req && req.query && typeof req.query === 'object' ? req.query : null;
		                                const quarkTvRaw = q
		                                    ? (Object.prototype.hasOwnProperty.call(q, 'quark_tv') ? q.quark_tv : q.quarkTv)
		                                    : null;
		                                const quarkTvStr = String(quarkTvRaw == null ? '' : quarkTvRaw).trim().toLowerCase();
		                                const quarkTvEnabled = quarkTvStr === '1' || quarkTvStr === 'true' || quarkTvStr === 'yes' || quarkTvStr === 'on';

		                                const needsQuarkDirect = hasQuark && directLinkEnabled && !quarkTvEnabled;
		                                const needsQuarkSaveOnly = hasQuark && quarkTvEnabled;
		                                const needsProxyBaseRewrite = hasQuark || needsBaiduRewrite || hasLocalBase;
		                                if (!needsQuarkDirect && !needsQuarkSaveOnly && !needsProxyBaseRewrite) return payload;

			                                const firstHeaderVal = (v) => String(v || '').split(',')[0].trim();
			                                const proto = firstHeaderVal(req.headers['x-forwarded-proto']) || String(req.protocol || 'http');
			                                const host = firstHeaderVal(req.headers['x-forwarded-host']) || firstHeaderVal(req.headers.host);
			                                const isLocalHost = (hn) => {
			                                    const h = String(hn || '').toLowerCase();
			                                    return h === '0.0.0.0' || h === '127.0.0.1' || h === 'localhost' || h === '::1';
			                                };
			                                const baseFromReq = host ? `${proto}://${host}`.replace(/\/+$/g, '') : '';
			                                const proxyBase = cfg && cfg.rewriteBase ? String(cfg.rewriteBase || '').trim() : '';
			                                const baseForProxy = proxyBase || baseFromReq;
		                                const rewriteUrlToBase = (urlStr) => {
		                                    const base = baseForProxy;
		                                    if (!base) return urlStr;
	                                    const raw = typeof urlStr === 'string' ? urlStr.trim() : '';
	                                    if (!raw) return urlStr;
	                                    const isAbs = /^https?:\/\//i.test(raw);
	                                    try {
	                                        const u = isAbs ? new URL(raw) : new URL(raw.replace(/^\//, ''), `${base}/`);
	                                        if (!isAbs) return u.toString();
	                                        if (!isLocalHost(u.hostname)) return raw;
	                                        const b = new URL(base);
	                                        const next = new URL(String(u.pathname || '/').replace(/^\//, ''), `${b.toString().replace(/\/+$/g, '')}/`);
	                                        next.search = u.search || '';
	                                        next.hash = u.hash || '';
	                                        return next.toString();
	                                    } catch (_) {
	                                        return urlStr;
	                                    }
	                                };

			                                const next = { ...data };

			                                // Some spiders return a single URL string instead of an array.
			                                if (typeof urlVal === 'string') {
			                                    next.url = rewriteUrlToBase(urlVal);
			                                    reply.type('application/json; charset=utf-8');
			                                    return JSON.stringify(next);
			                                }

			                                const rewritten = [];
	                                    const isHttpUrlStr = (s) => {
	                                        if (typeof s !== 'string') return false;
	                                        try {
	                                            const u = new URL(s);
	                                            return u.protocol === 'http:' || u.protocol === 'https:';
	                                        } catch (_) {
	                                            return false;
	                                        }
	                                    };
			                                if (!Array.isArray(data.url)) return payload;

	                                    // Support both formats:
	                                    // - [label,url,label,url,...] (common in some spiders)
	                                    // - [url,url,...] (some custom scripts)
	                                    const evenUrlCount = data.url.filter((v, i) => i % 2 === 0 && isHttpUrlStr(v)).length;
                                    const oddUrlCount = data.url.filter((v, i) => i % 2 === 1 && isHttpUrlStr(v)).length;
                                    const isPairFormat = oddUrlCount > 0 && evenUrlCount === 0 && data.url.length >= 2;
	                                for (let idx = 0; idx < data.url.length; idx++) {
	                                    const item = data.url[idx];
                                    if (typeof item !== 'string') {
                                        rewritten.push(item);
                                        continue;
                                    }
                                    // In pair format, only odd positions are URLs.
                                    if (isPairFormat && idx % 2 === 0) {
                                        rewritten.push(item);
                                        continue;
                                    }
	                                    let parsed;
	                                    let absItem = item;
	                                    try {
	                                        parsed = new URL(item);
	                                    } catch (_) {
	                                        if (baseFromReq) {
	                                            try {
	                                                parsed = new URL(item, `${baseFromReq}/`);
	                                                absItem = parsed.toString();
	                                            } catch (_e2) {
	                                                rewritten.push(item);
	                                                continue;
	                                            }
	                                        } else {
	                                            rewritten.push(item);
	                                            continue;
	                                        }
		                                    }
			                                    const hn = String(parsed.hostname || '').toLowerCase();
			                                    const isBaidu = hn && (hn.endsWith('.baidupcs.com') || hn === 'baidupcs.com');
			                                    const pathname = String(parsed.pathname || '');
			                                    const isLocalSpider = isLocalHost(hn) && pathname.startsWith('/spider/');
			                                    const isQuarkProxy = pathname && /\/proxy\/quark(?:\/|$)/.test(pathname);
			                                    if (isLocalSpider && needsProxyBaseRewrite) {
			                                        rewritten.push(rewriteUrlToBase(absItem));
			                                        continue;
			                                    }
		                                    if (isBaidu && needsBaiduRewrite) {
		                                        const token = putBaiduProxyEntry(
		                                            item,
		                                            rawHeader && typeof rawHeader === 'object' ? rawHeader : ua ? { 'User-Agent': ua } : {}
		                                        );
		                                        const base = baseForProxy;
		                                        if (!base) {
		                                            rewritten.push(item);
		                                            continue;
		                                        }
		                                        rewritten.push(`${base}/spider/proxy/baidu/${token}`);
		                                        continue;
		                                    }

			                                    if (isQuarkProxy && !directLinkEnabled && !needsQuarkSaveOnly) {
			                                        // Proxy mode: ensure Quark proxy URL is client-accessible.
			                                        rewritten.push(rewriteUrlToBase(absItem));
			                                        continue;
			                                    }

			                                    if (isQuarkProxy && needsQuarkSaveOnly) {
			                                        // Quark TV mode: trigger Quark "save" (and any required init/cleanup) but keep
			                                        // the original play payload URL (do not resolve download_url here).
			                                        const firstUrlIdx = isPairFormat
			                                            ? 1
			                                            : (() => {
			                                                  const httpIdx = data.url.findIndex((v) => typeof v === 'string' && isHttpUrlStr(v));
			                                                  if (httpIdx >= 0) return httpIdx;
			                                                  return data.url.findIndex((v) => typeof v === 'string' && v.includes('/proxy/quark/'));
			                                              })();
			                                        if (idx === firstUrlIdx) {
				                                                try {
				                                                    const runtimeCtx = quarkRuntime.ctx || context;
				                                                    const parsedDown = parseQuarkProxyDownUrl(absItem);
				                                                    if (!parsedDown) throw new Error('unrecognized quark proxy url');

				                                                    let effectiveHeader = null;
				                                                    try {
				                                                        const cookieFromDb = findPanCookieInDbJson('quark');
				                                                        effectiveHeader =
				                                                            rawHeader && typeof rawHeader === 'object'
				                                                                ? rawHeader
				                                                                : cookieFromDb
				                                                                  ? { Cookie: cookieFromDb }
				                                                                  : null;
				                                                        if (effectiveHeader && cookieFromDb && !effectiveHeader.Cookie && !effectiveHeader.cookie) {
				                                                            effectiveHeader.Cookie = cookieFromDb;
				                                                        }
                                                        await maybeInitQuarkDestForCurrentUser(effectiveHeader);
                                                        syncQuarkVarsForCurrentUser();
                                                        ensureQuarkDestForCurrentUser();
                                                    } catch (_) {}

				                                                    // Quark TV mode expects a "clear + save" flow. The bundled script's `MBe()`
				                                                    // performs the self-check/refresh cleanup in the configured destination folder.
				                                                    // We call it best-effort here (it is guarded to skip when s8 is missing/0).
				                                                    try {
				                                                        const initFn =
				                                                            runtimeCtx && typeof runtimeCtx.fKt === 'function'
				                                                                ? runtimeCtx.fKt
				                                                                : context && typeof context.fKt === 'function'
				                                                                  ? context.fKt
				                                                                  : null;
				                                                        if (initFn) {
				                                                            await initFn();
				                                                            try {
				                                                                ensureQuarkDestForCurrentUser();
				                                                            } catch (_) {}
				                                                        }
				                                                    } catch (_) {}

				                                                    try {
				                                                        const clearFn =
				                                                            runtimeCtx && typeof runtimeCtx.MBe === 'function'
				                                                                ? runtimeCtx.MBe
				                                                                : context && typeof context.MBe === 'function'
				                                                                  ? context.MBe
				                                                                  : null;
				                                                        if (clearFn) {
				                                                            await clearFn();
				                                                            try {
				                                                                ensureQuarkDestForCurrentUser();
				                                                            } catch (_) {}
				                                                        }
				                                                    } catch (_) {}

				                                                    await resolveQuarkDirectUrlCached({
				                                                        shareId: parsedDown.shareId,
				                                                        stoken: parsedDown.stoken,
				                                                        fid: parsedDown.fid,
			                                                    fidToken: parsedDown.fidToken,
			                                                    toPdirFid:
			                                                        context && context.UW && String(context.UW) !== '0'
			                                                            ? String(context.UW)
			                                                            : context && context.s8 && String(context.s8) !== '0'
			                                                              ? String(context.s8)
			                                                              : runtimeCtx && runtimeCtx.UW && String(runtimeCtx.UW) !== '0'
			                                                                ? String(runtimeCtx.UW)
			                                                                : runtimeCtx && runtimeCtx.s8 && String(runtimeCtx.s8) !== '0'
			                                                                  ? String(runtimeCtx.s8)
			                                                                  : '0',
			                                                    rawHeader: effectiveHeader,
			                                                    scriptContext: runtimeCtx,
			                                                    want: 'saved_fid',
			                                                });
			                                            } catch (e) {
			                                                const statusRaw =
			                                                    (e && typeof e.status === 'number' && e.status) ||
			                                                    (e && e.response && typeof e.response.status === 'number' && e.response.status) ||
			                                                    (e &&
			                                                        e.response &&
			                                                        e.response.data &&
			                                                        typeof e.response.data.status === 'number' &&
			                                                        e.response.data.status) ||
			                                                    0;
			                                                const status = Number.isFinite(Number(statusRaw)) ? Number(statusRaw) : 0;
			                                                if (status === 401) {
			                                                    const err = new Error('夸克登录失效');
			                                                    err.status = 401;
			                                                    throw err;
			                                                }
			                                                const err = new Error('获取播放地址失败');
			                                                err.status = status && status >= 400 && status <= 599 ? status : 424;
			                                                throw err;
			                                            }
			                                        }

			                                        rewritten.push(rewriteUrlToBase(absItem));
			                                        continue;
			                                    }

				                                    if (isQuarkProxy && needsQuarkDirect) {
			                                        // Only rewrite the first (default) playback URL to avoid triggering
			                                        // multiple expensive resolves for "quality" variants that are typically unused.
	                                            const firstUrlIdx = isPairFormat
	                                                ? 1
	                                                : (() => {
	                                                    const httpIdx = data.url.findIndex((v) => typeof v === 'string' && isHttpUrlStr(v));
	                                                    if (httpIdx >= 0) return httpIdx;
	                                                    return data.url.findIndex((v) => typeof v === 'string' && v.includes('/proxy/quark/'));
	                                                })();
		                                        if (idx !== firstUrlIdx) {
		                                            rewritten.push(item);
		                                            continue;
		                                        }

	                                        try {
	                                            const runtimeCtx = quarkRuntime.ctx || context;

		                                            const parsedDown = parseQuarkProxyDownUrl(absItem);
		                                            if (!parsedDown) throw new Error('unrecognized quark proxy url');
                                            // Do not force Quark init here; it can trigger noisy/slow API calls.
                                            // Only bind per-user variables; the resolver uses explicit API calls below.
                                            let effectiveHeader = null;
                                            try {
                                                const cookieFromDb = findPanCookieInDbJson('quark');
                                                effectiveHeader =
                                                    rawHeader && typeof rawHeader === 'object' ? rawHeader : cookieFromDb ? { Cookie: cookieFromDb } : null;
                                                if (effectiveHeader && cookieFromDb && !effectiveHeader.Cookie && !effectiveHeader.cookie) {
                                                    effectiveHeader.Cookie = cookieFromDb;
                                                }
                                                // The Quark cookie is often carried in the `/play` response headers (data.header),
                                                // not the inbound HTTP request headers, so init the folder here as well.
                                                await maybeInitQuarkDestForCurrentUser(effectiveHeader);
                                                syncQuarkVarsForCurrentUser();
                                                ensureQuarkDestForCurrentUser();
                                            } catch (_) {}
                                            if (QUARK_DEBUG) {
                                                quarkLog('rewrite start', {
                                                    user: sanitizeTvUsername(getCurrentTvUser()),
                                                    file: path.basename(filePath),
                                                    shareId: quarkMask(parsedDown.shareId),
                                                    fid: quarkMask(parsedDown.fid),
                                                    UW: quarkMask(runtimeCtx && runtimeCtx.UW),
                                                    s8: quarkMask(runtimeCtx && runtimeCtx.s8),
                                                    hasCookie: !!(rawHeader && (rawHeader.Cookie || rawHeader.cookie)) || !!findPanCookieInDbJson('quark'),
                                                    isPairFormat,
                                                });
                                            }
		                                            const toPdirFid =
		                                                context && context.UW && String(context.UW) !== '0'
		                                                    ? String(context.UW)
		                                                    : context && context.s8 && String(context.s8) !== '0'
		                                                      ? String(context.s8)
		                                                      : runtimeCtx && runtimeCtx.UW && String(runtimeCtx.UW) !== '0'
		                                                        ? String(runtimeCtx.UW)
		                                                        : runtimeCtx && runtimeCtx.s8 && String(runtimeCtx.s8) !== '0'
		                                                          ? String(runtimeCtx.s8)
		                                                          : '0';

		                                            const directUrl = await resolveQuarkDirectUrlCached({
		                                                shareId: parsedDown.shareId,
		                                                stoken: parsedDown.stoken,
		                                                fid: parsedDown.fid,
		                                                fidToken: parsedDown.fidToken,
	                                                toPdirFid,
		                                                rawHeader: effectiveHeader,
		                                                scriptContext: runtimeCtx,
		                                            });
	                                            if (!directUrl || !String(directUrl).trim()) {
	                                                const err = new Error('获取播放地址失败');
	                                                // Not a CatPawOpen service outage; usually cookie/login/params.
	                                                err.status = 424;
	                                                throw err;
	                                            }
                                            if (QUARK_DEBUG) {
                                                let host = '';
                                                try {
                                                    host = directUrl ? new URL(directUrl).host : '';
                                                } catch (_) {
                                                    host = '';
                                                }
                                                quarkLog('rewrite done', { host, ok: !!directUrl });
                                            }
	                                            rewritten.push(String(directUrl).trim());
	                                            continue;
	                                        } catch (e) {
	                                            if (QUARK_DEBUG) quarkLog('rewrite failed', String((e && e.message) || e || 'unknown').slice(0, 300));
	                                            const statusRaw =
	                                                (e && typeof e.status === 'number' && e.status) ||
	                                                (e && e.response && typeof e.response.status === 'number' && e.response.status) ||
	                                                (e && e.response && e.response.data && typeof e.response.data.status === 'number' && e.response.data.status) ||
	                                                0;
	                                            const status = Number.isFinite(Number(statusRaw)) ? Number(statusRaw) : 0;
	                                            if (status === 401) {
	                                                const err = new Error('夸克登录失效');
	                                                err.status = 401;
	                                                throw err;
	                                            }
	                                            const err = new Error('获取播放地址失败');
	                                            err.status = status && status >= 400 && status <= 599 ? status : 424;
	                                            throw err;
		                                        }
		                                    }

	                                    rewritten.push(item);
	                                }
	                                next.url = rewritten;

		                                return JSON.stringify(next);
		                            } catch (e) {
		                                const statusRaw =
		                                    (e && typeof e.status === 'number' && e.status) ||
		                                    (e && e.response && typeof e.response.status === 'number' && e.response.status) ||
		                                    (e && e.response && e.response.data && typeof e.response.data.status === 'number' && e.response.data.status) ||
		                                    0;
		                                const status = Number.isFinite(Number(statusRaw)) ? Number(statusRaw) : 0;
		                                const outStatus = status && status >= 400 && status <= 599 ? status : 424;
		                                try {
		                                    reply.code(outStatus);
		                                } catch (_) {}

		                                let msg = e && e.message ? String(e.message) : '获取播放地址失败';
		                                if (outStatus === 401 && msg === '夸克登录失效') msg = '夸克登录失效，错误码401';
		                                const error =
		                                    outStatus === 401 ? 'Unauthorized' : outStatus >= 500 ? 'Bad Gateway' : 'Failed Dependency';
		                                return JSON.stringify({ statusCode: outStatus, error, message: msg.slice(0, 400) });
		                            }
                        });
                    }

                    return await originalApi(instance, opts);
                };
            }
        } catch (_) {}
        return spider;
    });

    // websiteBundle is meant for browser execution (used as fallback if Yne is absent).
    // Some scripts expose it as a function; others assign it as a precomputed JS string.
    const websiteBundleRaw =
        context.websiteBundle !== undefined
            ? context.websiteBundle
            : context.globalThis && context.globalThis.websiteBundle !== undefined
              ? context.globalThis.websiteBundle
              : undefined;
    let websiteJs = '';
    if (typeof websiteBundleRaw === 'function') {
        try {
            websiteJs = String(websiteBundleRaw() || '');
        } catch (_) {
            websiteJs = '';
        }
    } else if (typeof websiteBundleRaw === 'string') {
        websiteJs = websiteBundleRaw;
    }

    // Extract the real /website fastify plugin (Yne) if present.
    // Some newer scripts embed the server plugins inside websiteBundle() instead of exporting them at top-level.
    const webPlugins = [];
    let webError = '';
    const addWebPlugin = (prefix, plugin) => {
        if (typeof prefix !== 'string' || !prefix) return;
        if (typeof plugin !== 'function') return;
        if (webPlugins.some((p) => p && p.prefix === prefix)) return;
        webPlugins.push({ prefix, plugin });
    };

    // 1) Prefer discovering plugins from the script itself (some bundles use `_te`/`fMe`/...).
    try {
        const detectedFromScript = detectWebPluginSymbols(code);
        for (const [prefix, symbol] of detectedFromScript.entries()) {
            const fn =
                (context && context[symbol] !== undefined ? context[symbol] : undefined) ||
                (context &&
                context.globalThis &&
                context.globalThis[symbol] !== undefined
                    ? context.globalThis[symbol]
                    : undefined);
            addWebPlugin(prefix, fn);
        }
    } catch (_) {}

    // 2) Legacy: older scripts export website plugin as `Yne` directly.
    if (!webPlugins.length && typeof context.Yne === 'function') {
        addWebPlugin('/website', context.Yne);
    }

    // 3) Fallback: try to extract plugins embedded inside websiteBundle() payload.
    if (!webPlugins.length && (typeof websiteBundleRaw === 'function' || typeof websiteBundleRaw === 'string')) {
        try {
            const websiteBundleFn = typeof websiteBundleRaw === 'function' ? websiteBundleRaw : () => websiteBundleRaw;
            const extracted = extractWebsiteWebPlugins(websiteBundleFn, requireFunc, filePath);
            if (Array.isArray(extracted) && extracted.length) {
                extracted.forEach((p) => {
                    if (!p || typeof p !== 'object') return;
                    if (typeof p.prefix !== 'string' || !p.prefix) return;
                    if (typeof p.plugin !== 'function') return;
                    addWebPlugin(p.prefix, p.plugin);
                });
            }
        } catch (err) {
            webError = (err && err.message) || String(err);
        }
        if (!webPlugins.length && !webError) {
            webError = 'websiteBundle() did not expose any web plugins';
        }
    }

    return { spiders, webPlugins, webError, websiteJs };
}

export async function loadCustomSourceSpiders() {
    const dirCandidates = resolveCustomSourceDirCandidates();
    const dirPath = dirCandidates.find((p) => p && fs.existsSync(p)) || (dirCandidates[0] || '');
    if (!dirPath) {
        cache = {
            dirPath: '',
            files: [],
            spiders: [],
            errors: { _dir: 'custom_spider not found' },
            byFile: {},
            webPlugins: [],
            webErrors: { _dir: 'custom_spider not found' },
            webByFile: {},
            websiteBundles: [],
            websiteErrors: { _dir: 'custom_spider not found' },
            websiteByFile: {},
        };
        console.warn('[customSpider] dir not found: (empty)');
        return [];
    }

    if (!fs.existsSync(dirPath)) {
        try {
            fs.mkdirSync(dirPath, { recursive: true });
        } catch (err) {
            const msg = (err && err.message) || String(err);
            cache = {
                dirPath,
                files: [],
                spiders: [],
                errors: { _dir: `custom_spider mkdir failed: ${msg}` },
                byFile: {},
                webPlugins: [],
                webErrors: { _dir: `custom_spider mkdir failed: ${msg}` },
                webByFile: {},
                websiteBundles: [],
                websiteErrors: { _dir: `custom_spider mkdir failed: ${msg}` },
                websiteByFile: {},
            };
            console.warn(`[customSpider] mkdir failed: ${dirPath} error=${msg}`);
            return [];
        }
    }

    const scriptPaths = listCustomScriptFiles(dirPath);
    const manifestPaths = [];
    scriptPaths.forEach((p) => {
        const mp = `${p}.manifest.json`;
        try {
            if (fs.existsSync(mp)) manifestPaths.push(mp);
        } catch (_) {}
    });
    const files = collectFileStats([...scriptPaths, ...manifestPaths]);
    if (cache.dirPath === dirPath && sameFiles(cache.files, files)) {
        return cache.spiders;
    }

    const errors = {};
    const allSpiders = [];
    const byFile = {};
    const webErrors = {};
    const webByFile = {};
    const allWebPlugins = [];
    const websiteErrors = {};
    const websiteByFile = {};
    const allWebsiteBundles = [];
    for (const filePath of scriptPaths) {
        const fileName = path
            .relative(dirPath, filePath)
            .split(path.sep)
            .join('/');
        try {
            const startNs = process.hrtime.bigint();
            const { spiders, webPlugins, webError, websiteJs } = await loadOneFile(filePath);
            const loadMs = Number((process.hrtime.bigint() - startNs) / 1000000n);
            const uniqInFile = new Map();
            spiders.forEach((s) => {
                if (!s || !s.meta) return;
                const key = s.meta.key;
                const type = String(s.meta.type);
                const id = `${key}:${type}`;
                if (!uniqInFile.has(id)) uniqInFile.set(id, s);
            });
            const uniqSpiders = Array.from(uniqInFile.values());
            uniqSpiders.forEach((s) => {
                try {
                    Object.defineProperty(s, '__customFile', {
                        value: fileName,
                        enumerable: false,
                        configurable: true,
                    });
                } catch (_) {}
                allSpiders.push(s);
            });
            byFile[fileName] = { loaded: uniqSpiders.length, errors: 0, ms: loadMs };

            if (webError) {
                webErrors[fileName] = webError;
            }
            const safeWebPlugins = Array.isArray(webPlugins) ? webPlugins : [];
            webByFile[fileName] = { loaded: safeWebPlugins.length, errors: webError ? 1 : 0, ms: loadMs };
            safeWebPlugins.forEach((p) => {
                if (!p || typeof p !== 'object') return;
                allWebPlugins.push({
                    prefix: p.prefix,
                    plugin: p.plugin,
                    fileName,
                });
            });

            const hasWebsite = typeof websiteJs === 'string' && !!websiteJs.trim();
            if (hasWebsite) allWebsiteBundles.push({ fileName, websiteJs });
            websiteByFile[fileName] = { loaded: hasWebsite ? 1 : 0, errors: 0, ms: loadMs };
        } catch (err) {
            const msg = (err && err.message) || String(err);
            errors[fileName] = msg;
            byFile[fileName] = { loaded: 0, errors: 1, ms: 0 };
            webErrors[fileName] = msg;
            webByFile[fileName] = { loaded: 0, errors: 1, ms: 0 };
            websiteErrors[fileName] = msg;
            websiteByFile[fileName] = { loaded: 0, errors: 1, ms: 0 };
            console.error(`[customSpider] load failed: file=${filePath} error=${msg}`);
        }
    }

    const uniq = new Map();
    allSpiders.forEach((s) => {
        const key = s.meta.key;
        const type = String(s.meta.type);
        const id = `${key}:${type}`;
        if (!uniq.has(id)) uniq.set(id, s);
    });

    cache = {
        dirPath,
        files,
        spiders: Array.from(uniq.values()),
        errors,
        byFile,
        webPlugins: allWebPlugins,
        webErrors,
        webByFile,
        websiteBundles: allWebsiteBundles,
        websiteErrors,
        websiteByFile,
    };
    return cache.spiders;
}
