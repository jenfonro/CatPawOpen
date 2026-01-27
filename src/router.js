import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';
import crypto from 'node:crypto';
import {
    getCustomSourceStatus,
    getCustomSourceApiPlugins,
    getCustomSourceWebPlugins,
    getCustomSourceWebsiteBundles,
    loadCustomSourceSpiders,
} from './util/customSourceSpiders.js';
import { getGlobalProxy, setGlobalProxy } from './util/proxy.js';
import { getCurrentTvUser, getTvUserFromRequest, hasExplicitTvUser, sanitizeTvUsername, tvUserStorage } from './util/tvUserContext.js';
import { getCatPawOpenVersion } from './util/version.js';

const spiderPrefix = '/spider';

const BAIDU_PLAY_UA = 'com.android.chrome/131.0.6778.200 (Linux;Android 10) AndroidXMedia3/1.5.1';
let panBuiltinResolverEnabledCache = false;
let corsAllowOriginsCache = [];
let corsAllowCredentialsCache = false;

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
    // For pkg executables, read/write config from the executable directory.
    try {
        if (process && process.pkg && typeof process.execPath === 'string' && process.execPath) {
            return path.dirname(process.execPath);
        }
    } catch (_) {}
    return '';
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

function pickForwardedFirst(value) {
    if (typeof value !== 'string') return '';
    const first = value.split(',')[0];
    return String(first || '').trim();
}

function getExternalOriginFromRequest(request) {
    const headers = (request && request.headers) || {};
    const proto = pickForwardedFirst(headers['x-forwarded-proto']) || '';
    const host = pickForwardedFirst(headers['x-forwarded-host']) || String(headers.host || '').trim();
    if (!host) return '';
    const scheme = proto === 'https' || proto === 'http' ? proto : 'http';
    return `${scheme}://${host}`;
}

function rewriteLocalUrlToExternal(url, externalOrigin) {
    if (!externalOrigin || typeof url !== 'string') return url;
    const raw = url.trim();
    if (!raw) return url;
    let parsed;
    try {
        parsed = new URL(raw);
    } catch (_) {
        return url;
    }
    const host = String(parsed.hostname || '').toLowerCase();
    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '0.0.0.0') return url;
    // Only rewrite URLs that clearly point back to this service.
    const pathName = String(parsed.pathname || '');
    if (!pathName.startsWith('/')) return url;
    return `${externalOrigin}${pathName}${parsed.search || ''}${parsed.hash || ''}`;
}

function rewriteLocalUrlsDeep(value, externalOrigin) {
    const seen = new WeakSet();
    const walk = (node) => {
        if (typeof node === 'string') return rewriteLocalUrlToExternal(node, externalOrigin);
        if (!node || typeof node !== 'object') return node;
        if (seen.has(node)) return node;
        seen.add(node);
        if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i += 1) node[i] = walk(node[i]);
            return node;
        }
        Object.keys(node).forEach((k) => {
            node[k] = walk(node[k]);
        });
        return node;
    };
    return walk(value);
}

function isSpiderPlayPath(urlPath) {
    const p = String(urlPath || '').split('?')[0];
    return /^\/spider\/[^/]+\/\d+\/play$/.test(p);
}

function readPanBuiltinResolverEnabledFromConfigRoot(root) {
    const cfg = root && typeof root === 'object' && !Array.isArray(root) ? root : {};
    if (Object.prototype.hasOwnProperty.call(cfg, 'panResolver') && typeof cfg.panResolver === 'boolean') return cfg.panResolver;
    const panResolver =
        cfg && cfg.panResolver && typeof cfg.panResolver === 'object' && !Array.isArray(cfg.panResolver) ? cfg.panResolver : null;
    if (panResolver && Object.prototype.hasOwnProperty.call(panResolver, 'builtinEnabled')) return !!panResolver.builtinEnabled;
    if (Object.prototype.hasOwnProperty.call(cfg, 'panBuiltinResolverEnabled')) return !!cfg.panBuiltinResolverEnabled;
    return false;
}

function getConfigJsonPath() {
    const external = getExternalRootDir();
    if (external) return path.resolve(external, 'config.json');
    return path.resolve(getEmbeddedRootDir(), 'config.json');
}

function readConfigJsonSafe(configPath) {
    try {
        if (!configPath || !fs.existsSync(configPath)) return {};
        const raw = fs.readFileSync(configPath, 'utf8');
        const parsed = raw && raw.trim() ? JSON.parse(raw) : {};
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (_) {
        return {};
    }
}

function writeConfigJsonSafe(configPath, obj) {
    const root = obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
    fs.writeFileSync(configPath, `${JSON.stringify(root, null, 2)}\n`, 'utf8');
}

function sanitizeOnlineScriptFileName(inputUrl, suggestedName) {
    const rawName = typeof suggestedName === 'string' && suggestedName.trim() ? suggestedName.trim() : '';
    let base = rawName;
    if (!base) {
        try {
            const u = new URL(String(inputUrl || '').trim());
            base = path.basename(u.pathname || '');
        } catch (_) {
            base = '';
        }
    }
    base = String(base || '').trim();
    if (!base || base === '/' || base === '.' || base === '..') base = 'online.cjs';
    base = path.basename(base);
    base = base.replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!base) base = 'online.cjs';
    const lower = base.toLowerCase();
    if (!(lower.endsWith('.js') || lower.endsWith('.mjs') || lower.endsWith('.cjs'))) base = `${base}.cjs`;
    return base;
}

function atomicWriteFileWithRollback(filePath, content) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const suffix = `${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`;
    const tmpPath = path.resolve(dir, `.${path.basename(filePath)}.tmp.${suffix}`);
    const bakPath = fs.existsSync(filePath) ? `${filePath}.bak.${suffix}` : '';

    fs.writeFileSync(tmpPath, content, 'utf8');
    try {
        if (bakPath) fs.renameSync(filePath, bakPath);
        fs.renameSync(tmpPath, filePath);
    } catch (e) {
        try {
            if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
        } catch (_) {}
        try {
            if (bakPath && fs.existsSync(bakPath)) fs.renameSync(bakPath, filePath);
        } catch (_) {}
        throw e;
    }
    try {
        if (bakPath && fs.existsSync(bakPath)) fs.unlinkSync(bakPath);
    } catch (_) {}
    return true;
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

function writeJsonFileAtomic(filePath, obj) {
    const root = obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
    atomicWriteFileWithRollback(filePath, `${JSON.stringify(root, null, 2)}\n`);
    return true;
}

function normalizeOnlineConfigListInput(body) {
    const b = body && typeof body === 'object' ? body : {};
    const pick = (k) => (Object.prototype.hasOwnProperty.call(b, k) ? b[k] : undefined);
    const v =
        pick('onlineConfigs') ??
        pick('online_configs') ??
        pick('configs') ??
        pick('configList') ??
        pick('config_list') ??
        pick('spiderConfigs') ??
        pick('spider_configs');
    if (v === undefined) return { provided: false, list: [] };
    if (v == null) return { provided: true, list: [] };
    if (!Array.isArray(v)) return { provided: true, list: null };
    return { provided: true, list: v };
}

function normalizeOnlineConfigItem(raw, index) {
    if (typeof raw === 'string') {
        const url = raw.trim();
        return { key: url, id: '', name: '', url, index };
    }
    const it = raw && typeof raw === 'object' ? raw : {};
    const url =
        (typeof it.url === 'string' && it.url.trim()) ||
        (typeof it.addr === 'string' && it.addr.trim()) ||
        (typeof it.address === 'string' && it.address.trim()) ||
        (typeof it.link === 'string' && it.link.trim()) ||
        '';
    const id = (typeof it.id === 'string' && it.id.trim()) || '';
    const name = (typeof it.name === 'string' && it.name.trim()) || (typeof it.title === 'string' && it.title.trim()) || '';
    const key = id || url;
    return { key: String(key || '').trim(), id, name, url: String(url || '').trim(), index };
}

function stableHashShort(input) {
    const s = String(input || '');
    return crypto.createHash('sha256').update(s).digest('hex').slice(0, 10);
}

function pickFileBaseNameFromUrl(urlStr) {
    try {
        const u = new URL(String(urlStr || '').trim());
        const base = path.basename(u.pathname || '');
        return base && base !== '/' ? base : '';
    } catch (_) {
        return '';
    }
}

function buildOnlineConfigFileName(key, urlStr) {
    const baseFromUrl = pickFileBaseNameFromUrl(urlStr);
    const base = sanitizeOnlineScriptFileName(urlStr, baseFromUrl || 'online.cjs');
    const ext = base.toLowerCase().endsWith('.cjs') || base.toLowerCase().endsWith('.mjs') || base.toLowerCase().endsWith('.js') ? '' : '.cjs';
    const hash = stableHashShort(key || urlStr);
    const name = base.replace(/\.(cjs|mjs|js)$/i, '');
    return `${name}.${hash}${ext || '.cjs'}`.replace(/\.{2,}/g, '.');
}

async function headRemoteMeta(url, options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const timeoutMs = Number.isFinite(Number(opts.timeoutMs)) ? Math.max(100, Math.trunc(Number(opts.timeoutMs))) : 8000;

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
        const res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller ? controller.signal : undefined });
        const ok = !!(res && res.ok);
        const getHeader = (k) => {
            try {
                return res && res.headers && typeof res.headers.get === 'function' ? res.headers.get(k) : '';
            } catch (_) {
                return '';
            }
        };
        return {
            ok,
            status: res ? Number(res.status || 0) : 0,
            etag: ok ? String(getHeader('etag') || '') : '',
            lastModified: ok ? String(getHeader('last-modified') || '') : '',
        };
    } catch (_) {
        return { ok: false, status: 0, etag: '', lastModified: '' };
    } finally {
        if (timer) clearTimeout(timer);
    }
}

function getCustomSourceErrorForFile(status, relName) {
    const s = status && typeof status === 'object' ? status : {};
    const errors = s.errors || {};
    const webErrors = s.webErrors || {};
    const apiErrors = s.apiErrors || {};
    const websiteErrors = s.websiteErrors || {};
    return errors[relName] || webErrors[relName] || apiErrors[relName] || websiteErrors[relName] || '';
}

async function ensureCustomSourceDirReady() {
    try {
        if (!getCustomSourceStatus().dirPath) await loadCustomSourceSpiders();
    } catch (_) {}
    const customDir = String(getCustomSourceStatus().dirPath || '');
    return customDir;
}

async function reconcileOnlineConfigs(nextListRaw, prevPersisted, customDir) {
    const prevList = Array.isArray(prevPersisted) ? prevPersisted : [];
    const prevById = new Map();
    const prevByUrl = new Map();
    prevList.forEach((r) => {
        if (!r || typeof r !== 'object') return;
        const id = typeof r.id === 'string' && r.id.trim() ? r.id.trim() : '';
        const url = typeof r.url === 'string' && r.url.trim() ? r.url.trim() : '';
        if (id) prevById.set(id, r);
        if (url) prevByUrl.set(url, r);
    });

    const rawArr = Array.isArray(nextListRaw) ? nextListRaw : [];
    const normalized = rawArr
        .map((it, idx) => normalizeOnlineConfigItem(it, idx))
        .filter((it) => it && typeof it.key === 'string' && it.key.trim());

    // De-dup by key while keeping order.
    const seenKeys = new Set();
    const nextItems = [];
    normalized.forEach((it) => {
        const k = it.key.trim();
        if (!k || seenKeys.has(k)) return;
        seenKeys.add(k);
        nextItems.push(it);
    });

    const onlineDir = path.resolve(customDir, 'online');
    try {
        if (!fs.existsSync(onlineDir)) fs.mkdirSync(onlineDir, { recursive: true });
    } catch (_) {}

    const actions = {
        downloaded: 0,
        updated: 0,
        deleted: 0,
        unchanged: 0,
    };
    let deletedAny = false;

    // Delete removed configs (and their files/meta).
    prevList.forEach((r) => {
        if (!r || typeof r !== 'object') return;
        const prevId = typeof r.id === 'string' && r.id.trim() ? r.id.trim() : '';
        const prevUrl = typeof r.url === 'string' && r.url.trim() ? r.url.trim() : '';
        const identity = prevId || prevUrl;
        if (!identity || seenKeys.has(identity)) return;
        const fileName = typeof r.fileName === 'string' ? r.fileName.trim() : '';
        if (!fileName) return;
        const destPath = path.resolve(onlineDir, fileName);
        const metaPath = path.resolve(onlineDir, `.${fileName}.remote.json`);
        try {
            if (fs.existsSync(destPath)) fs.unlinkSync(destPath);
        } catch (_) {}
        try {
            if (fs.existsSync(metaPath)) fs.unlinkSync(metaPath);
        } catch (_) {}
        deletedAny = true;
        actions.deleted += 1;
    });

    const persistedNext = [];
    const results = nextItems.map((it) => ({
        key: it.key,
        id: it.id,
        name: it.name,
        url: it.url,
        fileName: '',
        ok: false,
        status: 'error',
        _downloadError: '',
        _action: '',
    }));

    for (let i = 0; i < results.length; i += 1) {
        const item = results[i];

        let parsed;
        try {
            parsed = new URL(String(item.url || '').trim());
        } catch (_) {
            parsed = null;
        }
        if (!parsed || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')) {
            item._downloadError = 'invalid url';
            continue;
        }

        const prev = item.id ? prevById.get(item.id) : prevByUrl.get(parsed.toString());
        const fileName = prev && typeof prev.fileName === 'string' && prev.fileName.trim() ? prev.fileName.trim() : buildOnlineConfigFileName(item.key, parsed.toString());
        item.fileName = fileName;

        const destPath = path.resolve(onlineDir, fileName);
        const metaPath = path.resolve(onlineDir, `.${fileName}.remote.json`);

        const relName = path.relative(customDir, destPath).split(path.sep).join('/');
        if (!relName || !relName.startsWith(`online/`)) {
            item._downloadError = 'invalid dest';
            continue;
        }

        const exists = (() => {
            try {
                return fs.existsSync(destPath);
            } catch (_) {
                return false;
            }
        })();

        const localMeta = readJsonFileSafe(metaPath) || {};
        let shouldDownload = !exists;
        let headMeta = null;

        const prevUrl = prev && typeof prev.url === 'string' ? prev.url.trim() : '';
        if (!shouldDownload && prevUrl && prevUrl !== parsed.toString()) {
            shouldDownload = true;
        }

        if (!shouldDownload) {
            headMeta = await headRemoteMeta(parsed.toString(), { timeoutMs: 8000 });
            if (headMeta && headMeta.ok) {
                const remoteEtag = String(headMeta.etag || '').trim();
                const remoteLm = String(headMeta.lastModified || '').trim();
                const localEtag = typeof localMeta.etag === 'string' ? localMeta.etag.trim() : '';
                const localLm = typeof localMeta.lastModified === 'string' ? localMeta.lastModified.trim() : '';
                const hasRemote = !!(remoteEtag || remoteLm);
                if (hasRemote) {
                    const etagChanged = remoteEtag && localEtag && remoteEtag !== localEtag;
                    const lmChanged = remoteLm && localLm && remoteLm !== localLm;
                    if (etagChanged || lmChanged) shouldDownload = true;
                }

                // Persist meta headers if missing locally (quietly).
                const hasLocal = !!(localEtag || localLm);
                if (!hasLocal && (remoteEtag || remoteLm)) {
                    try {
                        writeJsonFileAtomic(metaPath, {
                            url: parsed.toString(),
                            etag: remoteEtag,
                            lastModified: remoteLm,
                            savedAt: Date.now(),
                        });
                    } catch (_) {}
                }
            }
        }

        if (shouldDownload) {
            try {
                const downloaded = await downloadTextFile(parsed.toString(), { maxBytes: 5 * 1024 * 1024, timeoutMs: 20000 });
                atomicWriteFileWithRollback(destPath, downloaded.text || '');
                const etag =
                    downloaded && downloaded.res && downloaded.res.headers && typeof downloaded.res.headers.get === 'function'
                        ? downloaded.res.headers.get('etag') || (headMeta ? headMeta.etag : '')
                        : headMeta
                          ? headMeta.etag
                          : '';
                const lastModified =
                    downloaded && downloaded.res && downloaded.res.headers && typeof downloaded.res.headers.get === 'function'
                        ? downloaded.res.headers.get('last-modified') || (headMeta ? headMeta.lastModified : '')
                        : headMeta
                          ? headMeta.lastModified
                          : '';
                try {
                    writeJsonFileAtomic(metaPath, {
                        url: parsed.toString(),
                        etag: typeof etag === 'string' ? etag : '',
                        lastModified: typeof lastModified === 'string' ? lastModified : '',
                        savedAt: Date.now(),
                    });
                } catch (_) {}
                if (!exists) {
                    actions.downloaded += 1;
                    item._action = 'downloaded';
                } else {
                    actions.updated += 1;
                    item._action = 'updated';
                }
            } catch (_) {
                item._downloadError = 'download failed';
                continue;
            }
        } else {
            actions.unchanged += 1;
            item._action = 'unchanged';
        }

        persistedNext.push({
            url: parsed.toString(),
            fileName,
            name: item.name || '',
            id: item.id && item.id !== parsed.toString() ? item.id : '',
        });
    }

    // Preload once and then map errors per file.
    try {
        await loadCustomSourceSpiders();
    } catch (_) {}
    const status = getCustomSourceStatus();
    let passedCount = 0;
    results.forEach((item) => {
        if (!item.fileName || item._downloadError) {
            item.ok = false;
            item.status = 'error';
            return;
        }
        const relName = `online/${item.fileName}`;
        const err = getCustomSourceErrorForFile(status, relName);
        if (err) {
            item.ok = false;
            item.status = 'error';
            return;
        }
        item.ok = true;
        item.status = 'pass';
        passedCount += 1;
    });

    const changedAny = deletedAny || actions.downloaded > 0 || actions.updated > 0;
    const shouldExit = changedAny && (passedCount > 0 || deletedAny || results.length === 0);

    // Strip internal fields for API output.
    const publicResults = results.map((r) => ({
        id: r.id,
        name: r.name,
        url: r.url,
        fileName: r.fileName,
        status: r.status === 'pass' ? 'pass' : 'error',
    }));

    return {
        results: publicResults,
        persisted: persistedNext,
        actions,
        changedAny,
        deletedAny,
        passedCount,
        shouldExit,
    };
}

async function downloadTextFile(url, options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const maxBytes = Number.isFinite(Number(opts.maxBytes)) ? Math.max(1, Math.trunc(Number(opts.maxBytes))) : 2 * 1024 * 1024;
    const timeoutMs = Number.isFinite(Number(opts.timeoutMs)) ? Math.max(100, Math.trunc(Number(opts.timeoutMs))) : 15000;

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
        const res = await fetch(url, {
            method: 'GET',
            headers: { accept: 'text/plain,application/javascript,*/*' },
            signal: controller ? controller.signal : undefined,
        });
        if (!res || !res.ok) {
            const status = res ? Number(res.status) : 0;
            throw new Error(`download failed: status=${status || 'unknown'}`);
        }
        const len = res.headers && typeof res.headers.get === 'function' ? Number(res.headers.get('content-length') || 0) : 0;
        if (len && Number.isFinite(len) && len > maxBytes) throw new Error(`download too large: ${len} bytes`);

        let buf;
        if (res.arrayBuffer) {
            const ab = await res.arrayBuffer();
            // eslint-disable-next-line no-undef
            buf = Buffer.from(ab);
        } else {
            const text = await res.text();
            // eslint-disable-next-line no-undef
            buf = Buffer.from(String(text || ''), 'utf8');
        }
        if (buf.length > maxBytes) throw new Error(`download too large: ${buf.length} bytes`);
        return { text: buf.toString('utf8'), res };
    } finally {
        if (timer) clearTimeout(timer);
    }
}

function normalizeCorsAllowOrigins(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value.map((v) => String(v || '').trim()).filter(Boolean);
    const s = String(value || '').trim();
    if (!s) return [];
    return s
        .split(',')
        .map((v) => String(v || '').trim())
        .filter(Boolean);
}

function readCorsAllowOriginsFromEnv() {
    const raw =
        (typeof process.env.CATPAW_CORS_ALLOW_ORIGINS === 'string' && process.env.CATPAW_CORS_ALLOW_ORIGINS) ||
        (typeof process.env.CATPAWOPEN_CORS_ALLOW_ORIGINS === 'string' && process.env.CATPAWOPEN_CORS_ALLOW_ORIGINS) ||
        '';
    return normalizeCorsAllowOrigins(raw);
}

function readCorsAllowCredentialsFromEnv() {
    const raw =
        (typeof process.env.CATPAW_CORS_ALLOW_CREDENTIALS === 'string' && process.env.CATPAW_CORS_ALLOW_CREDENTIALS) ||
        (typeof process.env.CATPAWOPEN_CORS_ALLOW_CREDENTIALS === 'string' &&
            process.env.CATPAWOPEN_CORS_ALLOW_CREDENTIALS) ||
        '';
    const s = String(raw || '').trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function readCorsAllowOriginsFromConfigRoot(root) {
    const cfg = root && typeof root === 'object' ? root : {};
    if (Object.prototype.hasOwnProperty.call(cfg, 'corsAllowOrigins')) return normalizeCorsAllowOrigins(cfg.corsAllowOrigins);
    if (Object.prototype.hasOwnProperty.call(cfg, 'corsOrigins')) return normalizeCorsAllowOrigins(cfg.corsOrigins);
    if (Object.prototype.hasOwnProperty.call(cfg, 'cors')) return normalizeCorsAllowOrigins(cfg.cors);
    return [];
}

function readCorsAllowCredentialsFromConfigRoot(root) {
    const cfg = root && typeof root === 'object' ? root : {};
    const v =
        Object.prototype.hasOwnProperty.call(cfg, 'corsAllowCredentials')
            ? cfg.corsAllowCredentials
            : Object.prototype.hasOwnProperty.call(cfg, 'corsCredentials')
              ? cfg.corsCredentials
              : null;
    if (v == null) return false;
    if (typeof v === 'boolean') return v;
    const s = String(v || '').trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function isLocalhostOrigin(origin) {
    try {
        const u = new URL(String(origin || ''));
        const host = String(u.hostname || '').toLowerCase();
        return host === 'localhost' || host === '127.0.0.1' || host === '::1';
    } catch (_) {
        return false;
    }
}

function originMatchesRule(origin, rule) {
    const o = String(origin || '').trim();
    const r = String(rule || '').trim();
    if (!o || !r) return false;
    if (r === '*') return true;

    let ou;
    try {
        ou = new URL(o);
    } catch (_) {
        return false;
    }
    const oProto = String(ou.protocol || '');
    const oHost = String(ou.hostname || '').toLowerCase();
    const oOrigin = `${oProto}//${String(ou.host || '')}`;

    if (r.includes('://')) {
        if (r.includes('*')) {
            let ru;
            try {
                ru = new URL(r.replace('*.', 'placeholder.'));
            } catch (_) {
                return false;
            }
            if (ru.protocol && ru.protocol !== ou.protocol) return false;
            const suffix = String(ru.hostname || '').replace(/^placeholder\./, '').toLowerCase();
            return oHost.endsWith(`.${suffix}`);
        }
        try {
            const ru = new URL(r);
            const rOrigin = `${ru.protocol}//${String(ru.host || '')}`;
            return rOrigin === oOrigin;
        } catch (_) {
            return false;
        }
    }

    if (r.startsWith('*.')) {
        const suffix = r.slice(2).toLowerCase();
        return oHost.endsWith(`.${suffix}`);
    }
    return oHost === r.toLowerCase();
}

function mergeVaryHeader(reply, value) {
    try {
        const cur = typeof reply.getHeader === 'function' ? String(reply.getHeader('Vary') || '') : '';
        const parts = cur
            ? cur
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean)
            : [];
        const wanted = String(value || '').trim();
        if (!wanted) return;
        if (parts.some((p) => p.toLowerCase() === wanted.toLowerCase())) return;
        parts.push(wanted);
        reply.header('Vary', parts.join(', '));
    } catch (_) {}
}

function setCorsHeaders(reply, origin, requestHeaders) {
    if (!reply || typeof reply.header !== 'function') return false;
    const o = String(origin || '').trim();
    if (!o) return false;

    const envOrigins = readCorsAllowOriginsFromEnv();
    const envCreds = readCorsAllowCredentialsFromEnv();
    const allowOrigins = envOrigins.length ? envOrigins : corsAllowOriginsCache && corsAllowOriginsCache.length ? corsAllowOriginsCache : ['*'];
    const allowCreds = envOrigins.length ? envCreds : corsAllowOriginsCache && corsAllowOriginsCache.length ? corsAllowCredentialsCache : false;

    const already = (() => {
        try {
            if (typeof reply.getHeader !== 'function') return false;
            return !!(reply.getHeader('access-control-allow-origin') || reply.getHeader('Access-Control-Allow-Origin'));
        } catch (_) {
            return false;
        }
    })();
    if (already) return false;

    let allowed = false;
    let allowOriginValue = '';
    if (allowOrigins && allowOrigins.length) {
        if (allowOrigins.some((v) => String(v || '').trim() === '*')) {
            allowed = true;
            allowOriginValue = allowCreds ? o : '*';
        } else if (allowOrigins.some((rule) => originMatchesRule(o, rule))) {
            allowed = true;
            allowOriginValue = o;
        }
    } else if (isLocalhostOrigin(o)) {
        allowed = true;
        allowOriginValue = o;
    }
    if (!allowed || !allowOriginValue) return false;

    reply.header('Access-Control-Allow-Origin', allowOriginValue);
    mergeVaryHeader(reply, 'Origin');
    reply.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    reply.header('Access-Control-Max-Age', '600');

    const reqH =
        (requestHeaders && (requestHeaders['access-control-request-headers'] || requestHeaders['Access-Control-Request-Headers'])) ||
        '';
    const allowHeaders = String(reqH || '').trim() || 'content-type,x-tv-user';
    reply.header('Access-Control-Allow-Headers', allowHeaders);
    if (allowCreds) reply.header('Access-Control-Allow-Credentials', 'true');
    return true;
}

function setAdminCors(reply, origin, requestHeaders) {
    return setCorsHeaders(reply, origin, requestHeaders);
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

function ensureWebsiteConfigShape(config) {
    const base = config && typeof config === 'object' ? config : {};
    const ensureObj = (key) => {
        const cur = base[key];
        if (!cur || typeof cur !== 'object' || Array.isArray(cur)) base[key] = {};
    };

    // website 配置中心（my.js）会读取这些 config.<key>.<field> 作为默认值/兜底；缺失会导致 undefined.cookie 报错
    [
        'baidu',
        'quark',
        'uc',
        'y115',
        'pan123ziyuan',
        'bili',
        'wuming',
        'ali',
        'tgsou',
        'tgchannel',
        'pans',
        'sites',
        'muou',
        'leijing',
        'wogg',
        'livetovod',
        'adapter',
    ].forEach(ensureObj);

    // Avoid `.filter/.some` crashes when website expects arrays.
    if (!Array.isArray(base.pans.list)) base.pans.list = [];
    if (!Array.isArray(base.sites.list)) base.sites.list = [];

    return base;
}

function mergeSpiders(baseSpiders, extraSpiders) {
    const byId = new Map();
    [...(baseSpiders || []), ...(extraSpiders || [])].forEach((spider) => {
        const key = spider && spider.meta ? spider.meta.key : null;
        const type = spider && spider.meta ? spider.meta.type : null;
        if (!key || type == null) return;
        const id = `${key}:${type}`;
        byId.set(id, spider);
    });
    return Array.from(byId.values());
}

function resolveSpiderRootDir() {
    const embedded = path.resolve(getEmbeddedRootDir(), 'src', 'spider');
    // When packaged by pkg, always prefer embedded spiders inside the executable snapshot.
    // This avoids accidentally loading a partial on-disk source tree (missing deps / wrong module type),
    // and makes the standalone binary self-contained.
    try {
        if (process && process.pkg) return embedded;
    } catch (_) {}

    const externalRoot = getExternalRootDir();
    const external = externalRoot ? path.resolve(externalRoot, 'src', 'spider') : '';
    try {
        if (external && fs.existsSync(external)) return external;
    } catch (_) {}
    return embedded;
}

function listSpiderJsFiles(rootDir) {
    if (!rootDir || !fs.existsSync(rootDir)) return [];
    const out = [];
    const stack = [rootDir];
    while (stack.length) {
        const dir = stack.pop();
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (_) {
            continue;
        }
        entries.forEach((ent) => {
            const name = ent.name || '';
            if (!name || name.startsWith('.') || name.startsWith('_')) return;
            const full = path.join(dir, name);
            if (ent.isDirectory()) {
                stack.push(full);
                return;
            }
            if (!ent.isFile()) return;
            if (!name.endsWith('.js')) return;
            out.push(full);
        });
    }
    return out.sort((a, b) => a.localeCompare(b, 'en'));
}

async function loadSpidersFromFiles(filePaths, options = {}) {
    const { logPrefix = '[spider]' } = options || {};
    const spiders = [];
    for (const filePath of Array.isArray(filePaths) ? filePaths : []) {
        try {
            const mod = await import(pathToFileURL(filePath).href);
            const candidate = mod && mod.default ? mod.default : null;
            if (isSpiderLike(candidate)) {
                spiders.push(candidate);
            }
        } catch (err) {
            const msg = err && err.message ? err.message : String(err);
            // eslint-disable-next-line no-console
            console.error(`${logPrefix} load failed: file=${filePath} error=${msg}`);
            try {
                if (process.env.CATPAW_DEBUG === '1' && err && err.stack) {
                    // eslint-disable-next-line no-console
                    console.error(err.stack);
                }
            } catch (_) {}
        }
    }
    return spiders;
}

function getGlobalPanDirNameForCurrentUser() {
    const base = String('TV_Server')
        .trim()
        .replace(/[^a-zA-Z0-9._-]+/g, '_')
        .replace(/^_+|_+$/g, '') || 'TV_Server';
    return base;
}

function decodeTvServerPlayId(rawId) {
    const idStr = String(rawId || '');
    if (!idStr) return { json: null, name: '' };

    const delims = ['|||', '######', '@@@', '***', '___'];
    let b64 = idStr;
    let name = '';
    for (const d of delims) {
        const idx = idStr.indexOf(d);
        if (idx >= 0) {
            b64 = idStr.slice(0, idx);
            name = idStr.slice(idx + d.length);
            break;
        }
    }

    // Support urlsafe base64 and missing padding.
    let normalized = String(b64 || '').trim();
    normalized = normalized.replace(/-/g, '+').replace(/_/g, '/');
    while (normalized.length % 4 !== 0) normalized += '=';

    let json = null;
    try {
        const buf = Buffer.from(normalized, 'base64');
        const text = buf.toString('utf8');
        const parsed = text && text.trim() ? JSON.parse(text) : null;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) json = parsed;
    } catch (_) {
        json = null;
    }
    return { json, name: String(name || '') };
}

/**
 * A function to initialize the router.
 *
 * @param {Object} fastify - The Fastify instance
 * @return {Promise<void>} - A Promise that resolves when the router is initialized
 */
export default async function router(fastify) {
    const startupProfile =
        (typeof process.env.CATPAW_STARTUP_PROFILE === 'string' && process.env.CATPAW_STARTUP_PROFILE.trim() === '1') ||
        (typeof process.env.CATPAWOPEN_STARTUP_PROFILE === 'string' && process.env.CATPAWOPEN_STARTUP_PROFILE.trim() === '1');
    const t0 = Date.now();
    const mark = (label) => {
        if (!startupProfile) return;
        const ms = Date.now() - t0;
        // eslint-disable-next-line no-console
        console.log(`[startup] ${ms}ms ${label}`);
    };

    // Load persisted settings from config.json on startup.
    try {
        const cfgPath = getConfigJsonPath();
        const root = readConfigJsonSafe(cfgPath);
        if (root && typeof root.proxy === 'string') {
            await setGlobalProxy(root.proxy);
        }
        panBuiltinResolverEnabledCache = readPanBuiltinResolverEnabledFromConfigRoot(root);
        corsAllowOriginsCache = readCorsAllowOriginsFromConfigRoot(root);
        corsAllowCredentialsCache = readCorsAllowCredentialsFromConfigRoot(root);
    } catch (_) {}
    mark('config loaded');

    fastify.addHook('onRequest', (request, reply, done) => {
        try {
            const origin = request && request.headers ? request.headers.origin : '';
            setCorsHeaders(reply, origin, request && request.headers ? request.headers : {});
        } catch (_) {}
        done();
    });

    fastify.options('/*', async function (request, reply) {
        try {
            const origin = request && request.headers ? request.headers.origin : '';
            setCorsHeaders(reply, origin, request && request.headers ? request.headers : {});
        } catch (_) {}
        reply.code(204).send();
    });

    // Propagate TV_Server user identity through the async call chain so custom-script VM wrappers
    // (e.g. Quark folder init) can resolve per-user working directories safely.
    fastify.addHook('onRequest', (request, _reply, done) => {
        try {
            const ip =
                (request && request.raw && request.raw.socket && request.raw.socket.remoteAddress) ||
                (request && request.ip) ||
                '';
            const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip === '::ffff:7f00:1';

            // If caller didn't specify a user identity, default to:
            // - loopback requests: `test` (for local/manual testing)
            // - non-loopback requests: `admin`
            const user = hasExplicitTvUser(request) ? getTvUserFromRequest(request) : isLoopback ? 'test' : 'admin';
            tvUserStorage.enterWith({ user });
        } catch (_) {}
        done();
    });

    fastify.addHook('preHandler', async (request, reply) => {
        try {
            const urlPath = (request && request.raw && request.raw.url) || request.url || '';
            if (!isSpiderPlayPath(urlPath)) return;
            if (!panBuiltinResolverEnabledCache) return;
            if (String(request.method || '').toUpperCase() !== 'POST') return;

            const body = request && request.body != null ? request.body : null;
            let parsed = body;
            if (typeof parsed === 'string') {
                try {
                    parsed = parsed.trim() ? JSON.parse(parsed) : {};
                } catch (_) {
                    parsed = {};
                }
            }
            if (!parsed || typeof parsed !== 'object') parsed = {};

            const flag = typeof parsed.flag === 'string' ? parsed.flag : '';
            const id = typeof parsed.id === 'string' ? parsed.id : '';
            if (!id) return;
            const isBaidu = flag.includes('百度');
            const isQuark = flag.includes('夸克') || flag.includes('夸父') || flag.toLowerCase().includes('quark');
            if (!isBaidu && !isQuark) return;

            const rawUrl = (request && request.raw && request.raw.url) || request.url || '';
            const queryStr = rawUrl.includes('?') ? rawUrl.slice(rawUrl.indexOf('?')) : '';
            const destName = getGlobalPanDirNameForCurrentUser();
            const tvUser = getTvUserFromRequest(request);
            const injected = await fastify.inject({
                method: 'POST',
                url: isBaidu ? `/api/baidu/play${queryStr}` : `/api/quark/play${queryStr}`,
                headers: {
                    'content-type': 'application/json',
                    ...(tvUser ? { 'x-tv-user': tvUser } : {}),
                },
                payload: { flag, id, destName },
            });
            const text = injected && typeof injected.payload === 'string' ? injected.payload : '';
            let out = {};
            try {
                out = text ? JSON.parse(text) : {};
            } catch (_) {
                out = { ok: false, message: 'builtin baidu play returned non-json payload' };
            }
            return reply.code(injected.statusCode || 200).send(out);
        } catch (e) {
            const msg = e && e.message ? String(e.message) : 'builtin baidu play failed';
            return reply.code(502).send({ ok: false, message: msg });
        }
    });

    // Rewrite play response URLs like `http://127.0.0.1:PORT/...` into the externally accessed origin.
    // This keeps clients from needing a local CatPawOpen instance.
    fastify.addHook('preSerialization', (request, _reply, payload, done) => {
        try {
            const urlPath = (request && request.raw && request.raw.url) || request.url || '';
            if (!isSpiderPlayPath(urlPath)) return done(null, payload);
            const externalOrigin = getExternalOriginFromRequest(request);
            if (!externalOrigin) return done(null, payload);
            if (payload && typeof payload === 'object') rewriteLocalUrlsDeep(payload, externalOrigin);
        } catch (_) {}
        done(null, payload);
    });
    fastify.addHook('onSend', async (request, reply, payload) => {
        try {
            const urlPath = (request && request.raw && request.raw.url) || request.url || '';
            if (!isSpiderPlayPath(urlPath)) return payload;
            const externalOrigin = getExternalOriginFromRequest(request);
            if (!externalOrigin) return payload;
            const ct = String(reply.getHeader('content-type') || '').toLowerCase();
            const isJson = ct.includes('application/json') || ct.includes('+json');
            const text = Buffer.isBuffer(payload) ? payload.toString('utf8') : typeof payload === 'string' ? payload : '';
            if (!isJson && (!text.startsWith('{') && !text.startsWith('['))) return payload;
            const parsed = text ? JSON.parse(text) : null;
            if (!parsed || typeof parsed !== 'object') return payload;
            rewriteLocalUrlsDeep(parsed, externalOrigin);
            return JSON.stringify(parsed);
        } catch (_) {
            return payload;
        }
    });

    // CORS is handled by this service via an allowlist (config/env). Reverse proxy CORS is optional.

    // 默认站点：动态 import src/spider 下所有 js（含子目录），不再写死列表
    const spiderRootDir = resolveSpiderRootDir();
    mark(`spider root resolved: ${spiderRootDir}`);
    const baseFiles = listSpiderJsFiles(spiderRootDir);
    mark(`spider files listed: ${baseFiles.length}`);
    const baseSpiders = await loadSpidersFromFiles(baseFiles, { logPrefix: '[builtin]' });
    mark(`builtin spiders loaded: ${(baseSpiders || []).length}`);

    const customSpiders = await loadCustomSourceSpiders();
    mark(`custom spiders loaded: ${(customSpiders || []).length}`);
    const customStatus = getCustomSourceStatus();
    const customIds = new Set(
        (customSpiders || [])
            .map((s) => (s && s.meta ? `${s.meta.key}:${String(s.meta.type)}` : ''))
            .filter(Boolean)
    );
    const effectiveBaseSpiders = (baseSpiders || []).filter(
        (s) => !(s && s.meta && customIds.has(`${s.meta.key}:${String(s.meta.type)}`))
    );
    mark(`effective builtin spiders: ${(effectiveBaseSpiders || []).length}`);

    // 1) 先注册默认 spiders
    effectiveBaseSpiders.forEach((spider) => {
        const routePath = spiderPrefix + '/' + spider.meta.key + '/' + spider.meta.type;
        fastify.register(spider.api, { prefix: routePath });
        // eslint-disable-next-line no-console
        console.log('Register spider: ' + routePath);
    });
    mark('builtin spiders registered');

    // 2) 输出自定义脚本的加载统计（按文件拆分）
    const byFile = (customStatus && customStatus.byFile) || {};
    Object.keys(byFile)
        .sort((a, b) => a.localeCompare(b, 'en'))
        .forEach((fileName) => {
            const info = byFile[fileName] || {};
            const loaded = Number.isFinite(Number(info.loaded)) ? Number(info.loaded) : 0;
            const errors = Number.isFinite(Number(info.errors)) ? Number(info.errors) : 0;
            // eslint-disable-next-line no-console
            console.log(`Custom spiders ${fileName} loaded: ${loaded} errors=${errors}`);
        });

    // 3) 最后注册自定义 spiders，并在日志中标注来源文件
    customSpiders.forEach((spider) => {
        const routePath = spiderPrefix + '/' + spider.meta.key + '/' + spider.meta.type;
        fastify.register(spider.api, { prefix: routePath });
        const fileName = spider && spider.__customFile ? String(spider.__customFile) : 'custom';
        // eslint-disable-next-line no-console
        console.log(`Register custom spider ${fileName} : ${routePath}`);
    });
    mark('custom spiders registered');

    // 4) 补全 /website：直接输出自定义脚本的 websiteBundle()（浏览器执行），不改写任何路由
    // 优先：注册自定义脚本提供的 Fastify 插件（例如 my.js 的 Yne），确保 /website 下所有子路由都存在
    const apiPlugins = getCustomSourceApiPlugins();
    (apiPlugins || [])
        .filter((p) => p && typeof p.prefix === 'string' && p.prefix && typeof p.plugin === 'function')
        .forEach((p) => {
            fastify.register(p.plugin, { prefix: p.prefix });
            const from = p.fileName || p.__customFile || 'custom';
            // eslint-disable-next-line no-console
            console.log(`Register api plugin: ${p.prefix} (from ${from})`);
        });
    mark(`api plugins registered: ${(apiPlugins || []).length}`);

    const webPlugins = getCustomSourceWebPlugins();
    // Register other extracted web prefixes first (optional helpers used by some website UIs)
    (webPlugins || [])
        .filter((p) => p && typeof p.prefix === 'string' && p.prefix && p.prefix !== '/website' && typeof p.plugin === 'function')
        .forEach((p) => {
            fastify.register(p.plugin, { prefix: p.prefix });
            const from = p.fileName || p.__customFile || 'custom';
            // eslint-disable-next-line no-console
            console.log(`Register web plugin: ${p.prefix} (from ${from})`);
        });
    mark(`web plugins registered: ${(webPlugins || []).length}`);

    const websitePlugin =
        (webPlugins || []).find((p) => p && p.prefix === '/website' && typeof p.plugin === 'function') || null;
    if (websitePlugin) {
        // Wrap plugin to normalize request body shape for handlers expecting `request.body.data.*`
        // while keeping top-level fields for other handlers (e.g. /account, /backup).
        fastify.register(
            async function websiteWrapper(instance) {
                instance.config = ensureWebsiteConfigShape(instance.config);
                instance.addHook('preValidation', async function (request) {
                    if (!request) return;
                    const method = String(request.method || '').toUpperCase();
                    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return;

                    let body = request.body;
                    if (body == null) {
                        request.body = { data: {} };
                        return;
                    }

                    // Fastify may parse some content-types as string/Buffer; normalize to object.
                    if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
                        body = Buffer.from(body).toString('utf8');
                    }

                    if (typeof body === 'string') {
                        const trimmed = body.trim();
                        if (!trimmed) {
                            request.body = { data: {} };
                            return;
                        }

                        // JSON body-as-string
                        if (
                            (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
                            (trimmed.startsWith('[') && trimmed.endsWith(']'))
                        ) {
                            try {
                                body = JSON.parse(trimmed);
                            } catch (_) {
                                body = trimmed;
                            }
                        }

                        // x-www-form-urlencoded (e.g. cookie=xxx or data[cookie]=xxx)
                        if (typeof body === 'string' && body.includes('=')) {
                            try {
                                const params = new URLSearchParams(body);
                                const plain = {};
                                for (const [k, v] of params.entries()) plain[k] = v;
                                const cookie =
                                    plain.cookie ??
                                    plain['data[cookie]'] ??
                                    plain['data.cookie'] ??
                                    plain['data%5Bcookie%5D'];
                                if (cookie !== undefined) {
                                    request.body = Object.assign({}, plain, { data: Object.assign({}, plain, { cookie }) });
                                    return;
                                }
                                request.body = Object.assign({}, plain, { data: plain });
                                return;
                            } catch (_) {
                                // fallthrough to cookie-as-plain-string
                            }
                        }

                        // Plain string payload; best-effort treat it as cookie for compatibility.
                        request.body = { data: { cookie: body } };
                        return;
                    }

                    if (!body || typeof body !== 'object' || Array.isArray(body)) {
                        request.body = { data: {} };
                        return;
                    }

                    // Add `data` as a shallow copy of the original body to satisfy `body.data.xxx` access.
                    if (body.data === undefined || body.data === null) {
                        request.body = Object.assign({}, body, { data: body });
                        return;
                    }
                    if (typeof body.data !== 'object' || Array.isArray(body.data)) {
                        request.body = Object.assign({}, body, { data: Object.assign({}, body) });
                    }
                });
                return websitePlugin.plugin(instance);
            },
            { prefix: '/website' }
        );
        // eslint-disable-next-line no-console
        console.log(
            `Register website plugin: /website (from ${websitePlugin.fileName || websitePlugin.__customFile || 'custom'})`
        );
        // baseset may reference `/website2`; keep it redirecting to `/website/`.
        fastify.get('/website2', async function (_request, reply) {
            reply.redirect(302, '/website');
        });
        fastify.get('/website2/', async function (_request, reply) {
            reply.redirect(302, '/website');
        });
    }

    // 兜底：如果没有插件，则仅输出前端页面（只能展示，无法保存配置）
    const websiteBundles = getCustomSourceWebsiteBundles();
    const chosenWebsite =
        (websiteBundles || []).find((it) => it && it.fileName === 'my.js') || (websiteBundles || [])[0] || null;
    if (!websitePlugin && chosenWebsite && typeof chosenWebsite.websiteJs === 'string' && chosenWebsite.websiteJs.trim()) {
        const websiteJs = chosenWebsite.websiteJs;
        const getWebsiteHtml = () => {
            if (!websiteJs.trim()) return '';

            return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>website</title>
  </head>
  <body>
    <div id="app"></div>
    <script crossorigin src="https://lib.baomitu.com/react/18.2.0/umd/react.production.min.js"></script>
    <script crossorigin src="https://lib.baomitu.com/react-dom/18.2.0/umd/react-dom.production.min.js"></script>
    <script crossorigin src="https://lib.baomitu.com/axios/0.26.0/axios.min.js"></script>
    <script crossorigin src="https://lib.baomitu.com/dayjs/1.10.8/dayjs.min.js"></script>
    <script crossorigin src="https://lib.baomitu.com/antd/5.23.3/antd.min.js"></script>
    <link rel="stylesheet" href="https://lib.baomitu.com/antd/5.23.3/reset.min.css">
    <script>${websiteJs}</script>
  </body>
</html>`;
        };

        const websiteHandler = async function (_request, reply) {
            const html = getWebsiteHtml();
            if (!html) {
                reply.code(500).send({ message: 'websiteBundle() returned empty content' });
                return;
            }
            reply.type('text/html; charset=utf-8').send(html);
        };

        // Support both `/website` and `/website/` to avoid "route not found" from clients that append `/`.
        fastify.get('/website', websiteHandler);
        fastify.get('/website/', websiteHandler);
        fastify.get('/website2', async function (_request, reply) {
            reply.redirect(302, '/website');
        });
        fastify.get('/website2/', async function (_request, reply) {
            reply.redirect(302, '/website');
        });
        // eslint-disable-next-line no-console
        console.log(`Register website: /website (from ${chosenWebsite.fileName || 'custom'})`);
    } else {
        if (!websitePlugin) {
            // eslint-disable-next-line no-console
            console.log('Register website skipped: websiteBundle() not found in custom scripts');
        }
    }

    // Unified admin settings endpoint so clients can persist proxy + pan settings with a single request.
    fastify.get('/admin/settings', async function (_request, reply) {
        const cfgPath = getConfigJsonPath();
        const root = readConfigJsonSafe(cfgPath);
        const onlineConfigs = root && Array.isArray(root.onlineConfigs) ? root.onlineConfigs : [];
        const envCorsOrigins = readCorsAllowOriginsFromEnv();
        const envCorsCreds = readCorsAllowCredentialsFromEnv();
        return reply.send({
            success: true,
            settings: {
                proxy: getGlobalProxy() || '',
                panBuiltinResolverEnabled: readPanBuiltinResolverEnabledFromConfigRoot(root),
                corsAllowOrigins: envCorsOrigins.length ? envCorsOrigins : readCorsAllowOriginsFromConfigRoot(root),
                corsAllowCredentials: envCorsOrigins.length ? envCorsCreds : readCorsAllowCredentialsFromConfigRoot(root),
            },
            onlineConfigs,
        });
    });

    fastify.put('/admin/settings', async function (request, reply) {
        const body = request && request.body && typeof request.body === 'object' ? request.body : {};
        const cfgPath = getConfigJsonPath();
        const prev = readConfigJsonSafe(cfgPath);

        const hasProxy = Object.prototype.hasOwnProperty.call(body, 'proxy');
        const proxy = hasProxy && typeof body.proxy === 'string' ? body.proxy : getGlobalProxy() || '';
        const hasPanBuiltin = Object.prototype.hasOwnProperty.call(body, 'panBuiltinResolverEnabled');
        const panBuiltinResolverEnabled = hasPanBuiltin ? !!body.panBuiltinResolverEnabled : readPanBuiltinResolverEnabledFromConfigRoot(prev);

        const hasCorsAllowOrigins = Object.prototype.hasOwnProperty.call(body, 'corsAllowOrigins');
        const corsAllowOrigins = hasCorsAllowOrigins
            ? normalizeCorsAllowOrigins(body.corsAllowOrigins)
            : readCorsAllowOriginsFromConfigRoot(prev);
        const hasCorsAllowCredentials = Object.prototype.hasOwnProperty.call(body, 'corsAllowCredentials');
        const corsAllowCredentials = hasCorsAllowCredentials
            ? !!body.corsAllowCredentials
            : readCorsAllowCredentialsFromConfigRoot(prev);

        let applied = proxy;
        try {
            applied = await setGlobalProxy(proxy);
        } catch (e) {
            const msg = e && e.message ? String(e.message) : 'proxy apply failed';
            return reply.code(400).send({ success: false, message: msg });
        }

        const next = {
            ...prev,
            proxy: applied || '',
            panResolver: !!panBuiltinResolverEnabled,
            corsAllowOrigins,
            corsAllowCredentials,
        };
        // Drop deprecated keys.
        try {
            delete next.panPassthrough;
            delete next.interceptPans;
            delete next.goProxy;
            delete next.directLink;
            delete next.panBuiltinResolverEnabled;
        } catch (_) {}

        const onlineInput = normalizeOnlineConfigListInput(body);
        let onlineResult = null;
        if (onlineInput.provided) {
            if (onlineInput.list === null) {
                return reply.code(400).send({ success: false, message: 'onlineConfigs must be an array' });
            }
            const customDir = await ensureCustomSourceDirReady();
            if (!customDir) return reply.code(500).send({ success: false, message: 'custom_spider dir not resolved' });
            const prevPersisted = prev && Array.isArray(prev.onlineConfigs) ? prev.onlineConfigs : [];
            onlineResult = await reconcileOnlineConfigs(onlineInput.list, prevPersisted, customDir);
            next.onlineConfigs = onlineResult.persisted;
        }

        try {
            writeConfigJsonSafe(cfgPath, next);
        } catch (e) {
            const msg = e && e.message ? String(e.message) : 'config write failed';
            return reply.code(500).send({ success: false, message: msg });
        }

        panBuiltinResolverEnabledCache = !!panBuiltinResolverEnabled;
        corsAllowOriginsCache = corsAllowOrigins;
        corsAllowCredentialsCache = !!corsAllowCredentials;

        const payload = {
            success: true,
            settings: {
                proxy: applied || '',
                panBuiltinResolverEnabled: !!panBuiltinResolverEnabled,
                corsAllowOrigins,
                corsAllowCredentials: !!corsAllowCredentials,
            },
            ...(onlineResult
                ? {
                      onlineConfigs: onlineResult.results,
                      actions: onlineResult.actions,
                      restart: !!onlineResult.shouldExit,
                  }
                : {}),
        };

        reply.send(payload);
        if (onlineResult && onlineResult.shouldExit) {
            setTimeout(() => {
                // eslint-disable-next-line no-undef
                process.exit(1);
            }, 300);
        }
        return;
    });

    const spiders = mergeSpiders(effectiveBaseSpiders, customSpiders);

    /**
     * @api {get} /check 检查
     */
    fastify.register(
        /**
         *
         * @param {import('fastify').FastifyInstance} fastify
         */
        async (fastify) => {
            fastify.get(
                '/check',
                /**
                 * check api alive or not
                 * @param {import('fastify').FastifyRequest} _request
                 * @param {import('fastify').FastifyReply} reply
                 */
                async function (_request, reply) {
                    reply.send({ run: !fastify.stop });
                }
            );
            fastify.get(
                '/config',
                /**
                 * get catopen format config
                 * @param {import('fastify').FastifyRequest} _request
                 * @param {import('fastify').FastifyReply} reply
                 */
                async function (_request, reply) {
                    const buildConfig = () => {
                        const config = {
                            video: {
                                sites: [],
                            },
                            read: {
                                sites: [],
                            },
                            comic: {
                                sites: [],
                            },
                            music: {
                                sites: [],
                            },
                            pan: {
                                sites: [],
                            },
                            color: fastify.config.color || [],
                        };
                        spiders.forEach((spider) => {
                            let meta = Object.assign({}, spider.meta);
                            meta.api = spiderPrefix + '/' + meta.key + '/' + meta.type;
                            meta.key = 'nodejs_' + meta.key;
                            const stype = spider.meta.type;
                            if (stype < 10) {
                                config.video.sites.push(meta);
                            } else if (stype >= 10 && stype < 20) {
                                config.read.sites.push(meta);
                            } else if (stype >= 20 && stype < 30) {
                                config.comic.sites.push(meta);
                            } else if (stype >= 30 && stype < 40) {
                                config.music.sites.push(meta);
                            } else if (stype >= 40 && stype < 50) {
                                config.pan.sites.push(meta);
                            }
                        });
                        return config;
                    };
                    reply.send(buildConfig());
                }
            );
            fastify.get(
                '/full-config',
                /**
                 * website 配置中心会读取 /full-config 来构建默认站源列表
                 * @param {import('fastify').FastifyRequest} _request
                 * @param {import('fastify').FastifyReply} reply
                 */
                async function (_request, reply) {
                    // 与 /config 返回保持一致（不做 enable 过滤）
                    const config = {
                        version: getCatPawOpenVersion(),
                        video: { sites: [] },
                        read: { sites: [] },
                        comic: { sites: [] },
                        music: { sites: [] },
                        pan: { sites: [] },
                        color: fastify.config.color || [],
                    };
                    spiders.forEach((spider) => {
                        let meta = Object.assign({}, spider.meta);
                        meta.api = spiderPrefix + '/' + meta.key + '/' + meta.type;
                        meta.key = 'nodejs_' + meta.key;
                        const stype = spider.meta.type;
                        if (stype < 10) config.video.sites.push(meta);
                        else if (stype >= 10 && stype < 20) config.read.sites.push(meta);
                        else if (stype >= 20 && stype < 30) config.comic.sites.push(meta);
                        else if (stype >= 30 && stype < 40) config.music.sites.push(meta);
                        else if (stype >= 40 && stype < 50) config.pan.sites.push(meta);
                    });
                    reply.send(config);
                }
            );
            fastify.get('/custom_source', async function (_request, reply) {
                reply.send(getCustomSourceStatus());
            });
        }
    );
}
