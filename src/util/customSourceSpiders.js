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
    apiPlugins: [],
    apiErrors: {},
    apiByFile: {},
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
function parseCookieKeys(cookieStr) {
    const raw = String(cookieStr || '').trim();
    if (!raw) return [];
    const keys = [];
    for (const part of raw.split(';')) {
        const s = String(part || '').trim();
        if (!s) continue;
        const idx = s.indexOf('=');
        if (idx <= 0) continue;
        const k = s.slice(0, idx).trim();
        if (k) keys.push(k);
    }
    return keys;
}
function isBaiduLikeHost(host) {
    const h = String(host || '').trim().toLowerCase();
    if (!h) return false;
    const hostname = h.split(':')[0];
    return (
        hostname === 'pan.baidu.com' ||
        hostname.endsWith('.pan.baidu.com') ||
        hostname === 'pcs.baidu.com' ||
        hostname.endsWith('.pcs.baidu.com')
    );
}
function looksLikeIpHost(host) {
    const h = String(host || '').trim();
    if (!h) return false;
    const hostname = h.split(':')[0];
    // ipv4 only; good enough for tracing
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}
function pickHeaderValue(headers, name) {
    const h = headers && typeof headers === 'object' ? headers : null;
    if (!h) return '';
    const target = String(name || '').toLowerCase();
    for (const [k, v] of Object.entries(h)) {
        if (String(k || '').toLowerCase() === target) return v == null ? '' : String(v);
    }
    return '';
}
function maskCookieForLog(cookieStr) {
    const keys = parseCookieKeys(cookieStr);
    if (!keys.length) return '';
    const uniq = Array.from(new Set(keys));
    const head = uniq.slice(0, 12);
    const tail = uniq.length > head.length ? `...+${uniq.length - head.length}` : '';
    return `${head.join(',')}${tail}`;
}
function maskAuthForLog(authValue) {
    const raw = String(authValue || '').trim();
    if (!raw) return '';
    const parts = raw.split(/\s+/);
    const scheme = parts[0] ? parts[0].slice(0, 24) : '';
    return scheme ? `${scheme} ...` : '...';
}
function pickHeadersForLog(headers, fallbackHost) {
    const h = headers && typeof headers === 'object' ? headers : {};
    const host = pickHeaderValue(h, 'host') || String(fallbackHost || '');
    const referer = pickHeaderValue(h, 'referer');
    const origin = pickHeaderValue(h, 'origin');
    const ua = pickHeaderValue(h, 'user-agent');
    const ct = pickHeaderValue(h, 'content-type');
    const accept = pickHeaderValue(h, 'accept');
    const range = pickHeaderValue(h, 'range');
    const cookie = pickHeaderValue(h, 'cookie');
    const auth = pickHeaderValue(h, 'authorization');
    return {
        host: host || undefined,
        referer: referer || undefined,
        origin: origin || undefined,
        contentType: ct || undefined,
        accept: accept ? String(accept).slice(0, 120) : undefined,
        range: range || undefined,
        ua: ua ? String(ua).slice(0, 120) : undefined,
        cookieKeys: cookie ? maskCookieForLog(cookie) : '',
        authorization: auth ? maskAuthForLog(auth) : '',
    };
}
function isBaiduLikeUrl(urlStr) {
    const raw = typeof urlStr === 'string' ? urlStr.trim() : '';
    if (!raw) return false;
    try {
        const u = new URL(raw, 'http://0.0.0.0');
        const host = String(u.hostname || '').toLowerCase();
        return host === 'pan.baidu.com' || host.endsWith('.pan.baidu.com') || host === 'pcs.baidu.com' || host.endsWith('.pcs.baidu.com');
    } catch (_) {
        return raw.includes('pan.baidu.com') || raw.includes('pcs.baidu.com');
    }
}
function wrapFetchForTrace(fetchImpl, filePath) {
    const enabled = process.env.CATPAW_DEBUG === '1';
    if (!enabled) return fetchImpl;
    if (typeof fetchImpl !== 'function') return fetchImpl;
    if (fetchImpl.__cp_traced) return fetchImpl;
    const tag = `[trace:${path.basename(String(filePath || 'custom'))}]`;
    const wrapped = async (input, init) => {
        let urlStr = '';
        try {
            if (typeof input === 'string') urlStr = input;
            else if (input && typeof input === 'object' && typeof input.url === 'string') urlStr = input.url;
        } catch (_) {}
        const full = String(urlStr || '');
        const method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        let headersObj = {};
        try {
            const headers = (init && init.headers) || (input && input.headers) || {};
            if (headers && typeof headers === 'object') headersObj = headers;
        } catch (_) {}
        const hostHeader = pickHeaderValue(headersObj, 'host');
        const shouldLog = true;
        if (shouldLog) {
            try {
                // eslint-disable-next-line no-console
                console.log(tag, 'fetch', method, full, {
                    ...pickHeadersForLog(headersObj, hostHeader || (() => {
                        try {
                            return new URL(full).host;
                        } catch (_) {
                            return '';
                        }
                    })()),
                });
            } catch (_) {}
        }
        try {
            const res = await fetchImpl(input, init);
            if (shouldLog) {
                try {
                    const status = res && typeof res.status === 'number' ? res.status : 0;
                    // eslint-disable-next-line no-console
                    console.log(tag, 'fetchRes', status, full, {
                        contentType:
                            res && res.headers && typeof res.headers.get === 'function'
                                ? String(res.headers.get('content-type') || '')
                                : undefined,
                    });
                } catch (_) {}
            }
            return res;
        } catch (err) {
            if (shouldLog) {
                try {
                    const message = (err && err.message) || String(err);
                    // eslint-disable-next-line no-console
                    console.log(tag, 'fetchErr', full, message.slice(0, 300));
                } catch (_) {}
            }
            throw err;
        }
    };
    try {
        wrapped.__cp_traced = true;
    } catch (_) {}
    return wrapped;
}
function wrapAxiosForTrace(axios, filePath) {
    const enabled = process.env.CATPAW_DEBUG === '1';
    if (!enabled) return axios;
    if (!axios || typeof axios !== 'function') return axios;
    if (axios.__cp_traced) return axios;
    const tag = `[trace:${path.basename(String(filePath || 'custom'))}]`;
    const safeUrlFromConfig = (cfg) => {
        const c = cfg && typeof cfg === 'object' ? cfg : {};
        const baseURL = typeof c.baseURL === 'string' ? c.baseURL : '';
        const url = typeof c.url === 'string' ? c.url : '';
        if (!url && !baseURL) return '';
        try {
            return new URL(url || baseURL, baseURL || undefined).toString();
        } catch (_) {
            return `${baseURL || ''}${url || ''}`;
        }
    };
    const attach = (inst) => {
        try {
            if (!inst || !inst.interceptors || !inst.interceptors.request || !inst.interceptors.response) return inst;
            if (inst.__cp_traced) return inst;
            inst.__cp_traced = true;
            inst.interceptors.request.use((cfg) => {
                try {
                    const full = safeUrlFromConfig(cfg);
                    const method = String((cfg && cfg.method) || 'GET').toUpperCase();
                    const headers = (cfg && cfg.headers && typeof cfg.headers === 'object') ? cfg.headers : {};
                    const hostHeader = pickHeaderValue(headers, 'host') || (() => {
                        try {
                            return new URL(full).host;
                        } catch (_) {
                            return '';
                        }
                    })();
                    let dataInfo = '';
                    try {
                        const d = cfg && Object.prototype.hasOwnProperty.call(cfg, 'data') ? cfg.data : undefined;
                        if (typeof d === 'string') dataInfo = d.length > 200 ? `${d.slice(0, 200)}...(${d.length})` : d;
                        else if (Buffer.isBuffer(d)) dataInfo = `Buffer(${d.length})`;
                        else if (d && typeof d === 'object') dataInfo = `Object(${Object.keys(d).slice(0, 10).join(',')})`;
                    } catch (_) {}
                    // eslint-disable-next-line no-console
                    console.log(tag, 'req', method, full, {
                        ...pickHeadersForLog(headers, hostHeader),
                        data: dataInfo,
                    });
                } catch (_) {}
                return cfg;
            });
            inst.interceptors.response.use(
                (res) => {
                    try {
                        const cfg = res && res.config ? res.config : null;
                        const full = safeUrlFromConfig(cfg);
                        const headers = (cfg && cfg.headers && typeof cfg.headers === 'object') ? cfg.headers : {};
                        const hostHeader = pickHeaderValue(headers, 'host') || (() => {
                            try {
                                return new URL(full).host;
                            } catch (_) {
                                return '';
                            }
                        })();
                        const status = res && typeof res.status === 'number' ? res.status : 0;
                        // eslint-disable-next-line no-console
                        console.log(tag, 'res', status, full, {
                            host: hostHeader || undefined,
                            contentType:
                                res && res.headers && typeof res.headers === 'object'
                                    ? String(res.headers['content-type'] || res.headers['Content-Type'] || '')
                                    : undefined,
                        });
                    } catch (_) {}
                    return res;
                },
                (err) => {
                    try {
                        const cfg = err && err.config ? err.config : null;
                        const full = safeUrlFromConfig(cfg);
                        const headers = (cfg && cfg.headers && typeof cfg.headers === 'object') ? cfg.headers : {};
                        const hostHeader = pickHeaderValue(headers, 'host') || (() => {
                            try {
                                return new URL(full).host;
                            } catch (_) {
                                return '';
                            }
                        })();
                        const status = err && err.response && typeof err.response.status === 'number' ? err.response.status : 0;
                        const message = (err && err.message) || String(err);
                        // eslint-disable-next-line no-console
                        console.log(tag, 'err', status, full, { host: hostHeader || undefined, message: message.slice(0, 300) });
                    } catch (_) {}
                    return Promise.reject(err);
                }
            );
        } catch (_) {}
        return inst;
    };
    attach(axios);
    const wrapped = new Proxy(axios, {
        get(target, prop, receiver) {
            if (prop === 'create') {
                return (...args) => {
                    const inst = target.create(...args);
                    return attach(inst);
                };
            }
            return Reflect.get(target, prop, receiver);
        },
        apply(target, thisArg, argArray) {
            return Reflect.apply(target, thisArg, argArray);
        },
    });
    try {
        wrapped.__cp_traced = true;
    } catch (_) {}
    return wrapped;
}
function wrapNodeHttpForTrace(mod, filePath, defaultScheme) {
    const enabled = process.env.CATPAW_DEBUG === '1';
    if (!enabled) return mod;
    if (!mod || typeof mod !== 'object') return mod;
    if (mod.__cp_traced) return mod;
    const tag = `[trace:${path.basename(String(filePath || 'custom'))}]`;
    const origRequest = typeof mod.request === 'function' ? mod.request : null;
    const normalizeUrlFromArgs = (args) => {
        const a0 = args[0];
        const a1 = args[1];
        let urlStr = '';
        let opts = null;
        if (typeof a0 === 'string' || a0 instanceof URL) {
            urlStr = String(a0);
            if (a1 && typeof a1 === 'object' && !Array.isArray(a1)) opts = a1;
        } else if (a0 && typeof a0 === 'object' && !Array.isArray(a0)) {
            opts = a0;
        }
        const headers = (opts && opts.headers && typeof opts.headers === 'object') ? opts.headers : {};
        const hostHeader = pickHeaderValue(headers, 'host');
        let hostname = '';
        try {
            if (urlStr) hostname = new URL(urlStr).hostname;
        } catch (_) {
            hostname = '';
        }
        if (!hostname && opts) {
            hostname =
                (typeof opts.hostname === 'string' && opts.hostname) ||
                (typeof opts.host === 'string' && opts.host) ||
                (typeof opts.servername === 'string' && opts.servername) ||
                '';
        }
        const method = String((opts && opts.method) || 'GET').toUpperCase();
        const pathName = (opts && (opts.path || opts.pathname)) ? String(opts.path || opts.pathname) : '';
        const cookie = pickHeaderValue(headers, 'cookie');
        const shouldLog = true;
        const scheme = typeof defaultScheme === 'string' && defaultScheme ? defaultScheme : '';
        const hostForUrl = (hostHeader || hostname || '').trim();
        const fullUrl =
            urlStr ||
            (scheme && hostForUrl && pathName
                ? `${scheme}://${hostForUrl}${pathName.startsWith('/') ? '' : '/'}${pathName}`
                : '');
        return { shouldLog, method, urlStr: fullUrl, hostname, hostHeader, pathName, cookie, headers };
    };
    const wrapFn = (fnName, original) => {
        if (!original) return;
        mod[fnName] = function (...args) {
            const info = normalizeUrlFromArgs(args);
            const req = original.apply(this, args);
            try {
                if (!info.shouldLog) return req;
                if (!req || typeof req !== 'object') return req;
                if (req.__cp_trace_attached) return req;
                req.__cp_trace_attached = true;

                const headerMap = Object.assign({}, info.headers || {});
                try {
                    if (typeof req.getHeader === 'function') {
                        const names = ['host', 'referer', 'origin', 'user-agent', 'cookie', 'content-type'];
                        for (const n of names) {
                            const v = req.getHeader(n);
                            if (v != null && v !== '') headerMap[n] = String(v);
                        }
                    }
                } catch (_) {}

                const logReq = (extra) => {
                    // eslint-disable-next-line no-console
                    console.log(tag, fnName, info.method, info.urlStr || info.pathName || '', {
                        ...pickHeadersForLog(headerMap, info.hostHeader || info.hostname),
                        ...extra,
                    });
                };

                const bodyChunks = [];
                let bodyBytes = 0;
                const BODY_MAX = 2048;
                const captureBody = (chunk, encoding) => {
                    try {
                        if (chunk == null) return;
                        let buf;
                        if (Buffer.isBuffer(chunk)) buf = chunk;
                        else if (typeof chunk === 'string') buf = Buffer.from(chunk, encoding || 'utf8');
                        else return;
                        if (!buf.length) return;
                        const remain = BODY_MAX - bodyBytes;
                        if (remain <= 0) return;
                        const slice = buf.length > remain ? buf.slice(0, remain) : buf;
                        bodyChunks.push(slice);
                        bodyBytes += slice.length;
                    } catch (_) {}
                };
                const originalWrite = typeof req.write === 'function' ? req.write.bind(req) : null;
                const originalEnd = typeof req.end === 'function' ? req.end.bind(req) : null;
                if (originalWrite) {
                    req.write = function (chunk, encoding, cb) {
                        captureBody(chunk, encoding);
                        return originalWrite(chunk, encoding, cb);
                    };
                }
                if (originalEnd) {
                    req.end = function (chunk, encoding, cb) {
                        captureBody(chunk, encoding);
                        try {
                            const bodyPreview = bodyChunks.length ? Buffer.concat(bodyChunks).toString('utf8') : '';
                            logReq({ body: bodyPreview ? bodyPreview.slice(0, 400) : undefined });
                        } catch (_) {
                            logReq({});
                        }
                        return originalEnd(chunk, encoding, cb);
                    };
                } else {
                    logReq({});
                }

                req.on('response', (res) => {
                    try {
                        if (!res) return;
                        const status = typeof res.statusCode === 'number' ? res.statusCode : 0;
                        const respChunks = [];
                        let respBytes = 0;
                        const RESP_MAX = 2048;
                        res.on('data', (d) => {
                            try {
                                if (!d) return;
                                const buf = Buffer.isBuffer(d) ? d : Buffer.from(String(d));
                                const remain = RESP_MAX - respBytes;
                                if (remain <= 0) return;
                                const slice = buf.length > remain ? buf.slice(0, remain) : buf;
                                respChunks.push(slice);
                                respBytes += slice.length;
                            } catch (_) {}
                        });
                        res.on('end', () => {
                            try {
                                const text = respChunks.length ? Buffer.concat(respChunks).toString('utf8') : '';
                                // eslint-disable-next-line no-console
                                console.log(tag, 'res', status, info.urlStr || info.pathName || '', {
                                    ...pickHeadersForLog(headerMap, info.hostHeader || info.hostname),
                                    body: text ? text.slice(0, 400) : undefined,
                                });
                            } catch (_) {}
                        });
                    } catch (_) {}
                });
            } catch (_) {}
            return req;
        };
    };
    wrapFn('request', origRequest);
    try {
        mod.__cp_traced = true;
    } catch (_) {}
    return mod;
}
function detectCustomScriptFormat(filePath) {
    const filename = typeof filePath === 'string' ? filePath : '';
    if (!filename) return 'vm';
    const stripStringsAndComments = (input) => {
        const src = typeof input === 'string' ? input : '';
        let out = '';
        let i = 0;
        let state = 'code'; // code | sq | dq | tpl | line | block
        while (i < src.length) {
            const ch = src[i];
            const next = i + 1 < src.length ? src[i + 1] : '';
            if (state === 'code') {
                if (ch === "'" || ch === '"' || ch === '`') {
                    state = ch === "'" ? 'sq' : ch === '"' ? 'dq' : 'tpl';
                    out += ' ';
                    i += 1;
                    continue;
                }
                if (ch === '/' && next === '/') {
                    state = 'line';
                    out += '  ';
                    i += 2;
                    continue;
                }
                if (ch === '/' && next === '*') {
                    state = 'block';
                    out += '  ';
                    i += 2;
                    continue;
                }
                out += ch;
                i += 1;
                continue;
            }
            if (state === 'line') {
                if (ch === '\n') {
                    state = 'code';
                    out += '\n';
                } else {
                    out += ' ';
                }
                i += 1;
                continue;
            }
            if (state === 'block') {
                if (ch === '*' && next === '/') {
                    state = 'code';
                    out += '  ';
                    i += 2;
                } else {
                    out += ch === '\n' ? '\n' : ' ';
                    i += 1;
                }
                continue;
            }
            // string states
            if (state === 'sq' || state === 'dq') {
                const quote = state === 'sq' ? "'" : '"';
                if (ch === '\\') {
                    out += '  ';
                    i += 2;
                    continue;
                }
                if (ch === quote) {
                    state = 'code';
                }
                out += ch === '\n' ? '\n' : ' ';
                i += 1;
                continue;
            }
            if (state === 'tpl') {
                if (ch === '\\') {
                    out += '  ';
                    i += 2;
                    continue;
                }
                if (ch === '`') {
                    state = 'code';
                    out += ' ';
                    i += 1;
                    continue;
                }
                // We intentionally do not try to parse `${ ... }` expressions here; this is only for a lightweight format hint.
                out += ch === '\n' ? '\n' : ' ';
                i += 1;
                continue;
            }
        }
        return out;
    };
    try {
        const fd = fs.openSync(filename, 'r');
        try {
            const buf = Buffer.alloc(64 * 1024);
            const n = fs.readSync(fd, buf, 0, buf.length, 0);
            const head = buf.slice(0, Math.max(0, n)).toString('utf8');
            const src = head.replace(/^#!.*\n/, '');
            // Many bundles embed `module.exports` text inside template literals (e.g. websiteBundle()).
            // Strip strings/comments first to avoid mis-detecting them as CJS.
            const stripped = stripStringsAndComments(src);
            // ESM detection is cheap and reliable on the raw source.
            if (/(^|\n)\s*export\s+(?:const|let|var|function|class|default)\b/.test(src)) return 'esm';
            if (/(^|\n)\s*import\s+[\s\S]*?\sfrom\s+['"]/.test(src)) return 'esm';
            if (/\bmodule\.exports\b|\bexports\./.test(stripped)) return 'cjs';
            return 'vm';
        } finally {
            fs.closeSync(fd);
        }
    } catch (_) {
        return 'vm';
    }
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
        dirPath: cache.dirPath,
        files: cache.files.slice(),
        count: Array.isArray(cache.spiders) ? cache.spiders.length : 0,
        errors: cache.errors || {},
        byFile: cache.byFile || {},
        webPlugins: Array.isArray(cache.webPlugins) ? cache.webPlugins.length : 0,
        webErrors: cache.webErrors || {},
        webByFile: cache.webByFile || {},
        apiPlugins: Array.isArray(cache.apiPlugins) ? cache.apiPlugins.length : 0,
        apiErrors: cache.apiErrors || {},
        apiByFile: cache.apiByFile || {},
        websiteBundles: Array.isArray(cache.websiteBundles) ? cache.websiteBundles.length : 0,
        websiteErrors: cache.websiteErrors || {},
        websiteByFile: cache.websiteByFile || {},
    };
}
export function getCustomSourceWebPlugins() {
    return Array.isArray(cache.webPlugins) ? cache.webPlugins : [];
}
export function getCustomSourceApiPlugins() {
    return Array.isArray(cache.apiPlugins) ? cache.apiPlugins : [];
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
    const fetch = wrapFetchForTrace(globalThis.fetch || (undici && undici.fetch), filePath);
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
    const scriptFormat = detectCustomScriptFormat(filePath);
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
            const apiPlugins = [];
            let apiError = '';
            try {
                const exportedApiPlugins = (mod && mod.apiPlugins) || (mod && mod.default && mod.default.apiPlugins) || null;
                if (Array.isArray(exportedApiPlugins)) {
                    exportedApiPlugins.forEach((p) => {
                        if (!p || typeof p !== 'object') return;
                        if (typeof p.prefix !== 'string' || !p.prefix) return;
                        if (typeof p.plugin !== 'function') return;
                        apiPlugins.push({
                            prefix: p.prefix,
                            plugin: p.plugin,
                        });
                    });
                }
            } catch (e) {
                apiError = (e && e.message) || String(e);
            }
            let websiteJs = '';
            try {
                const websiteBundle = (mod && mod.websiteBundle) || (mod && mod.default && mod.default.websiteBundle) || null;
                if (typeof websiteBundle === 'string') websiteJs = websiteBundle;
                else if (typeof websiteBundle === 'function') websiteJs = String(websiteBundle() || '');
            } catch (_) {}
            return { spiders, webPlugins, webError, apiPlugins, apiError, websiteJs };
        } catch (err) {
            const msg = (err && err.message) || String(err);
            return { spiders: [], webPlugins: [], webError: `load ${scriptFormat} failed: ${msg}`, apiPlugins: [], apiError: '', websiteJs: '' };
        }
    }
    const code = fs.readFileSync(filePath, 'utf8');
    const baseRequire = createRequire(filePath);
    const requireFunc = (() => {
        const fn = (id) => {
            const mod = baseRequire(id);
            if (id === 'axios') return wrapAxiosForTrace(mod, filePath);
            if (id === 'http' || id === 'node:http') return wrapNodeHttpForTrace(mod, filePath, 'http');
            if (id === 'https' || id === 'node:https') return wrapNodeHttpForTrace(mod, filePath, 'https');
            return mod;
        };
        try {
            fn.resolve = baseRequire.resolve.bind(baseRequire);
            fn.cache = baseRequire.cache;
            fn.extensions = baseRequire.extensions;
            fn.main = baseRequire.main;
        } catch (_) {}
        return fn;
    })();
    if (false) {
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
    }
    const context = buildVmContext(requireFunc, filePath);
    if (false) {
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
    }
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
    // Some bundles keep Baidu account state in `kl.baiduuk` and call `.includes(...)` during play.
    // Ensure it is always an array to avoid crashes like:
    // "TypeError: Cannot read properties of undefined (reading 'includes')".
    try {
        const hasKl = context && Object.prototype.hasOwnProperty.call(context, 'kl') && context.kl && typeof context.kl === 'object';
        if (hasKl && !Array.isArray(context.kl.baiduuk)) {
            context.kl.baiduuk = [];
            if (context.globalThis && context.globalThis.kl === context.kl) {
                context.globalThis.kl.baiduuk = context.kl.baiduuk;
            }
        }
    } catch (_) {}
    if (false) {
        try {
            syncQuarkVarsForCurrentUser();
        } catch (_) {}
        try {
            if (typeof context.WKt === 'function') {
                quarkRuntime.ctx = context;
                quarkRuntime.fromFile = path.basename(filePath);
            }
        } catch (_) {}
    }
    const apiPlugins = [];
    let apiError = '';
    try {
        const apiBundle =
            (context && typeof context.apiBundle === 'function' && context.apiBundle) ||
            (context && context.module && context.module.exports && typeof context.module.exports.apiBundle === 'function'
                ? context.module.exports.apiBundle
                : null) ||
            (context && typeof context.apiPlugins === 'function' ? context.apiPlugins : null) ||
            (context && context.globalThis && typeof context.globalThis.apiBundle === 'function' ? context.globalThis.apiBundle : null);
        if (typeof apiBundle === 'function') {
            const out = apiBundle();
            const list = Array.isArray(out) ? out : out ? [out] : [];
            list.forEach((p) => {
                if (!p || typeof p !== 'object') return;
                if (typeof p.prefix !== 'string' || !p.prefix) return;
                if (typeof p.plugin !== 'function') return;
                apiPlugins.push({
                    prefix: p.prefix,
                    plugin: p.plugin,
                });
            });
        }
    } catch (e) {
        apiError = (e && e.message) || String(e);
    }
    if (false) {
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
    }
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
    if (false) {
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
    }
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
    return { spiders, webPlugins, webError, apiPlugins, apiError, websiteJs };
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
            apiPlugins: [],
            apiErrors: { _dir: 'custom_spider not found' },
            apiByFile: {},
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
                apiPlugins: [],
                apiErrors: { _dir: `custom_spider mkdir failed: ${msg}` },
                apiByFile: {},
                websiteBundles: [],
                websiteErrors: { _dir: `custom_spider mkdir failed: ${msg}` },
                websiteByFile: {},
            };
            console.warn(`[customSpider] mkdir failed: ${dirPath} error=${msg}`);
            return [];
        }
    }
    const scriptPaths = listCustomScriptFiles(dirPath);
    const files = collectFileStats(scriptPaths);
    if (cache.dirPath === dirPath && sameFiles(cache.files, files)) {
        return cache.spiders;
    }
    const errors = {};
    const allSpiders = [];
    const byFile = {};
    const webErrors = {};
    const webByFile = {};
    const allWebPlugins = [];
    const apiErrors = {};
    const apiByFile = {};
    const allApiPlugins = [];
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
            const { spiders, webPlugins, webError, apiPlugins, apiError, websiteJs } = await loadOneFile(filePath);
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
            if (apiError) {
                apiErrors[fileName] = apiError;
            }
            const safeApiPlugins = Array.isArray(apiPlugins) ? apiPlugins : [];
            apiByFile[fileName] = { loaded: safeApiPlugins.length, errors: apiError ? 1 : 0, ms: loadMs };
            safeApiPlugins.forEach((p) => {
                if (!p || typeof p !== 'object') return;
                allApiPlugins.push({
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
            apiErrors[fileName] = msg;
            apiByFile[fileName] = { loaded: 0, errors: 1, ms: 0 };
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
        apiPlugins: allApiPlugins,
        apiErrors,
        apiByFile,
        websiteBundles: allWebsiteBundles,
        websiteErrors,
        websiteByFile,
    };
    return cache.spiders;
}
