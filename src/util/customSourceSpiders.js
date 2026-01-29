import fs from 'fs';
import path from 'path';
import vm from 'vm';
import crypto from 'node:crypto';
import { createRequire } from 'module';
import { fileURLToPath, pathToFileURL } from 'url';
import { getCurrentTvUser, sanitizeTvUsername } from './tvUserContext.js';

const PAN_RUNTIME_SCRIPTS = [
    {
        name: 'baidu.cjs',
        url: 'https://raw.githubusercontent.com/jenfonro/CatPawOpen/refs/heads/main/custom_spider/pan/baidu.cjs',
    },
    {
        name: 'quark.cjs',
        url: 'https://raw.githubusercontent.com/jenfonro/CatPawOpen/refs/heads/main/custom_spider/pan/quark.cjs',
    },
    {
        name: '139.cjs',
        url: 'https://raw.githubusercontent.com/jenfonro/CatPawOpen/refs/heads/main/custom_spider/pan/139.cjs',
    },
];
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
function isSpiderDebugEnabled() {
    return process.env.SPIDER_DEBUG === '1' || process.env.spider_debug === '1';
}
function isPanHostForSites(host) {
    const h = String(host || '').trim().toLowerCase();
    if (!h) return false;
    const hostname = h.split(':')[0];
    return (
        hostname === 'pan.quark.cn' ||
        hostname === 'drive.quark.cn' ||
        hostname.endsWith('.quark.cn') ||
        hostname.endsWith('.baidu.com') ||
        hostname.endsWith('.baidupcs.com') ||
        hostname === 'drive.uc.cn' ||
        hostname === 'open-api-drive.uc.cn' ||
        hostname.endsWith('.uc.cn')
    );
}
function getCustomScriptFileNameForLog(filePath) {
    try {
        const fp = String(filePath || '');
        if (!fp) return '';
        const base = path.basename(fp);
        if (!cache || !cache.dirPath) return base;
        const rel = path.relative(String(cache.dirPath), fp).split(path.sep).join('/');
        return rel && !rel.startsWith('..') ? rel : base;
    } catch (_) {
        return path.basename(String(filePath || 'custom'));
    }
}
function isApiScriptFileForLog(filePath) {
    try {
        const fileName = getCustomScriptFileNameForLog(filePath);
        if (!fileName) return false;
        const stat = cache && cache.apiByFile && cache.apiByFile[fileName] ? cache.apiByFile[fileName] : null;
        return !!(stat && Number(stat.loaded) > 0);
    } catch (_) {
        return false;
    }
}
function isQuarkLikeHost(host) {
    const h = String(host || '').trim().toLowerCase();
    if (!h) return false;
    const hostname = h.split(':')[0];
    return hostname === 'pan.quark.cn' || hostname === 'drive.quark.cn' || hostname.endsWith('.quark.cn');
}
function isUcLikeHost(host) {
    const h = String(host || '').trim().toLowerCase();
    if (!h) return false;
    const hostname = h.split(':')[0];
    return hostname === 'drive.uc.cn' || hostname.endsWith('.uc.cn') || hostname === 'open-api-drive.uc.cn' || hostname.endsWith('.open-api-drive.uc.cn');
}
function getUrlHostForCookieFix(urlStr) {
    const raw = typeof urlStr === 'string' ? urlStr.trim() : '';
    if (!raw) return '';
    try {
        const u = new URL(raw, 'http://0.0.0.0');
        return u.host || u.hostname || '';
    } catch (_) {
        return '';
    }
}
function getCookieHeaderAny(headers) {
    if (!headers) return '';
    try {
        if (typeof headers.get === 'function') return String(headers.get('cookie') || headers.get('Cookie') || '');
    } catch (_) {}
    if (typeof headers !== 'object') return '';
    return pickHeaderValue(headers, 'cookie');
}
function setCookieHeaderAny(headers, cookieValue) {
    if (!headers) return;
    const v = typeof cookieValue === 'string' ? cookieValue.trim() : '';
    if (!v) return;
    try {
        if (typeof headers.set === 'function') {
            headers.set('Cookie', v);
            return;
        }
    } catch (_) {}
    if (typeof headers !== 'object') return;
    for (const k of Object.keys(headers)) {
        if (String(k || '').toLowerCase() === 'cookie') delete headers[k];
    }
    headers.Cookie = v;
}
function maybeFixPanCookieHeader({ host, headers }) {
    const hostname = String(host || '').trim().toLowerCase();
    if (!hostname) return;
    try {
        if (isQuarkLikeHost(hostname)) {
            const cookieFromDb = findPanCookieInDbJson('quark');
            if (!cookieFromDb) return;
            const existingCookie = getCookieHeaderAny(headers);
            if (!String(existingCookie || '').trim()) {
                setCookieHeaderAny(headers, cookieFromDb);
                return;
            }
            const s = String(existingCookie || '');
            const hasVideoAuth = /(?:^|;\s*)video-auth=/i.test(s);
            const hasLoginMarkers = /(?:^|;\s*)(ctoken|__uid|b-user-id|__puus|__pus|tfstk|isg)=/i.test(s);
            if (hasVideoAuth && !hasLoginMarkers) {
                const pairs = s.match(/(?:^|;\s*)video-auth=[^;]*/gi) || [];
                const mergedCookie = [String(cookieFromDb || '').trim()]
                    .concat(pairs.map((p) => String(p || '').trim()).filter(Boolean))
                    .filter(Boolean)
                    .join('; ');
                if (mergedCookie) setCookieHeaderAny(headers, mergedCookie);
            }
            return;
        }
    } catch (_) {}
    try {
        if (isUcLikeHost(hostname)) {
            const existingCookie = getCookieHeaderAny(headers);
            if (String(existingCookie || '').trim()) return;
            const cookieFromDb = findPanCookieInDbJson('uc');
            if (cookieFromDb) setCookieHeaderAny(headers, cookieFromDb);
        }
    } catch (_) {}
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
    const netDebug = process.env.NET_DEBUG === '1';
    const sitesDebug = isSpiderDebugEnabled();
    if (typeof fetchImpl !== 'function') return fetchImpl;
    if (fetchImpl.__cp_traced) return fetchImpl;
    const tag = `[trace:${path.basename(String(filePath || 'custom'))}]`;
    const sitesTag = `[sites:${getCustomScriptFileNameForLog(filePath) || path.basename(String(filePath || 'custom'))}]`;
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
        try {
            const host = getUrlHostForCookieFix(full);
            if (host) maybeFixPanCookieHeader({ host, headers: headersObj });
            if (sitesDebug && !isApiScriptFileForLog(filePath) && !isPanHostForSites(host || '')) {
                try {
                    // eslint-disable-next-line no-console
                    console.log(sitesTag, method, full.length > 500 ? `${full.slice(0, 500)}...(${full.length})` : full);
                } catch (_) {}
            }
        } catch (_) {}
        const hostHeader = pickHeaderValue(headersObj, 'host');
        const shouldLog = netDebug;
        if (netDebug) {
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
            if (netDebug) {
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
            if (netDebug) {
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
    const enabled = process.env.NET_DEBUG === '1';
    const sitesDebug = isSpiderDebugEnabled();
    if (!axios || typeof axios !== 'function') return axios;
    if (axios.__cp_traced) return axios;
    const tag = `[trace:${path.basename(String(filePath || 'custom'))}]`;
    const sitesTag = `[sites:${getCustomScriptFileNameForLog(filePath) || path.basename(String(filePath || 'custom'))}]`;
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
                    try {
                        const headers = (cfg && cfg.headers && typeof cfg.headers === 'object') ? cfg.headers : {};
                        const host = getUrlHostForCookieFix(full);
                        if (host) maybeFixPanCookieHeader({ host, headers });
                        if (sitesDebug && !isApiScriptFileForLog(filePath) && !isPanHostForSites(host || '')) {
                            const method = String((cfg && cfg.method) || 'GET').toUpperCase();
                            // eslint-disable-next-line no-console
                            console.log(sitesTag, method, full.length > 500 ? `${full.slice(0, 500)}...(${full.length})` : full);
                        }
                    } catch (_) {}
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
                    if (enabled) {
                        console.log(tag, 'req', method, full, {
                            ...pickHeadersForLog(headers, hostHeader),
                            data: dataInfo,
                        });
                    }
                } catch (_) {}
                return cfg;
            });
            inst.interceptors.response.use(
                (res) => {
                    try {
                        if (!enabled) return res;
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
                        if (!enabled) return Promise.reject(err);
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
    const netDebug = process.env.NET_DEBUG === '1';
    const sitesDebug = isSpiderDebugEnabled();
    if (!netDebug && !sitesDebug) return mod;
    if (!mod || typeof mod !== 'object') return mod;
    if (mod.__cp_traced) return mod;
    const tag = `[trace:${path.basename(String(filePath || 'custom'))}]`;
    const sitesTag = `[sites:${getCustomScriptFileNameForLog(filePath) || path.basename(String(filePath || 'custom'))}]`;
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
                const host = String(info.hostHeader || info.hostname || '').trim();
                try {
                    maybeFixPanCookieHeader({ host, headers: info.headers || {} });
                } catch (_) {}
                if (sitesDebug && !netDebug && !isApiScriptFileForLog(filePath) && !isPanHostForSites(host)) {
                    try {
                        // eslint-disable-next-line no-console
                        console.log(
                            sitesTag,
                            info.method,
                            (info.urlStr || info.pathName || '').length > 500
                                ? `${String(info.urlStr || info.pathName || '').slice(0, 500)}...`
                                : (info.urlStr || info.pathName || '')
                        );
                    } catch (_) {}
                    return req;
                }
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

function isPkgRuntime() {
    try {
        // eslint-disable-next-line no-undef
        return !!(process && process.pkg);
    } catch (_) {
        return false;
    }
}

function isPanRuntimeScriptDownloadDisabled() {
    const raw = typeof process.env.DISABLE__RUNTIME_DOWNLOAD === 'string' ? process.env.DISABLE__RUNTIME_DOWNLOAD : '';
    const s = String(raw || '').trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'yes' || s === 'on';
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

function writeJsonFileSafe(filePath, obj) {
    try {
        const root = obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
        fs.writeFileSync(filePath, `${JSON.stringify(root, null, 2)}\n`, 'utf8');
        return true;
    } catch (_) {
        return false;
    }
}

function normalizeDownloadProxyPrefix(raw) {
    if (typeof raw !== 'string') return '';
    const trimmed = raw.trim();
    if (!trimmed) return '';
    try {
        const u = new URL(trimmed);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    } catch (_) {
        return '';
    }
    const noTrailing = trimmed.replace(/\/+$/g, '');
    return noTrailing ? `${noTrailing}/` : '';
}

function getDownloadProxyPrefixFromConfig() {
    try {
        const root = readJsonFileSafe(getConfigJsonPath()) || {};
        const raw =
            (typeof root.downloadProxy === 'string' && root.downloadProxy) ||
            (typeof root.download_proxy === 'string' && root.download_proxy) ||
            '';
        return normalizeDownloadProxyPrefix(raw);
    } catch (_) {
        return '';
    }
}

async function fetchCompat(url, init = {}) {
    const fetchImpl = globalThis.fetch;
    if (typeof fetchImpl === 'function') return fetchImpl(url, init);

    const axiosMod = await import('axios');
    const axios = axiosMod && (axiosMod.default || axiosMod);
    const method = (init && init.method) || 'GET';
    const headers = (init && init.headers) || {};
    const resp = await axios.request({
        url,
        method,
        headers,
        responseType: 'text',
        transformResponse: [(v) => v],
        maxRedirects: 0,
        validateStatus: () => true,
    });
    const dataText = typeof resp.data === 'string' ? resp.data : Buffer.isBuffer(resp.data) ? resp.data.toString('utf8') : String(resp.data || '');
    return {
        ok: resp.status >= 200 && resp.status < 300,
        status: resp.status,
        text: async () => dataText,
        headers: {
            get: (key) => {
                if (!key) return null;
                const k = String(key).toLowerCase();
                const v = resp.headers ? resp.headers[k] : undefined;
                return typeof v === 'string' ? v : Array.isArray(v) ? v.join(', ') : v != null ? String(v) : null;
            },
        },
    };
}

function getHeaderLower(resp, key) {
    try {
        if (resp && resp.headers && typeof resp.headers.get === 'function') return resp.headers.get(key) || resp.headers.get(String(key || '').toLowerCase());
    } catch (_) {}
    return null;
}

function commitStagedFilesWithRollback(staged, options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const keepCreatedOnFail = !!opts.keepCreatedOnFail;

    const backups = [];
    const created = [];
    const backupSuffix = `.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`;

    const rollback = () => {
        backups
            .slice()
            .reverse()
            .forEach((b) => {
                try {
                    if (fs.existsSync(b.filePath)) fs.unlinkSync(b.filePath);
                } catch (_) {}
                try {
                    if (fs.existsSync(b.bakPath)) fs.renameSync(b.bakPath, b.filePath);
                } catch (_) {}
            });
        if (!keepCreatedOnFail) {
            created.forEach((p) => {
                try {
                    if (fs.existsSync(p)) fs.unlinkSync(p);
                } catch (_) {}
            });
        }
        staged.forEach((s) => {
            try {
                if (s && s.tmpPath && fs.existsSync(s.tmpPath)) fs.unlinkSync(s.tmpPath);
            } catch (_) {}
        });
    };

    try {
        staged.forEach((s) => {
            const existed = fs.existsSync(s.filePath);
            if (existed) {
                const bakPath = `${s.filePath}.bak${backupSuffix}`;
                fs.renameSync(s.filePath, bakPath);
                backups.push({ filePath: s.filePath, bakPath });
            }
            fs.renameSync(s.tmpPath, s.filePath);
            if (!existed) created.push(s.filePath);
        });
    } catch (e) {
        rollback();
        throw e;
    }

    // Best-effort cleanup backups after success.
    backups.forEach((b) => {
        try {
            if (fs.existsSync(b.bakPath)) fs.unlinkSync(b.bakPath);
        } catch (_) {}
    });
    return true;
}

async function ensurePanRuntimeScripts(customSpiderDir) {
    if (!isPkgRuntime()) return { action: 'none' };
    if (!customSpiderDir) return { action: 'none' };
    if (isPanRuntimeScriptDownloadDisabled()) return { action: 'disabled' };

    const panDir = path.resolve(customSpiderDir, 'pan');
    try {
        if (!fs.existsSync(panDir)) fs.mkdirSync(panDir, { recursive: true });
    } catch (_) {
        return { action: 'none' };
    }

    const downloadProxyPrefix = getDownloadProxyPrefixFromConfig();
    const resolveDownloadUrl = (url) => (downloadProxyPrefix ? `${downloadProxyPrefix}${url}` : url);

    const items = PAN_RUNTIME_SCRIPTS.map((it) => ({
        name: String(it.name || '').trim(),
        url: String(it.url || '').trim(),
        filePath: path.resolve(panDir, String(it.name || '').trim()),
        metaPath: path.resolve(panDir, `.${String(it.name || '').trim()}.remote.json`),
    })).filter((it) => it.name && it.url);

    const anyMissing = items.some((it) => !fs.existsSync(it.filePath));
    if (anyMissing) {
        // eslint-disable-next-line no-console
        console.log('检测到运行环境环境缺失,开始下载....');
        const staged = [];
        try {
            for (const it of items) {
                const res = await fetchCompat(resolveDownloadUrl(it.url), { method: 'GET', headers: {} });
                if (!res || Number(res.status) < 200 || Number(res.status) >= 300) throw new Error(`status=${res ? res.status : 'unknown'}`);
                const text = await res.text();
                if (!text) throw new Error('empty body');
                // eslint-disable-next-line no-undef
                const tmpPath = path.resolve(panDir, `.${it.name}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
                fs.writeFileSync(tmpPath, text, 'utf8');
                staged.push({ ...it, tmpPath, res });
            }
        } catch (_) {
            staged.forEach((s) => {
                try {
                    fs.unlinkSync(s.tmpPath);
                } catch (_e) {}
            });
            // eslint-disable-next-line no-console
            console.log('下载失败,请检查网络');
            return { action: 'missing_failed' };
        }
        try {
            commitStagedFilesWithRollback(staged);
            staged.forEach((s) => {
                const etag = getHeaderLower(s.res, 'etag');
                const lastModified = getHeaderLower(s.res, 'last-modified');
                writeJsonFileSafe(s.metaPath, {
                    url: s.url,
                    etag: typeof etag === 'string' ? etag : '',
                    lastModified: typeof lastModified === 'string' ? lastModified : '',
                    savedAt: Date.now(),
                });
            });
        } catch (_) {
            // eslint-disable-next-line no-console
            console.log('下载失败,请检查网络');
            return { action: 'missing_failed' };
        }

        // eslint-disable-next-line no-console
        console.log('下载完成,请重启程序,');
        // eslint-disable-next-line no-undef
        process.exit(1);
    }

        // Exists: ensure we have meta headers without being noisy.
    for (const it of items) {
        const meta = readJsonFileSafe(it.metaPath);
        const hasMeta =
            meta &&
            typeof meta === 'object' &&
            ((typeof meta.etag === 'string' && meta.etag.trim()) || (typeof meta.lastModified === 'string' && meta.lastModified.trim()));
        if (hasMeta) continue;
        try {
            const res = await fetchCompat(resolveDownloadUrl(it.url), { method: 'HEAD', headers: {} });
            if (!res || Number(res.status) < 200 || Number(res.status) >= 300) continue;
            const etag = getHeaderLower(res, 'etag');
            const lastModified = getHeaderLower(res, 'last-modified');
            writeJsonFileSafe(it.metaPath, {
                url: it.url,
                etag: typeof etag === 'string' ? etag : '',
                lastModified: typeof lastModified === 'string' ? lastModified : '',
                savedAt: Date.now(),
            });
        } catch (_) {}
    }

    // Check updates using conditional GET; only print if an update is actually needed.
    const updates = [];
    let updateMode = false;
    try {
        for (const it of items) {
            const meta = readJsonFileSafe(it.metaPath) || {};
            const headers = {};
            if (typeof meta.etag === 'string' && meta.etag.trim()) headers['if-none-match'] = meta.etag.trim();
            if (typeof meta.lastModified === 'string' && meta.lastModified.trim()) headers['if-modified-since'] = meta.lastModified.trim();

            const res = await fetchCompat(resolveDownloadUrl(it.url), { method: 'GET', headers });
            if (!res) continue;
            const code = Number(res.status);
            if (code === 304) continue;
            if (code < 200 || code >= 300) continue;

            if (!updateMode) {
                updateMode = true;
                // eslint-disable-next-line no-console
                console.log('检测到新的运行环境,开始下载...');
            }

            const text = await res.text();
            if (!text) throw new Error('empty body');
            // eslint-disable-next-line no-undef
            const tmpPath = path.resolve(panDir, `.${it.name}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
            fs.writeFileSync(tmpPath, text, 'utf8');
            updates.push({ ...it, tmpPath, res });
        }
    } catch (_) {
        updates.forEach((u) => {
            try {
                fs.unlinkSync(u.tmpPath);
            } catch (_e) {}
        });
        if (updateMode) {
            // eslint-disable-next-line no-console
            console.log('更新失败,请检查网络,将使用旧运行环境,');
        }
        return { action: updateMode ? 'update_failed' : 'none' };
    }

    if (!updates.length) return { action: 'none' };

    try {
        commitStagedFilesWithRollback(updates, { keepCreatedOnFail: true });
        updates.forEach((u) => {
            const etag = getHeaderLower(u.res, 'etag');
            const lastModified = getHeaderLower(u.res, 'last-modified');
            writeJsonFileSafe(u.metaPath, {
                url: u.url,
                etag: typeof etag === 'string' ? etag : '',
                lastModified: typeof lastModified === 'string' ? lastModified : '',
                savedAt: Date.now(),
            });
        });
    } catch (_) {
        // eslint-disable-next-line no-console
        console.log('更新失败,请检查网络,将使用旧运行环境,');
        return { action: 'update_failed' };
    }

    // eslint-disable-next-line no-console
    console.log('更新完成,请重启程序');
    // eslint-disable-next-line no-undef
    process.exit(1);
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
                // In dev, bypass ESM import cache when the file changes.
                // In pkg executables, avoid `?mtime=` because some runtimes don't support external ESM URL queries.
                const isPkg = (() => {
                    try {
                        return !!(process && process.pkg);
                    } catch (_) {
                        return false;
                    }
                })();
                if (isPkg) {
                    mod = await import(href);
                } else {
                    const st = fs.statSync(filePath);
                    mod = await import(`${href}?mtime=${encodeURIComponent(String(st.mtimeMs))}`);
                }
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
    const context = buildVmContext(requireFunc, filePath);
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

    // pkg runtime bootstrap for pan scripts: ensure `custom_spider/pan/{baidu,quark}.cjs` exists and is up-to-date.
    // - Missing: download, ask to restart, and exit(1)
    // - Update: download, ask to restart, and exit(1)
    // - Update failed: keep old scripts and continue
    try {
        await ensurePanRuntimeScripts(dirPath);
    } catch (_) {}

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
