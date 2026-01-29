import fastify from 'fastify';
import router from './router.js';
import { JsonDB, Config } from 'node-json-db';
import axios from 'axios';
import fs from 'node:fs';
import path from 'node:path';
import { getCatPawOpenVersion } from './util/version.js';

let server = null;

function getEmbeddedRootDir() {
    try {
        // eslint-disable-next-line no-undef
        if (typeof __dirname !== 'undefined') return path.resolve(__dirname, '..');
    } catch (_) {}
    return process.cwd();
}

function getExternalRootDir() {
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

function normalizeListenPort(value) {
    const n =
        typeof value === 'number'
            ? value
            : typeof value === 'string' && value.trim()
              ? Number(value.trim())
              : Number.NaN;
    if (!Number.isFinite(n)) return null;
    const port = Math.trunc(n);
    if (port < 0 || port > 65535) return null;
    return port;
}

function parseAddrOverrideFromArgv(argv) {
    const args = Array.isArray(argv) ? argv : [];
    let raw = '';
    for (let i = 0; i < args.length; i += 1) {
        const a = String(args[i] || '');
        if (a === '-addr' || a === '--addr') {
            raw = String(args[i + 1] || '');
            break;
        }
        if (a.startsWith('-addr=')) {
            raw = a.slice('-addr='.length);
            break;
        }
        if (a.startsWith('--addr=')) {
            raw = a.slice('--addr='.length);
            break;
        }
    }
    raw = String(raw || '').trim();
    if (!raw) return null;

    // Support: "3006", ":3006", "0.0.0.0:3006", "[::]:3006", "http://0.0.0.0:3006"
    if (raw.startsWith('http://') || raw.startsWith('https://')) {
        try {
            const u = new URL(raw);
            const port = normalizeListenPort(u.port);
            if (port == null) return null;
            return { host: u.hostname || '', port };
        } catch (_) {
            return null;
        }
    }

    let host = '';
    let portPart = raw;
    if (raw.startsWith('[')) {
        const idx = raw.indexOf(']');
        if (idx > 0 && raw[idx + 1] === ':') {
            host = raw.slice(1, idx);
            portPart = raw.slice(idx + 2);
        }
    } else if (raw.includes(':')) {
        const lastColon = raw.lastIndexOf(':');
        host = raw.slice(0, lastColon);
        portPart = raw.slice(lastColon + 1);
    }
    if (host === ':') host = '';
    if (host === '') {
        // allow ":3006"
        if (raw.startsWith(':')) portPart = raw.slice(1);
    }
    const port = normalizeListenPort(portPart);
    if (port == null) return null;
    return { host: String(host || '').trim(), port };
}

async function ensureFetchPolyfill() {
    const isPkg = (() => {
        try {
            return !!(process && process.pkg);
        } catch (_) {
            return false;
        }
    })();

    // In some pkg-bundled Node runtimes, global fetch may emit ExperimentalWarning.
    // Prefer undici.fetch in pkg to avoid the warning.
    if (isPkg) {
        try {
            const undici = await import('undici');
            if (undici && typeof undici.fetch === 'function') {
                globalThis.fetch = undici.fetch;
                if (undici.Headers && !globalThis.Headers) globalThis.Headers = undici.Headers;
                if (undici.Request && !globalThis.Request) globalThis.Request = undici.Request;
                if (undici.Response && !globalThis.Response) globalThis.Response = undici.Response;
                if (undici.FormData && !globalThis.FormData) globalThis.FormData = undici.FormData;
                if (undici.Blob && !globalThis.Blob) globalThis.Blob = undici.Blob;
                if (undici.AbortController && !globalThis.AbortController) globalThis.AbortController = undici.AbortController;
                if (undici.AbortSignal && !globalThis.AbortSignal) globalThis.AbortSignal = undici.AbortSignal;
                if (undici.DOMException && !globalThis.DOMException) globalThis.DOMException = undici.DOMException;
                return;
            }
        } catch (_) {
            // fall back to axios polyfill below
        }
    }

    if (!isPkg && typeof globalThis.fetch === 'function') return;

    globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === 'string' ? input : input && typeof input.url === 'string' ? input.url : String(input);
        const method = init && init.method ? String(init.method).toUpperCase() : 'GET';
        const headers = (init && init.headers) || {};
        const body = init && Object.prototype.hasOwnProperty.call(init, 'body') ? init.body : undefined;
        const redirect = init && init.redirect ? String(init.redirect) : 'follow';

        const resp = await axios.request({
            url,
            method,
            headers,
            data: body,
            responseType: 'arraybuffer',
            transformResponse: [(v) => v],
            maxRedirects: redirect === 'manual' ? 0 : 5,
            validateStatus: () => true,
        });

        const buf = Buffer.isBuffer(resp.data) ? resp.data : Buffer.from(resp.data || []);
        const dataText = buf.toString('utf8');
        return {
            ok: resp.status >= 200 && resp.status < 300,
            status: resp.status,
            url: url,
            text: async () => dataText,
            json: async () => {
                const t = dataText;
                return t ? JSON.parse(t) : null;
            },
            arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
            headers: {
                get: (key) => {
                    if (!key) return null;
                    const k = String(key).toLowerCase();
                    const v = resp.headers ? resp.headers[k] : undefined;
                    return typeof v === 'string' ? v : Array.isArray(v) ? v.join(', ') : v != null ? String(v) : null;
                },
            },
        };
    };
}

function ensureConfigDefaults(config) {
    if (!config || typeof config !== 'object') return {};

    const ensureObj = (key) => {
        const cur = config[key];
        if (!cur || typeof cur !== 'object') config[key] = {};
        return config[key];
    };
    const ensureNonEmptyString = (obj, field, fallback) => {
        if (!obj || typeof obj !== 'object') return;
        const cur = obj[field];
        if (typeof cur !== 'string' || !cur.trim()) obj[field] = fallback;
    };
    const ensureCookie = (key) => {
        const obj = ensureObj(key);
        if (typeof obj.cookie !== 'string') obj.cookie = '';
    };
    const ensureAccount = (key) => {
        const obj = ensureObj(key);
        if (typeof obj.username !== 'string') obj.username = '';
        if (typeof obj.password !== 'string') obj.password = '';
    };

    // Provide safe defaults for common keys expected by custom bundles (e.g. two.js),
    // so missing settings don't crash route handlers.
    ensureCookie('baidu');
    ensureCookie('quark');
    ensureCookie('uc');
    ensureCookie('bili');
    ensureCookie('wuming');
    ensureCookie('pan123ziyuan');
    ensureAccount('tianyi');
    ensureAccount('pan123');
    ensureAccount('yunchao');

    // UC custom bundles persist multiple values under `/uc/<md5(config.uc.*)>`.
    // If these identifiers are empty, different values collide at MD5('') and overwrite each other.
    try {
        const uc = ensureObj('uc');
        // Keep `uc.cookie` default as empty for backwards-compat (existing db.json may use MD5('') for UC cookie).
        ensureNonEmptyString(uc, 'token', '__uc_token_id__');
        ensureNonEmptyString(uc, 'refreshtoken', '__uc_refreshtoken_id__');
        ensureNonEmptyString(uc, 'ut', '__uc_ut_id__');
    } catch (_) {}

    return config;
}

/**
 * Start the server with the given configuration.
 *
 * Be careful that start will be called multiple times when
 * work with catvodapp. If the server is already running,
 * the stop will be called by engine before start, make sure
 * to return new server every time.
 *
 * @param {Map} config - the config of the server
 * @return {void}
 */
export async function start(config) {
    console.log(`catpawopen version : ${getCatPawOpenVersion()}`);
    await ensureFetchPolyfill();
    const enableLogger = process.env.NODE_ENV !== 'development';
    const timeoutRaw =
        (typeof process.env.CATPAW_PLUGIN_TIMEOUT_MS === 'string' && process.env.CATPAW_PLUGIN_TIMEOUT_MS) ||
        (typeof process.env.CATPAWOPEN_PLUGIN_TIMEOUT_MS === 'string' && process.env.CATPAWOPEN_PLUGIN_TIMEOUT_MS) ||
        '';
    const parsedTimeout = timeoutRaw && timeoutRaw.trim() ? Number.parseInt(timeoutRaw.trim(), 10) : Number.NaN;
    const envPluginTimeoutMs = Number.isFinite(parsedTimeout) ? Math.max(0, parsedTimeout) : 0;
    const defaultPluginTimeoutMs = (() => {
        try {
            return process && process.pkg ? 60 * 1000 : 0;
        } catch (_) {
            return 0;
        }
    })();
    const pluginTimeoutMs = envPluginTimeoutMs > 0 ? envPluginTimeoutMs : defaultPluginTimeoutMs;
    /**
     * @type {import('fastify').FastifyInstance}
     */
    server = fastify({
        serverFactory: catServerFactory,
        forceCloseConnections: true,
        logger: enableLogger
            ? {
                  level: 'info',
                  redact: {
                      // Avoid huge logs (e.g. axios error objects embed agents/sockets/certs).
                      paths: [
                          'req.headers.authorization',
                          'req.headers.cookie',
                          'err.config',
                          'err.request',
                          'err.response',
                      ],
                      remove: true,
                  },
              }
            : false,
        maxParamLength: 10240,
        ...(pluginTimeoutMs > 0 ? { pluginTimeout: pluginTimeoutMs } : {}),
    });
    server.messageToDart = async (data, inReq) => {
        try {
            if (!data.prefix) {
                data.prefix = inReq ? inReq.server.prefix : '';
            }
            console.log(data);
            const port = catDartServerPort();
            if (port == 0) {
                return null;
            }
            const resp = await axios.post(`http://127.0.0.1:${port}/msg`, data);
            return resp.data;
        } catch (error) {
            return null;
        }
    };
    server.address = function () {
        const result = this.server.address();
        result.url = `http://${result.address}:${result.port}`;
        result.dynamic = 'js2p://_WEB_';
        return result;
    };
    server.addHook('onError', async (_request, _reply, error) => {
        try {
            // Keep logs small: some thrown objects (e.g. axios errors) contain huge nested config/agent state.
            // eslint-disable-next-line no-console
            console.error(error && error.stack ? error.stack : error);
        } catch (_) {}
        if (!error.statusCode) error.statusCode = 500;
        return error;
    });
    server.stop = false;
    server.config = ensureConfigDefaults(config);
    // Persist db.json in current working directory.
    server.db = new JsonDB(new Config(path.resolve(process.cwd(), 'db.json'), true, true, '/', true));
    server.register(router);
    // 注意 一定要监听ipv4地址 build后 app中使用时 端口使用0让系统自动分配可用端口
    const isStandalone = !!(process && process.pkg);

    const addrOverride = isStandalone ? parseAddrOverrideFromArgv(process.argv) : null;

    const cfgPath = getConfigJsonPath();
    const persisted = isStandalone ? readConfigJsonSafe(cfgPath) : {};
    const persistedListen = normalizeListenPort(
        persisted && Object.prototype.hasOwnProperty.call(persisted, 'listen') ? persisted.listen : persisted.linsten
    );
    const configListen = persistedListen == null ? 3006 : persistedListen;

    if (isStandalone && !addrOverride) {
        const next = { ...(persisted && typeof persisted === 'object' ? persisted : {}) };
        let changed = false;
        const nextListen = normalizeListenPort(next.listen);
        const legacyListen = normalizeListenPort(next.linsten);
        if (nextListen == null) {
            next.listen = legacyListen == null ? 3006 : legacyListen;
            changed = true;
        }
        if (typeof next.downloadProxy !== 'string') {
            next.downloadProxy = '';
            changed = true;
        }
        try {
            if (changed || !fs.existsSync(cfgPath)) writeConfigJsonSafe(cfgPath, next);
        } catch (_) {}
    }

    const envPortRaw = process.env['DEV_HTTP_PORT'] || process.env['PORT'] || '';
    const defaultPort = isStandalone ? configListen : 0;
    const parsedPort = envPortRaw === '' ? defaultPort : Number(envPortRaw);
    const port = Number.isFinite(parsedPort) ? parsedPort : defaultPort;

    const hostRaw = typeof process.env['HOST'] === 'string' ? process.env['HOST'].trim() : '';
    const hostDefault = hostRaw || (isStandalone ? '0.0.0.0' : '127.0.0.1');

    const finalPort = addrOverride ? addrOverride.port : port;
    const finalHost = addrOverride && addrOverride.host ? addrOverride.host : hostDefault;

    server.listen({ port: finalPort, host: finalHost });
}

/**
 * Stop the server if it exists.
 *
 */
export async function stop() {
    if (server) {
        server.close();
        server.stop = true;
    }
    server = null;
}
