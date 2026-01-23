import fastify from 'fastify';
import router from './router.js';
import { JsonDB, Config } from 'node-json-db';
import axios from 'axios';
import path from 'node:path';

let server = null;

function ensureFetchPolyfill() {
    if (typeof globalThis.fetch === 'function') return;
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
            responseType: 'text',
            transformResponse: [(v) => v],
            maxRedirects: redirect === 'manual' ? 0 : 5,
            validateStatus: () => true,
        });

        const dataText =
            typeof resp.data === 'string' ? resp.data : Buffer.isBuffer(resp.data) ? resp.data.toString('utf8') : JSON.stringify(resp.data);
        return {
            ok: resp.status >= 200 && resp.status < 300,
            status: resp.status,
            url: url,
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
    ensureFetchPolyfill();
    /**
     * @type {import('fastify').FastifyInstance}
     */
    server = fastify({
        serverFactory: catServerFactory,
        forceCloseConnections: true,
        logger: !!(process.env.NODE_ENV !== 'development'),
        maxParamLength: 10240,
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
        console.error(error);
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

    const envPortRaw = process.env['DEV_HTTP_PORT'] || process.env['PORT'] || '';
    const defaultPort = isStandalone ? 3006 : 0;
    const parsedPort = envPortRaw === '' ? defaultPort : Number(envPortRaw);
    const port = Number.isFinite(parsedPort) ? parsedPort : defaultPort;

    const hostRaw = typeof process.env['HOST'] === 'string' ? process.env['HOST'].trim() : '';
    const host = hostRaw || (isStandalone ? '0.0.0.0' : '127.0.0.1');

    server.listen({ port, host });
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
