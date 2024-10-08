import fastify from 'fastify';
import router from './router.js';
import { JsonDB, Config } from 'node-json-db';
import axios from 'axios';

let server = null;

function ensureConfigDefaults(config) {
    if (!config || typeof config !== 'object') return {};

    const ensureObj = (key) => {
        const cur = config[key];
        if (!cur || typeof cur !== 'object') config[key] = {};
        return config[key];
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
    // 推荐使用NODE_PATH做db存储的更目录，这个目录在应用中清除缓存时会被清空
    server.db = new JsonDB(new Config((process.env['NODE_PATH'] || '.') + '/db.json', true, true, '/', true));
    server.register(router);
    // 注意 一定要监听ipv4地址 build后 app中使用时 端口使用0让系统自动分配可用端口
    const envPortRaw = process.env['DEV_HTTP_PORT'] || process.env['PORT'] || '';
    const parsedPort = envPortRaw === '' ? 0 : Number(envPortRaw);
    const port = Number.isFinite(parsedPort) ? parsedPort : 0;

    const hostRaw = typeof process.env['HOST'] === 'string' ? process.env['HOST'].trim() : '';
    const host = hostRaw || '127.0.0.1';

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
