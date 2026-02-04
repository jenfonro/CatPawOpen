import * as cfg from './index.config.js';
import {md5} from "./util/crypto-util.js";
import chunkStream from "./util/chunk.js";
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import apiPlugins from './plugins/api/index.js';

const spiderPrefix = '/spider';

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

function rewriteLocalUrlToExternal(url, externalOrigin, idPrefix, allowedPorts) {
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
    const port = Number(parsed.port || 0);
    if (Array.isArray(allowedPorts) && allowedPorts.length && port) {
        if (!allowedPorts.some((p) => Number(p) === port)) return url;
    }
    const pathName = String(parsed.pathname || '');
    if (!pathName.startsWith('/')) return url;
    const prefix = idPrefix ? `/${String(idPrefix).trim()}` : '';
    const withId = prefix && !pathName.startsWith(`${prefix}/`) && pathName !== prefix ? `${prefix}${pathName}` : pathName;
    return `${externalOrigin}${withId}${parsed.search || ''}${parsed.hash || ''}`;
}

function rewriteLocalUrlsDeep(value, externalOrigin, idPrefix, allowedPorts) {
    const seen = new WeakSet();
    const walk = (node) => {
        if (typeof node === 'string') return rewriteLocalUrlToExternal(node, externalOrigin, idPrefix, allowedPorts);
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

function resolveRuntimeRootDir() {
    try {
        if (process && process.pkg && typeof process.execPath === 'string' && process.execPath) {
            return path.dirname(process.execPath);
        }
    } catch (_) {}
    try {
        const envRoot = typeof process.env.NODE_PATH === 'string' ? process.env.NODE_PATH.trim() : '';
        if (envRoot) return path.resolve(envRoot);
    } catch (_) {}
    return process.cwd();
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

function readPanBuiltinResolverEnabledFromConfigRoot(root) {
    const cfgRoot = root && typeof root === 'object' && !Array.isArray(root) ? root : {};
    if (Object.prototype.hasOwnProperty.call(cfgRoot, 'panResolver') && typeof cfgRoot.panResolver === 'boolean') return cfgRoot.panResolver;
    if (Object.prototype.hasOwnProperty.call(cfgRoot, 'panBuiltinResolverEnabled')) return !!cfgRoot.panBuiltinResolverEnabled;
    return false;
}

function pickFirstHeaderValue(value) {
    if (typeof value !== 'string') return '';
    const first = value.split(',')[0];
    return String(first || '').trim();
}

function getTvUserFromRequest(request) {
    const headers = (request && request.headers) || {};
    const v = headers['x-tv-user'] || headers['X-TV-User'] || '';
    return pickFirstHeaderValue(String(v || '').trim());
}

function parseJsonSafe(text) {
    try {
        const t = typeof text === 'string' ? text : '';
        return t && t.trim() ? JSON.parse(t) : {};
    } catch (_) {
        return null;
    }
}

function isBaiduFlag(flag) {
    const s = String(flag || '');
    return s.includes('百度') || s.toLowerCase().includes('baidu');
}

function isQuarkFlag(flag) {
    const s = String(flag || '');
    return s.includes('夸克') || s.includes('夸父') || s.toLowerCase().includes('quark');
}

function looksLikeHexId32(value) {
    return /^[a-f0-9]{32}$/i.test(String(value || '').trim());
}

function is139Flag(flag) {
    const s = String(flag || '');
    return s.includes('逸动') || s.includes('139') || s.includes('和彩云') || s.includes('移动');
}

/**
 * A function to initialize the router.
 *
 * @param {Object} fastify - The Fastify instance
 * @return {Promise<void>} - A Promise that resolves when the router is initialized
 */
export default async function router(fastify) {
    // 0) register builtin api plugins (packaged with this build)
    for (const p of (apiPlugins || [])) {
        fastify.register(p.plugin, {prefix: p.prefix});
        console.log(`Register api plugin: ${p.prefix} (from ${p.fileName || 'builtin'})`);
    }

    // Unified play entrypoint:
    // - if builtin pan resolver enabled: dispatch to /api/{baidu,quark,139}/play based on flag
    // - otherwise (or no match): forward to the target runtime play via siteApi + siteId
    fastify.post('/play', async function (request, reply) {
        const body = request && request.body && typeof request.body === 'object' ? request.body : {};
        const flag = typeof body.flag === 'string' ? body.flag : '';
        const playId = typeof body.id === 'string' ? body.id : '';
        if (!flag || !playId) return reply.code(400).send({ ok: false, message: 'missing flag/id' });

        const externalOrigin = getExternalOriginFromRequest(request);

        const runtimeRoot = resolveRuntimeRootDir();
        const cfgPath = path.resolve(runtimeRoot, 'config.json');
        const cfgRoot = readConfigJsonSafe(cfgPath);
        const panEnabled = readPanBuiltinResolverEnabledFromConfigRoot(cfgRoot);

        const rawUrl = request && request.raw && typeof request.raw.url === 'string' ? request.raw.url : '';
        const queryStr = rawUrl.includes('?') ? rawUrl.slice(rawUrl.indexOf('?')) : '';
        const tvUser = getTvUserFromRequest(request);
        const baseHeaders = { 'content-type': 'application/json' };

        // 1) builtin pan resolver path
        if (panEnabled) {
            let route = isBaiduFlag(flag) ? '/api/baidu/play' : isQuarkFlag(flag) ? '/api/quark/play' : is139Flag(flag) ? '/api/139/play' : '';
            // If the id is already a Quark file id (32-hex), skip save/transfer and request a direct url.
            if (route === '/api/quark/play' && looksLikeHexId32(playId)) {
                route = '/api/quark/download';
            }
            if (route) {
                const nextBody = { ...body };
                // Do not leak site routing fields into pan plugins.
                delete nextBody.siteApi;
                delete nextBody.spiderApi;
                delete nextBody.api;
                delete nextBody.siteId;
                delete nextBody.onlineId;
                delete nextBody.runtimeId;
                // Ensure Baidu has a destination folder (plugin requires destPath/destName).
                if (route === '/api/baidu/play') {
                    if (!nextBody.destPath && !nextBody.destName) nextBody.destName = 'MeowFilm';
                }
                if (route === '/api/quark/download') {
                    // Normalize to the download API input shape.
                    nextBody.fid = playId;
                    delete nextBody.id;
                }
                const injected = await fastify.inject({
                    method: 'POST',
                    url: `${route}${queryStr}`,
                    headers: { ...baseHeaders, ...(tvUser ? { 'x-tv-user': tvUser } : {}) },
                    payload: nextBody,
                });
                const parsed = parseJsonSafe(injected.payload);
                if (externalOrigin && parsed && typeof parsed === 'object') {
                    try {
                        rewriteLocalUrlsDeep(parsed, externalOrigin, '', []);
                    } catch (_) {}
                }
                return reply.code(injected.statusCode || 200).send(parsed != null ? parsed : injected.payload);
            }
        }

        // 2) fallback: forward to the site runtime play
        const siteApi =
            (typeof body.siteApi === 'string' && body.siteApi.trim()) ||
            (typeof body.spiderApi === 'string' && body.spiderApi.trim()) ||
            (typeof body.api === 'string' && body.api.trim()) ||
            '';
        const siteIdRaw =
            (typeof body.siteId === 'string' && body.siteId.trim()) ||
            (typeof body.onlineId === 'string' && body.onlineId.trim()) ||
            (typeof body.runtimeId === 'string' && body.runtimeId.trim()) ||
            '';

        if (!siteApi) return reply.code(400).send({ ok: false, message: 'missing siteApi' });

        const apiTrimmed = String(siteApi || '').trim();
        const apiHasIdPrefix = /^\/[a-f0-9]{10}\/spider\//.test(apiTrimmed);
        const idFromApi = apiHasIdPrefix ? apiTrimmed.slice(1, 11) : '';
        let siteId = siteIdRaw || idFromApi;

        if (!apiHasIdPrefix && !siteId) {
            const keys =
                fastify && fastify.onlineRuntimePorts && typeof fastify.onlineRuntimePorts.keys === 'function'
                    ? Array.from(fastify.onlineRuntimePorts.keys())
                    : [];
            if (keys.length === 1) siteId = String(keys[0] || '').trim();
        }
        if (!apiHasIdPrefix && !siteId) return reply.code(400).send({ ok: false, message: 'missing siteId' });

        const forwardBase = apiHasIdPrefix ? apiTrimmed : `/${siteId}${apiTrimmed.startsWith('/') ? '' : '/'}${apiTrimmed}`;
        const forwardUrl = `${forwardBase.replace(/\/+$/g, '')}/play${queryStr}`;
        const forwardBody = { ...body };
        delete forwardBody.siteApi;
        delete forwardBody.spiderApi;
        delete forwardBody.api;
        delete forwardBody.siteId;
        delete forwardBody.onlineId;
        delete forwardBody.runtimeId;

        const injected = await fastify.inject({
            method: 'POST',
            url: forwardUrl,
            headers: baseHeaders,
            payload: forwardBody,
        });
        const parsed = parseJsonSafe(injected.payload);
        if (externalOrigin && parsed && typeof parsed === 'object') {
            try {
                const port = fastify && fastify.onlineRuntimePorts && typeof fastify.onlineRuntimePorts.get === 'function' ? fastify.onlineRuntimePorts.get(siteId) : null;
                const p = Number.isFinite(Number(port)) ? Math.max(1, Math.trunc(Number(port))) : 0;
                rewriteLocalUrlsDeep(parsed, externalOrigin, siteId, p ? [p] : []);
            } catch (_) {}
        }
        return reply.code(injected.statusCode || 200).send(parsed != null ? parsed : injected.payload);
    });

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
                    reply.send({run: !fastify.stop});
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
                    reply.send(config);
                }
            );

            fastify.all('/proxy', async (request, reply) => {
                try {
                    const {thread, chunkSize, url, header} = request.query;

                    if (!url) {
                        reply.code(400).send({error: 'url is required'});
                        return;
                    }

                    // 解码 URL 和 Header
                    // const decodedUrl = decodeURIComponent(url);
                    const decodedUrl = url;
                    // const decodedHeader = header ? JSON.parse(decodeURIComponent(header)) : {};
                    const decodedHeader = header ? JSON.parse(header) : {};

                    // 获取当前请求头
                    const currentHeaders = request.headers;

                    // 解析目标 URL
                    const targetUrl = new URL(decodedUrl);

                    // 更新特殊头部
                    const proxyHeaders = {
                        ...currentHeaders,
                        ...decodedHeader,
                        host: targetUrl.host, // 确保 Host 对应目标网站
                        origin: `${targetUrl.protocol}//${targetUrl.host}`, // Origin
                        referer: targetUrl.href, // Referer
                    };

                    // 删除本地无关头部
                    delete proxyHeaders['content-length']; // 避免因修改内容导致不匹配
                    delete proxyHeaders['transfer-encoding'];

                    // 添加缺省值或更新
                    proxyHeaders['user-agent'] =
                        proxyHeaders['user-agent'] ||
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36';
                    proxyHeaders['accept'] = proxyHeaders['accept'] || '*/*';
                    proxyHeaders['accept-language'] = proxyHeaders['accept-language'] || 'en-US,en;q=0.9';
                    proxyHeaders['accept-encoding'] = proxyHeaders['accept-encoding'] || 'gzip, deflate, br';


                    // delete proxyHeaders['host'];
                    // delete proxyHeaders['origin'];
                    // delete proxyHeaders['referer'];
                    // delete proxyHeaders['cookie'];
                    // delete proxyHeaders['accept'];

                    delete proxyHeaders['sec-fetch-site'];
                    delete proxyHeaders['sec-fetch-mode'];
                    delete proxyHeaders['sec-fetch-dest'];
                    delete proxyHeaders['sec-ch-ua'];
                    delete proxyHeaders['sec-ch-ua-mobile'];
                    delete proxyHeaders['sec-ch-ua-platform'];
                    // delete proxyHeaders['connection'];
                    // delete proxyHeaders['user-agent'];
                    delete proxyHeaders['range']; // 必须删除，后面chunkStream会从request取出来的
                    // console.log(`proxyHeaders:`, proxyHeaders);

                    // 处理选项
                    const option = {
                        chunkSize: chunkSize ? 1024 * parseInt(chunkSize, 10) : 1024 * 256,
                        poolSize: thread ? parseInt(thread, 10) : 6,
                        timeout: 1000 * 10, // 默认 10 秒超时
                    };

                    // console.log(`option:`, option);
                    // 计算 urlKey (MD5)
                    const urlKey = md5(decodedUrl);

                    // 调用 chunkStream
                    return await chunkStream(request, reply, decodedUrl, urlKey, proxyHeaders, option);
                } catch (err) {
                    reply.code(500).send({error: err.message});
                }
            });
        }
    );

    // If a route is not handled by CatPawOpen, proxy it to the online runtime (default: 9988).
    // This allows downloaded scripts in `custom_spider/` to expose their own routes while still being accessed from this port.
    const proxyToPort = async function (request, reply, targetPort, urlPath) {
        const pathToUse = typeof urlPath === 'string' && urlPath ? urlPath : '/';

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

        const headers = {};
        const inHeaders = (request && request.headers) || {};
        Object.keys(inHeaders).forEach((k) => {
            const key = String(k || '').toLowerCase();
            if (!key || hopByHop.has(key)) return;
            headers[key] = inHeaders[k];
        });
        headers.host = `127.0.0.1:${targetPort}`;
        // Fastify may have already consumed the incoming stream to populate `request.body`.
        // Never forward a stale Content-Length (will hang the upstream waiting for bytes).
        delete headers['content-length'];
        delete headers['transfer-encoding'];

        reply.hijack();
        return await new Promise((resolve) => {
            const proxyReq = http.request(
                {
                    hostname: '127.0.0.1',
                    port: targetPort,
                    method: String(request.method || 'GET').toUpperCase(),
                    path: pathToUse,
                    headers,
                },
                (proxyRes) => {
                    const outHeaders = {};
                    Object.keys(proxyRes.headers || {}).forEach((k) => {
                        const key = String(k || '').toLowerCase();
                        if (!key || hopByHop.has(key)) return;
                        outHeaders[k] = proxyRes.headers[k];
                    });

                    // Preserve any headers already set on the Fastify reply (e.g. CORS from onRequest hook).
                    try {
                        const existing = reply && typeof reply.getHeaders === 'function' ? reply.getHeaders() : null;
                        if (existing && typeof existing === 'object') {
                            const outLower = new Set(Object.keys(outHeaders).map((k) => String(k || '').toLowerCase()));
                            Object.keys(existing).forEach((k) => {
                                const key = String(k || '');
                                const lower = key.toLowerCase();
                                if (!lower || hopByHop.has(lower)) return;
                                if (outLower.has(lower)) return;
                                outHeaders[key] = existing[k];
                                outLower.add(lower);
                            });
                        }
                    } catch (_) {}
                    try {
                        reply.raw.writeHead(proxyRes.statusCode || 502, outHeaders);
                    } catch (_) {}
                    proxyRes.pipe(reply.raw);
                    proxyRes.on('end', () => resolve());
                }
            );
            proxyReq.on('error', (err) => {
                try {
                    reply.raw.statusCode = 502;
                    reply.raw.setHeader('content-type', 'application/json; charset=utf-8');
                    try {
                        const origin = request && request.headers ? request.headers.origin : '';
                        if (origin) reply.raw.setHeader('Access-Control-Allow-Origin', origin);
                        else reply.raw.setHeader('Access-Control-Allow-Origin', '*');
                    } catch (_) {}
                    reply.raw.end(JSON.stringify({ error: (err && err.message) || 'proxy failed' }));
                } catch (_) {}
                resolve();
            });
            try {
                const method = String(request.method || 'GET').toUpperCase();
                const body = request && Object.prototype.hasOwnProperty.call(request, 'body') ? request.body : undefined;

                if (body !== undefined && body !== null && method !== 'GET' && method !== 'HEAD') {
                    let buf = null;
                    if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
                        buf = Buffer.from(body);
                    } else if (typeof body === 'string') {
                        buf = Buffer.from(body, 'utf8');
                    } else if (typeof body === 'object') {
                        buf = Buffer.from(JSON.stringify(body), 'utf8');
                        if (!headers['content-type']) headers['content-type'] = 'application/json';
                    }
                    if (buf) {
                        proxyReq.setHeader('content-length', String(buf.length));
                        proxyReq.end(buf);
                        return;
                    }
                }

                if (request && request.raw) request.raw.pipe(proxyReq);
                else proxyReq.end();
            } catch (_) {
                try {
                    proxyReq.end();
                } catch (_) {}
            }
        });
    };

    const onlineSpiderInitPromises = new Map(); // key -> Promise<void>
    const onlineSpiderInited = new Set(); // key

    const ensureOnlineSpiderInited = async function (id, targetPort, spiderKey, spiderType) {
        const k = `${id}:${spiderKey}:${spiderType}`;
        if (onlineSpiderInited.has(k)) return;
        if (onlineSpiderInitPromises.has(k)) return await onlineSpiderInitPromises.get(k);

        const run = async () => {
            const initPath = `/spider/${encodeURIComponent(spiderKey)}/${encodeURIComponent(String(spiderType))}/init`;
            const doReq = (method) =>
                new Promise((resolve, reject) => {
                    const req = http.request(
                        {
                            hostname: '127.0.0.1',
                            port: targetPort,
                            method,
                            path: initPath,
                            headers: {
                                host: `127.0.0.1:${targetPort}`,
                                accept: 'application/json, text/plain, */*',
                                'content-type': 'application/json',
                            },
                        },
                        (res) => {
                            const chunks = [];
                            res.on('data', (c) => chunks.push(c));
                            res.on('end', () => {
                                const status = Number(res.statusCode || 0);
                                if (status >= 200 && status < 300) return resolve({ status, body: Buffer.concat(chunks).toString('utf8') });
                                if (status === 404) return resolve({ status, body: Buffer.concat(chunks).toString('utf8') });
                                return reject(
                                    new Error(
                                        `init failed status=${status || 'unknown'} body=${Buffer.concat(chunks).toString('utf8').slice(0, 200)}`
                                    )
                                );
                            });
                        }
                    );
                    req.on('error', reject);
                    if (method === 'POST') req.end('{}');
                    else req.end();
                });

            // Some scripts expose init as GET, some as POST; try POST first.
            const first = await doReq('POST');
            if (first && first.status === 404) await doReq('GET');
        };

        const p = run()
            .then(() => {
                onlineSpiderInited.add(k);
            })
            .finally(() => {
                onlineSpiderInitPromises.delete(k);
            });
        onlineSpiderInitPromises.set(k, p);
        return await p;
    };

    // Explicit id-based proxy: /online/:id/* -> the runtime port for that script id.
    fastify.all('/online/:id', async function (request, reply) {
        if (String(request && request.method || '').toUpperCase() === 'OPTIONS') return reply.code(204).send();
        const id = request && request.params ? String(request.params.id || '').trim() : '';
        const port = fastify && fastify.onlineRuntimePorts && typeof fastify.onlineRuntimePorts.get === 'function' ? fastify.onlineRuntimePorts.get(id) : null;
        const p = Number.isFinite(Number(port)) ? Math.max(1, Math.trunc(Number(port))) : 0;
        if (!id || !p) return reply.code(404).send({ error: 'online runtime not found', id });
        return proxyToPort(request, reply, p, '/');
    });
    fastify.all('/online/:id/*', async function (request, reply) {
        if (String(request && request.method || '').toUpperCase() === 'OPTIONS') return reply.code(204).send();
        const id = request && request.params ? String(request.params.id || '').trim() : '';
        const port = fastify && fastify.onlineRuntimePorts && typeof fastify.onlineRuntimePorts.get === 'function' ? fastify.onlineRuntimePorts.get(id) : null;
        const p = Number.isFinite(Number(port)) ? Math.max(1, Math.trunc(Number(port))) : 0;
        if (!id || !p) return reply.code(404).send({ error: 'online runtime not found', id });

        const tail = request && request.params ? String(request.params['*'] || '') : '';
        const normalizedTail = String(tail || '').replace(/^\/+/, '');
        const m = /^spider\/([^/]+)\/(\d+)\//.exec(normalizedTail);
        if (m) {
            const key = m[1];
            const type = m[2];
            const isInit = normalizedTail === `spider/${key}/${type}/init`;
            if (!isInit) {
                try {
                    await ensureOnlineSpiderInited(id, p, key, type);
                } catch (_) {}
            }
        }
        const rawUrl = request && request.raw && typeof request.raw.url === 'string' ? request.raw.url : '';
        const query = rawUrl && rawUrl.includes('?') ? `?${rawUrl.split('?').slice(1).join('?')}` : '';
        const forwardPath = `/${tail || ''}${query}`;
        return proxyToPort(request, reply, p, forwardPath);
    });

    // Preferred id-based proxy: /:id/spider/...  (avoid catching /api, /admin, etc by using a strict id pattern).
    fastify.all('/:id([a-f0-9]{10})', async function (request, reply) {
        if (String(request && request.method || '').toUpperCase() === 'OPTIONS') return reply.code(204).send();
        const id = request && request.params ? String(request.params.id || '').trim() : '';
        const port = fastify && fastify.onlineRuntimePorts && typeof fastify.onlineRuntimePorts.get === 'function' ? fastify.onlineRuntimePorts.get(id) : null;
        const p = Number.isFinite(Number(port)) ? Math.max(1, Math.trunc(Number(port))) : 0;
        if (!id || !p) return reply.code(404).send({ error: 'online runtime not found', id });
        return proxyToPort(request, reply, p, '/');
    });
    fastify.all('/:id([a-f0-9]{10})/*', async function (request, reply) {
        if (String(request && request.method || '').toUpperCase() === 'OPTIONS') return reply.code(204).send();
        const id = request && request.params ? String(request.params.id || '').trim() : '';
        const port = fastify && fastify.onlineRuntimePorts && typeof fastify.onlineRuntimePorts.get === 'function' ? fastify.onlineRuntimePorts.get(id) : null;
        const p = Number.isFinite(Number(port)) ? Math.max(1, Math.trunc(Number(port))) : 0;
        if (!id || !p) return reply.code(404).send({ error: 'online runtime not found', id });

        const tail = request && request.params ? String(request.params['*'] || '') : '';
        const normalizedTail = String(tail || '').replace(/^\/+/, '');
        const m = /^spider\/([^/]+)\/(\d+)\//.exec(normalizedTail);
        if (m) {
            const key = m[1];
            const type = m[2];
            const isInit = normalizedTail === `spider/${key}/${type}/init`;
            if (!isInit) {
                try {
                    await ensureOnlineSpiderInited(id, p, key, type);
                } catch (_) {}
            }
        }
        const rawUrl = request && request.raw && typeof request.raw.url === 'string' ? request.raw.url : '';
        const query = rawUrl && rawUrl.includes('?') ? `?${rawUrl.split('?').slice(1).join('?')}` : '';
        const forwardPath = `/${tail || ''}${query}`;
        return proxyToPort(request, reply, p, forwardPath);
    });

    // Online runtime routes must be accessed via an explicit id prefix.
    fastify.setNotFoundHandler(async function (request, reply) {
        // Security: do not leak runtime ids or routing hints for unregistered routes.
        return reply.code(403).send({ error: 'forbidden' });
    });
}
