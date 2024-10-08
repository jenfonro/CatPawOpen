let currentProxy = '';

function normalizeProxyUrl(input) {
    const raw = typeof input === 'string' ? input.trim() : '';
    if (!raw) return '';
    let url;
    try {
        url = new URL(raw);
    } catch (_e) {
        throw new Error('Proxy 不是合法 URL');
    }

    const protocol = String(url.protocol || '').toLowerCase();
    if (protocol !== 'http:' && protocol !== 'https:') {
        throw new Error('暂仅支持 http/https 代理（Clash/mihomo mixed-port）');
    }

    if (!url.hostname) throw new Error('Proxy 缺少 hostname');
    if (!url.port) throw new Error('Proxy 缺少 port');

    return url.toString();
}

function applyEnvProxy(proxyUrl) {
    const set = (k, v) => {
        if (!v) {
            // eslint-disable-next-line no-undef
            delete process.env[k];
        } else {
            // eslint-disable-next-line no-undef
            process.env[k] = v;
        }
    };

    set('HTTP_PROXY', proxyUrl);
    set('HTTPS_PROXY', proxyUrl);
    set('ALL_PROXY', proxyUrl);
    set('http_proxy', proxyUrl);
    set('https_proxy', proxyUrl);
    set('all_proxy', proxyUrl);

    // Avoid proxying local services (CatPawOpen/TV_Server/Clash).
    set('NO_PROXY', '127.0.0.1,localhost,::1');
    set('no_proxy', '127.0.0.1,localhost,::1');
}

async function applyUndiciProxy(proxyUrl) {
    try {
        const undici = await import('undici');
        if (!undici || typeof undici.setGlobalDispatcher !== 'function') return;
        if (!proxyUrl) {
            undici.setGlobalDispatcher(new undici.Agent());
            return;
        }
        undici.setGlobalDispatcher(new undici.ProxyAgent(proxyUrl));
    } catch (_e) {
        // ignore
    }
}

export function getGlobalProxy() {
    return currentProxy;
}

export async function setGlobalProxy(proxyUrl) {
    const normalized = normalizeProxyUrl(proxyUrl);
    currentProxy = normalized;
    applyEnvProxy(normalized);
    await applyUndiciProxy(normalized);
    return currentProxy;
}

