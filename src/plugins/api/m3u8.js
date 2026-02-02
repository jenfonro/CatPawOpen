import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { URL } from 'node:url';

const DEFAULT_TTL_SECONDS = 30 * 60;
const MAX_URL_LEN = 8 * 1024;

function nowMs() {
  return Date.now();
}

function safeTrim(v) {
  return typeof v === 'string' ? v.trim() : '';
}

function normalizeHeaders(input) {
  const h = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const out = {};
  for (const [k0, v0] of Object.entries(h)) {
    const k = safeTrim(k0);
    if (!k) continue;
    if (v0 == null) continue;
    const v = safeTrim(String(v0));
    if (!v) continue;
    out[k] = v;
  }
  return out;
}

function isHttpUrl(u) {
  try {
    const p = new URL(u);
    return p.protocol === 'http:' || p.protocol === 'https:';
  } catch {
    return false;
  }
}

function normalizeHttpUrl(u) {
  const raw = safeTrim(u);
  if (!raw) return '';
  try {
    // Ensure a WHATWG-normalized, ASCII-safe URL string (percent-encoded pathname/query).
    const p = new URL(raw);
    return p.toString();
  } catch {
    return raw;
  }
}

function decodeQueryUrl(raw) {
  const s = safeTrim(String(raw || ''));
  if (!s) return '';
  // Fastify usually decodes query values, but keep it safe for double-encoded inputs.
  let v = s;
  try {
    v = decodeURIComponent(v);
  } catch {}
  return v;
}

function toNodeReadable(body) {
  if (!body) return null;
  // undici fetch: body is a WHATWG ReadableStream
  if (typeof body.getReader === 'function' && typeof Readable.fromWeb === 'function') {
    return Readable.fromWeb(body);
  }
  // node stream
  if (typeof body.pipe === 'function') return body;
  return null;
}

function ensureStore(fastify) {
  if (!fastify) return null;
  if (!fastify.m3u8Store) {
    fastify.m3u8Store = new Map();
  }
  return fastify.m3u8Store;
}

function sweepExpired(store) {
  if (!store || typeof store.forEach !== 'function') return;
  const t = nowMs();
  for (const [k, v] of store.entries()) {
    if (!v || !v.expiresAt || v.expiresAt <= t) store.delete(k);
  }
}

function getSession(store, token) {
  if (!store) return null;
  sweepExpired(store);
  const s = store.get(token);
  if (!s) return null;
  if (s.expiresAt && s.expiresAt <= nowMs()) {
    store.delete(token);
    return null;
  }
  return s;
}

function parseAttributeUri(tagLine) {
  // Extract URI="..." (first occurrence)
  const m = /URI\s*=\s*"([^"]+)"/i.exec(String(tagLine || ''));
  return m && m[1] ? String(m[1]) : '';
}

function replaceAttributeUri(tagLine, nextUri) {
  const line = String(tagLine || '');
  if (!line) return line;
  if (!/URI\s*=\s*"/i.test(line)) return line;
  return line.replace(/URI\s*=\s*"([^"]*)"/i, (_all, _v) => `URI="${nextUri}"`);
}

function absolutizeMaybe(uri, baseUrl) {
  const u = safeTrim(uri);
  if (!u) return '';
  try {
    return new URL(u, baseUrl).toString();
  } catch {
    return u;
  }
}

function classifyUriKind(absUrl) {
  const s = safeTrim(absUrl);
  if (!s) return 'seg';
  try {
    const u = new URL(s);
    const p = String(u.pathname || '').toLowerCase();
    if (p.endsWith('.m3u8')) return 'pl';
  } catch {}
  return 'seg';
}

function buildProxyPath(token, kind, absUrl) {
  const enc = encodeURIComponent(absUrl);
  if (kind === 'key') return `/api/m3u8/${encodeURIComponent(token)}/key?u=${enc}`;
  if (kind === 'pl') return `/api/m3u8/${encodeURIComponent(token)}/pl?u=${enc}`;
  return `/api/m3u8/${encodeURIComponent(token)}/seg?u=${enc}`;
}

function rewritePlaylistText(text, { token, baseUrl, mode }) {
  const raw = typeof text === 'string' ? text : '';
  if (!raw) return '';
  const lines = raw.split(/\r?\n/);
  const out = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const trimmed = String(line || '').trim();
    if (!trimmed) {
      out.push(line);
      continue;
    }
    if (trimmed.startsWith('#')) {
      // Tags with URI="..."
      if (/^#EXT-X-(KEY|SESSION-KEY|MAP|MEDIA|I-FRAME-STREAM-INF)\b/i.test(trimmed) && /URI\s*=\s*"/i.test(trimmed)) {
        const uri = parseAttributeUri(trimmed);
        const abs = uri ? absolutizeMaybe(uri, baseUrl) : '';
        if (mode === 'proxy') {
          const kind = /^#EXT-X-(KEY|SESSION-KEY|MAP)\b/i.test(trimmed) ? 'key' : 'pl';
          const nextUri = abs ? buildProxyPath(token, kind, abs) : uri;
          out.push(replaceAttributeUri(line, nextUri));
        } else {
          // index mode: keep "original" but normalize to absolute so the client can resolve correctly.
          const nextUri = abs || uri;
          out.push(replaceAttributeUri(line, nextUri));
        }
        continue;
      }
      out.push(line);
      continue;
    }

    // URI line (segment or playlist)
    const abs = absolutizeMaybe(trimmed, baseUrl);
    if (mode === 'proxy') {
      const kind = classifyUriKind(abs);
      out.push(buildProxyPath(token, kind, abs));
    } else {
      out.push(abs || trimmed);
    }
  }

  return out.join('\n');
}

async function fetchUpstreamText(url, headers) {
  const res = await fetch(url, { method: 'GET', headers, redirect: 'follow' });
  const buf = await res.arrayBuffer();
  const text = Buffer.from(buf).toString('utf8');
  return { res, text };
}

function buildUpstreamHeaders(sessionHeaders, request) {
  const out = { ...normalizeHeaders(sessionHeaders) };
  // Forward some safe headers from client (Range/If-Range) at proxy endpoints.
  const h = request && request.headers ? request.headers : {};
  const range = h.range || h.Range || '';
  const ifRange = h['if-range'] || h['If-Range'] || '';
  if (range) out.Range = String(range);
  if (ifRange) out['If-Range'] = String(ifRange);
  return out;
}

function copyUpstreamResponseHeaders(reply, upstreamHeaders, opts) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const stripContentLength = !!options.stripContentLength;
  const stripContentEncoding = !!options.stripContentEncoding;
  const deny = new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade',
  ]);
  const expose = [];
  for (const [k, v] of upstreamHeaders.entries()) {
    const key = String(k || '').toLowerCase();
    if (!key || deny.has(key)) continue;
    if (stripContentLength && key === 'content-length') continue;
    if (stripContentEncoding && key === 'content-encoding') continue;
    try {
      reply.header(k, v);
      if (
        key === 'accept-ranges' ||
        key === 'content-range' ||
        key === 'content-length' ||
        key === 'content-type' ||
        key === 'etag' ||
        key === 'last-modified'
      ) {
        expose.push(k);
      }
    } catch {}
  }
  // Ensure range-related headers are readable by browsers (HLS engines).
  const baseExpose = ['Accept-Ranges', 'Content-Range', 'Content-Length', 'Content-Type', 'ETag', 'Last-Modified'];
  const merged = Array.from(new Set([...baseExpose, ...expose]));
  try {
    reply.header('Access-Control-Expose-Headers', merged.join(', '));
  } catch {}
}

function apiError(reply, status, message) {
  reply.code(status);
  return { ok: false, message: String(message || 'error') };
}

const apiPlugins = [
  {
    prefix: '/api/m3u8',
    plugin: async function m3u8Api(fastify) {
      const store = ensureStore(fastify);

      fastify.post('/register', async function (request, reply) {
        const body = request && request.body && typeof request.body === 'object' ? request.body : {};
        const upstreamUrlRaw = safeTrim(body && body.url);
        const upstreamUrl = normalizeHttpUrl(upstreamUrlRaw);
        if (!upstreamUrl) return apiError(reply, 400, 'missing url');
        if (upstreamUrl.length > MAX_URL_LEN) return apiError(reply, 400, 'url too long');
        if (!isHttpUrl(upstreamUrl)) return apiError(reply, 400, 'invalid url');

        const ttl = Number(body && body.ttlSeconds) || DEFAULT_TTL_SECONDS;
        const ttlSeconds = Math.max(30, Math.min(24 * 3600, ttl));
        const headers = normalizeHeaders(body && body.headers);

        const token = crypto.randomBytes(12).toString('hex');
        const createdAt = nowMs();
        store.set(token, {
          token,
          upstreamUrl,
          headers,
          createdAt,
          expiresAt: createdAt + ttlSeconds * 1000,
        });

        return {
          ok: true,
          token,
          index: `/api/m3u8/${encodeURIComponent(token)}/index.m3u8`,
          proxy: `/api/m3u8/${encodeURIComponent(token)}/proxy.m3u8`,
        };
      });

      // Return "original sources" playlist (not proxied), but normalize all URIs to absolute
      // so hls.js can resolve segments correctly even when this playlist is served from CatPawOpen.
      fastify.get('/:token/index.m3u8', async function (request, reply) {
        const token = safeTrim(request && request.params ? request.params.token : '');
        if (!token) return apiError(reply, 404, 'not found');
        const session = getSession(store, token);
        if (!session) return apiError(reply, 404, 'not found');

        const { res, text } = await fetchUpstreamText(session.upstreamUrl, session.headers);
        reply.code(res.status || 200);
        reply.type('application/vnd.apple.mpegurl; charset=utf-8');
        // Avoid injecting raw upstream URL into headers: non-ASCII characters can crash Node's header validator.
        const normalized = rewritePlaylistText(text, { token, baseUrl: session.upstreamUrl, mode: 'index' });
        return normalized;
      });

      // Return proxied playlist (segments/key/child playlists are rewritten to CatPawOpen proxy endpoints).
      fastify.get('/:token/proxy.m3u8', async function (request, reply) {
        const token = safeTrim(request && request.params ? request.params.token : '');
        if (!token) return apiError(reply, 404, 'not found');
        const session = getSession(store, token);
        if (!session) return apiError(reply, 404, 'not found');

        const { res, text } = await fetchUpstreamText(session.upstreamUrl, session.headers);
        reply.code(res.status || 200);
        reply.type('application/vnd.apple.mpegurl; charset=utf-8');
        const rewritten = rewritePlaylistText(text, { token, baseUrl: session.upstreamUrl, mode: 'proxy' });
        return rewritten;
      });

      // Proxy a child playlist (multi-level m3u8). Response is also rewritten.
      fastify.get('/:token/pl', async function (request, reply) {
        const token = safeTrim(request && request.params ? request.params.token : '');
        if (!token) return apiError(reply, 404, 'not found');
        const session = getSession(store, token);
        if (!session) return apiError(reply, 404, 'not found');
        const u = decodeQueryUrl(request && request.query ? request.query.u : '');
        if (!u) return apiError(reply, 400, 'missing u');
        if (u.length > MAX_URL_LEN) return apiError(reply, 400, 'u too long');
        if (!isHttpUrl(u)) return apiError(reply, 400, 'invalid u');

        const { res, text } = await fetchUpstreamText(u, session.headers);
        reply.code(res.status || 200);
        reply.type('application/vnd.apple.mpegurl; charset=utf-8');
        const rewritten = rewritePlaylistText(text, { token, baseUrl: u, mode: 'proxy' });
        return rewritten;
      });

      // Proxy a segment (ts/m4s...) or key file. Supports Range by forwarding request's Range/If-Range.
      const proxyBinary = async (request, reply, kind) => {
        const token = safeTrim(request && request.params ? request.params.token : '');
        if (!token) return apiError(reply, 404, 'not found');
        const session = getSession(store, token);
        if (!session) return apiError(reply, 404, 'not found');
        const u = decodeQueryUrl(request && request.query ? request.query.u : '');
        if (!u) return apiError(reply, 400, 'missing u');
        if (u.length > MAX_URL_LEN) return apiError(reply, 400, 'u too long');
        if (!isHttpUrl(u)) return apiError(reply, 400, 'invalid u');

        const headers = buildUpstreamHeaders(session.headers, request);
        // Avoid transparent decompression by undici (Node fetch) which can cause Content-Length mismatches.
        // For binary segments/keys, always request identity encoding.
        if (!Object.keys(headers).some((k) => String(k).toLowerCase() === 'accept-encoding')) {
          headers['Accept-Encoding'] = 'identity';
        }
        const res = await fetch(u, { method: 'GET', headers, redirect: 'follow' });
        reply.code(res.status || 200);
        // When streaming, do not forward Content-Length/Encoding (Fastify will stream chunked),
        // otherwise browsers may throw ERR_CONTENT_LENGTH_MISMATCH.
        copyUpstreamResponseHeaders(reply, res.headers, { stripContentLength: true, stripContentEncoding: true });
        if (!reply.getHeader || !reply.getHeader('Content-Type')) {
          try {
            if (kind === 'key') reply.type('application/octet-stream');
          } catch {}
        }
        const body = toNodeReadable(res.body);
        if (body) return reply.send(body);
        const buf = await res.arrayBuffer().catch(() => null);
        if (!buf) return reply.send('');
        return reply.send(Buffer.from(buf));
      };

      fastify.get('/:token/seg', async function (request, reply) {
        return await proxyBinary(request, reply, 'seg');
      });
      fastify.get('/:token/key', async function (request, reply) {
        return await proxyBinary(request, reply, 'key');
      });
    },
  },
];

export { apiPlugins };
export default apiPlugins;
