import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { findAvailablePortInRange } from './tool.js';

const children = new Map(); // id -> { child, entry, port }
const starting = new Map(); // id -> Promise<startResult>

function getRootDir() {
    // Prefer the executable directory for pkg builds so `db.json` can sit next to the exe.
    try {
        if (process && process.pkg && typeof process.execPath === 'string' && process.execPath) {
            return path.dirname(process.execPath);
        }
    } catch (_) {}
    const p = typeof process.env.NODE_PATH === 'string' && process.env.NODE_PATH.trim() ? process.env.NODE_PATH.trim() : '';
    if (p) return path.resolve(p);
    return process.cwd();
}

function findOnlineEntry(onlineDir) {
    try {
        if (!onlineDir || !fs.existsSync(onlineDir)) return '';
        const preferred = path.resolve(onlineDir, '0119.js');
        if (fs.existsSync(preferred)) return preferred;
        const files = fs
            .readdirSync(onlineDir, { withFileTypes: true })
            .filter(
                (d) =>
                    d &&
                    d.isFile() &&
                    typeof d.name === 'string' &&
                    d.name &&
                    !d.name.startsWith('.') &&
                    d.name !== 'node_modules' &&
                    d.name !== '.catpaw_online_runtime_bootstrap.cjs' &&
                    /\.(js|cjs|mjs)$/i.test(d.name)
            )
            .map((d) => path.resolve(onlineDir, d.name))
            .sort((a, b) => a.localeCompare(b, 'en'));
        return files[0] || '';
    } catch (_) {
        return '';
    }
}

export async function startOnlineRuntime({ id = 'default', port, logPrefix = '[online]', entry: entryOverride = '' } = {}) {
    const rootDir = getRootDir();
    const onlineDir = path.resolve(rootDir, 'custom_spider');
    const entry =
        entryOverride && typeof entryOverride === 'string' && entryOverride.trim()
            ? path.resolve(entryOverride.trim())
            : findOnlineEntry(onlineDir);
    if (!entry) return { started: false, port: 0, entry: '' };

    // Online runtime port must not default to the main server port (commonly 9988).
    // If caller does not provide a port, auto-pick a free port in the online range.
    const parsedPort = Number.isFinite(Number(port)) ? Math.max(0, Math.trunc(Number(port))) : 0;
    if (!parsedPort) {
        try {
            // eslint-disable-next-line no-console
            console.warn(`${logPrefix} port not provided; auto-picking one`);
        } catch (_) {}
    }
    const p = parsedPort || (await findAvailablePortInRange(30000, 39999));

    const isPkg = (() => {
        try {
            return !!(process && process.pkg);
        } catch (_) {
            return false;
        }
    })();

    const key = typeof id === 'string' && id.trim() ? id.trim() : 'default';

    // Coalesce concurrent start attempts for the same id.
    const inflight = starting.get(key);
    if (inflight) {
        try {
            return await inflight;
        } catch (_) {
            // fallthrough
        }
    }

    const startPromise = (async () => {
    const prev = children.get(key) || null;

    // Avoid duplicate processes across hot restarts.
    if (prev && prev.child && !prev.child.killed && prev.entry === entry && prev.port === p) {
        return { started: true, port: prev.port, entry: prev.entry, reused: true, id: key };
    }

    try {
        if (prev && prev.child && !prev.child.killed) prev.child.kill();
    } catch (_) {}

			const bootstrap = `
			(() => {
			  const __send = (m) => { try { if (typeof process.send === 'function') process.send(m); } catch (_) {} };
			  // Exit when parent process disappears.
			  // This is important on Windows (and some service managers) where child processes
			  // can outlive the parent if the parent is force-killed.
			  try {
			    if (process.stdin && typeof process.stdin.on === 'function') {
			      process.stdin.resume();
			      const exitIfClosed = () => {
			        try { process.exit(0); } catch (_) {}
			      };
			      process.stdin.once('end', exitIfClosed);
			      process.stdin.once('close', exitIfClosed);
			      process.stdin.once('error', exitIfClosed);
			    }
			  } catch (_) {}

			  const http = require('http');
			  const https = require('https');
			  const fs = require('fs');
			  const path = require('path');
			  const Module = require('module');
		  const nodeCrypto = require('crypto');
		  let CryptoJS = null;
		  try { CryptoJS = require('crypto-js'); } catch (_) { CryptoJS = null; }
		  const vm = require('vm');

		  try { if (process.env.ONLINE_CWD) process.chdir(process.env.ONLINE_CWD); } catch (_) {}

		  // Some bundled spiders expect CryptoJS-style helpers on crypto (e.g. crypto.MD5),
		  // while others expect Node crypto (e.g. crypto.createHash). Provide a compatible object
		  // for require('crypto') and also ensure globalThis.crypto has MD5/SHA* while preserving WebCrypto methods.
		  try {
		    const webcrypto = (() => {
		      try {
		        const c = globalThis && globalThis.crypto;
		        return c && typeof c === 'object' ? c : null;
		      } catch (_) {
		        return null;
		      }
		    })();

		    const md5Hex = (s) =>
		      nodeCrypto.createHash('md5').update(String(s == null ? '' : s), 'utf8').digest('hex');
		    const sha1Hex = (s) =>
		      nodeCrypto.createHash('sha1').update(String(s == null ? '' : s), 'utf8').digest('hex');
		    const sha256Hex = (s) =>
		      nodeCrypto.createHash('sha256').update(String(s == null ? '' : s), 'utf8').digest('hex');

		    const wordArrayFromHex = (hex) => ({
		      __hex: String(hex || ''),
		      toString(enc) {
		        if (enc && typeof enc.stringify === 'function') return enc.stringify(this);
		        return this.__hex;
		      },
		    });

		    const cryptoCompat =
		      CryptoJS && typeof CryptoJS === 'object'
		        ? CryptoJS
		        : {
		            enc: {
		              Hex: {
		                stringify(wa) {
		                  if (wa && typeof wa.__hex === 'string') return wa.__hex;
		                  if (wa && typeof wa.toString === 'function') return wa.toString();
		                  return String(wa == null ? '' : wa);
		                },
		              },
		            },
		            MD5(s) {
		              return wordArrayFromHex(md5Hex(s));
		            },
		            SHA1(s) {
		              return wordArrayFromHex(sha1Hex(s));
		            },
		            SHA256(s) {
		              return wordArrayFromHex(sha256Hex(s));
		            },
		          };

		    if (cryptoCompat && typeof cryptoCompat === 'object') {
		      if (typeof cryptoCompat.md5 !== 'function') cryptoCompat.md5 = cryptoCompat.MD5;
		      if (typeof cryptoCompat.sha1 !== 'function') cryptoCompat.sha1 = cryptoCompat.SHA1;
		      if (typeof cryptoCompat.sha256 !== 'function') cryptoCompat.sha256 = cryptoCompat.SHA256;
		    }

		    const composite = new Proxy(cryptoCompat || {}, {
		      get(target, prop) {
		        if (target && prop in target) return target[prop];
		        if (nodeCrypto && prop in nodeCrypto) return nodeCrypto[prop];
		        return undefined;
		      },
		    });

		    // Expose CryptoJS (or a minimal substitute) for scripts that reference it directly.
		    globalThis.CryptoJS = cryptoCompat;

		    // Preserve WebCrypto methods on the object scripts see as global crypto.
		    try {
		      if (webcrypto && typeof webcrypto === 'object') {
		        if (!composite.subtle && webcrypto.subtle) composite.subtle = webcrypto.subtle;
		        if (typeof composite.getRandomValues !== 'function' && typeof webcrypto.getRandomValues === 'function') {
		          composite.getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
		        }
		        if (typeof composite.randomUUID !== 'function' && typeof webcrypto.randomUUID === 'function') {
		          composite.randomUUID = webcrypto.randomUUID.bind(webcrypto);
		        }
		      }
		    } catch (_) {}

		    // Make sure scripts that use the global crypto variable can call crypto.MD5(...).
		    // Some bundles overwrite global crypto; we keep it pinned to the composite but still accept WebCrypto updates.
		    try {
		      Object.defineProperty(globalThis, 'crypto', {
		        configurable: true,
		        enumerable: true,
		        get() {
		          return composite;
		        },
		        set(v) {
		          try {
		            if (v && typeof v === 'object') {
		              if (!composite.subtle && v.subtle) composite.subtle = v.subtle;
		              if (typeof composite.getRandomValues !== 'function' && typeof v.getRandomValues === 'function') {
		                composite.getRandomValues = v.getRandomValues.bind(v);
		              }
		              if (typeof composite.randomUUID !== 'function' && typeof v.randomUUID === 'function') {
		                composite.randomUUID = v.randomUUID.bind(v);
		              }
		            }
		          } catch (_) {}
		        },
		      });
		    } catch (_) {
		      try {
		        globalThis.crypto = composite;
		      } catch (_) {}
		    }

		    // Ensure any require('crypto') within the online script resolves to our composite.
		    try {
		      const origLoad = Module._load;
		      Module._load = function patchedLoad(request, parent, isMain) {
		        try {
		          if (request === 'crypto' || request === 'node:crypto') return composite;
		          if (request === 'crypto-js') return cryptoCompat;
		        } catch (_) {}
		        return origLoad.apply(this, arguments);
		      };
		    } catch (_) {}

		    try {
		      const origRequire = require;
		      globalThis.require = function patchedRequire(name) {
		        try {
		          const mod = String(name || '').trim();
		          if (mod === 'crypto' || mod === 'node:crypto') return composite;
		          if (mod === 'crypto-js') return cryptoCompat;
		        } catch (_) {}
		        return origRequire(name);
		      };
		    } catch (_) {}
		  } catch (_) {}
			  globalThis.catServerFactory = (handle) => {
			    const srv = http.createServer((req, res) => handle(req, res));
			    try {
			      srv.on('listening', () => {
			        try {
			          const a = srv.address && typeof srv.address === 'function' ? srv.address() : null;
			          __send({ type: 'listening', port: a && a.port ? a.port : 0 });
			        } catch (_) {}
			      });
			    } catch (_) {}
			    try {
			      srv.on('error', (e) => {
			        try {
			          __send({
			            type: 'listen_error',
			            code: e && e.code ? String(e.code) : '',
			            message: e && e.message ? String(e.message) : '',
			          });
			        } catch (_) {}
			        try { process.exit(1); } catch (_) {}
			      });
			    } catch (_) {}
			    return srv;
			  };
			  globalThis.catDartServerPort = () => 0;

  const entry = process.env.ONLINE_ENTRY;
  if (!entry) throw new Error('missing ONLINE_ENTRY');

  globalThis.module = globalThis.module && typeof globalThis.module === 'object' ? globalThis.module : { exports: {} };
  globalThis.exports = globalThis.module.exports;
  globalThis.require = typeof globalThis.require === 'function' ? globalThis.require : require;
  globalThis.__filename = entry;
  const __onlineCwd = (typeof process.env.ONLINE_CWD === 'string' && process.env.ONLINE_CWD.trim()) ? process.env.ONLINE_CWD.trim() : process.cwd();
  globalThis.__dirname = path.resolve(__onlineCwd);

  try {
    const md5hex = (s) => nodeCrypto.createHash('md5').update(String(s || ''), 'utf8').digest('hex');
    const dbPath = path.resolve(__onlineCwd, 'db.json');
    const readDb = () => {
      try {
        if (!fs.existsSync(dbPath)) return null;
        const raw = fs.readFileSync(dbPath, 'utf8');
        const parsed = raw && raw.trim() ? JSON.parse(raw) : null;
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
      } catch (_) {
        return null;
      }
    };
    const pickCookie = (provider) => {
      const db = readDb();
      if (!db) return '';
      const bucket = db[provider];
      if (!bucket || typeof bucket !== 'object' || Array.isArray(bucket)) return '';
      const byKey = (k) => (typeof bucket[k] === 'string' ? String(bucket[k] || '').trim() : '');
      const val = byKey(md5hex('default')) || byKey(md5hex('')) || '';
      if (val) return val;
      const keys = Object.keys(bucket).filter((k) => k !== 'qktime');
      for (const k of keys) {
        const v = byKey(k);
        if (v) return v;
      }
      return '';
    };
    const patch = (mod) => {
      const orig = mod && typeof mod.request === 'function' ? mod.request : null;
      if (!orig) return;
      mod.request = function patchedRequest(options, cb) {
        try {
          const isUrl = options && typeof options === 'object' && options instanceof URL;
          const hostname = isUrl
            ? String(options.hostname || '')
            : options && typeof options === 'string'
              ? (() => { try { return String(new URL(options).hostname || ''); } catch (_) { return ''; } })()
              : String((options && (options.hostname || options.host)) || '');
          const host = String(hostname || '').toLowerCase();

          let provider = '';
          if (host.endsWith('quark.cn')) provider = 'quark';
          else if (host.endsWith('uc.cn') || host.includes('open-api-drive.uc.cn')) provider = 'uc';
          else if (host.endsWith('baidu.com')) provider = 'baidu';

          if (provider) {
            const cookie = pickCookie(provider);
            if (cookie) {
              const hdrs = (isUrl ? null : options && typeof options === 'object' ? options.headers : null) || {};
              const lower = Object.keys(hdrs).reduce((m, k) => { m[String(k).toLowerCase()] = k; return m; }, {});
              const ckKey = lower['cookie'] || 'Cookie';
              const cur = hdrs[ckKey];
              const curStr = cur == null ? '' : String(cur);
              if (!curStr.trim()) {
                hdrs[ckKey] = cookie;
                if (!isUrl && options && typeof options === 'object') options.headers = hdrs;
              }
            }
          }
        } catch (_) {}
        return orig.call(mod, options, cb);
      };
    };
    patch(http);
    patch(https);
  } catch (_) {}

  vm.runInThisContext(fs.readFileSync(entry, 'utf8'), { filename: entry });
})();

(async () => {
  const ensureConfigDefaults = (srv) => {
    try {
      if (!srv || typeof srv !== 'object') return;
	      if (!srv.config || typeof srv.config !== 'object' || Array.isArray(srv.config)) srv.config = {};
	      const ensureObj = (k) => {
	        const cur = srv.config[k];
	        if (!cur || typeof cur !== 'object' || Array.isArray(cur)) srv.config[k] = {};
	      };
      // Keys referenced by the bundled website/account routes.
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
      ].forEach(ensureObj);
      if (!Array.isArray(srv.config.pans.list)) srv.config.pans.list = [];
      if (!Array.isArray(srv.config.sites.list)) srv.config.sites.list = [];
	    } catch (_) {}
	  };

  const patchBodyShape = (srv) => {
    try {
      if (!srv || typeof srv.addHook !== 'function') return;
      srv.addHook('preValidation', async function (request) {
        try {
          if (!request) return;
          const method = String(request.method || '').toUpperCase();
          if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return;

          let body = request.body;
          if (body == null) {
            request.body = { data: {} };
            return;
          }

          if (Buffer.isBuffer(body) || body instanceof Uint8Array) body = Buffer.from(body).toString('utf8');

          if (typeof body === 'string') {
            const trimmed = body.trim();
            if (!trimmed) {
              request.body = { data: {} };
              return;
            }

            // JSON string
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
                // fallthrough
              }
            }

            // Plain string; best-effort treat it as cookie.
            request.body = { data: { cookie: body } };
            return;
          }

          if (!body || typeof body !== 'object' || Array.isArray(body)) {
            request.body = { data: {} };
            return;
          }

          if (body.data === undefined || body.data === null) {
            request.body = Object.assign({}, body, { data: body });
            return;
          }
          if (typeof body.data !== 'object' || Array.isArray(body.data)) {
            request.body = Object.assign({}, body, { data: Object.assign({}, body) });
          }
        } catch (_) {
          // best-effort only
        }
      });
    } catch (_) {
      // ignore if server is already ready/started
    }
	  };

  if (typeof globalThis.Ndr === 'function') {
	    // Some handlers expect request.body.data.cookie; normalize body shape up-front.
	    patchBodyShape(globalThis.xn);
	    const baseCfg = (() => {
	      return { sites: { list: [] }, pans: { list: [] }, color: [] };
	    })();
	    // Let the script's own JsonDB load persisted data from db.json.
	    await globalThis.Ndr(baseCfg);
	    patchBodyShape(globalThis.xn);
	    ensureConfigDefaults(globalThis.xn);
	    // Guard against accidental credential wipe:
	    // Some bundled scripts may push('/uc/<hash>', '') during unrelated flows (e.g. category probe),
	    // which overwrites a previously saved UC cookie with empty string.
	    try {
	      const srv = globalThis.xn;

	      if (srv && srv.db && typeof srv.db.push === 'function' && typeof srv.db.getData === 'function') {
	        const origPush = srv.db.push.bind(srv.db);
	        srv.db.push = async (...args) => {
	          try {
	            const p = args[0];
	            const v = args[1];
	            if (typeof p === 'string') {
	              // 1) Prevent overwriting "/uc/<md5>" with empty string if there is already a non-empty value.
	              if (/^\\/uc\\/[0-9a-f]{32}$/i.test(p) && typeof v === 'string' && v === '') {
	                try {
	                  const cur = await srv.db.getData(p);
	                  if (typeof cur === 'string' && cur.trim()) return cur;
	                } catch (_) {}
	              }

	              // 2) If a script writes the whole "/uc" object, keep existing non-empty md5 keys.
	              if (p === '/uc' && v && typeof v === 'object' && !Array.isArray(v)) {
	                let out = null;
	                for (const k of Object.keys(v)) {
	                  if (!/^[0-9a-f]{32}$/i.test(k)) continue;
	                  const vv = v[k];
	                  if (typeof vv !== 'string' || vv !== '') continue;
	                  try {
	                    const cur = await srv.db.getData('/uc/' + k);
	                    if (typeof cur === 'string' && cur.trim()) {
	                      if (!out) out = Object.assign({}, v);
	                      out[k] = cur;
	                    }
	                  } catch (_) {}
	                }
	                if (out) args[1] = out;
	              }
	            }
	          } catch (_) {}
	          return origPush(...args);
	        };
	      }
	    } catch (_) {}

    return;
  }
  throw new Error('Ndr() not found on globalThis');
})().catch((e) => { console.error(e && e.stack ? e.stack : e); process.exit(1); });
`.trim();

    // `pkg` executables don't reliably support `-e/--eval` for running an inline script.
    // Write a small bootstrap file to the online directory and execute it.
    // Keep bootstrap out of the script directory so it won't be mistaken as an online entry.
    const bootstrapPath = path.resolve(onlineDir, '.catpaw_online_runtime_bootstrap.cjs');
    try {
        if (!fs.existsSync(onlineDir)) fs.mkdirSync(onlineDir, { recursive: true });
        fs.writeFileSync(bootstrapPath, `${bootstrap}\n`, 'utf8');
    } catch (e) {
        const msg = e && e.message ? String(e.message) : String(e);
        throw new Error(`write bootstrap failed: ${msg}`);
    }

	    // In pkg builds, keep the online runtime quiet by default to avoid excessive IO.
	    const hasDevLogFile =
	        !isPkg && typeof process.env.CATPAW_LOG_FILE === 'string' && process.env.CATPAW_LOG_FILE.trim();
    // Keep stdin as a pipe so the child can detect parent exit via stdin close (see bootstrap above),
    // and open an IPC channel so we can confirm "listening" (and detect EADDRINUSE) reliably.
    const stdio = isPkg
        ? ['pipe', 'ignore', 'ignore', 'ipc']
        : hasDevLogFile
          ? ['pipe', 'pipe', 'pipe', 'ipc']
          : ['pipe', 'inherit', 'inherit', 'ipc'];

    const waitForReady = (childProc, expectedPort) =>
        new Promise((resolve) => {
            let done = false;
            const finish = (v) => {
                if (done) return;
                done = true;
                try {
                    clearTimeout(timer);
                } catch (_) {}
                try {
                    childProc.off('exit', onExit);
                } catch (_) {}
                try {
                    childProc.off('message', onMsg);
                } catch (_) {}
                resolve(v);
            };
            const onExit = (code, signal) => finish({ ok: false, code, signal, port: expectedPort });
            const onMsg = (msg) => {
                if (!msg || typeof msg !== 'object') return;
                if (msg.type === 'listening') {
                    const lp = Number.isFinite(Number(msg.port)) ? Math.max(1, Math.trunc(Number(msg.port))) : expectedPort;
                    finish({ ok: true, port: lp });
                    return;
                }
                if (msg.type === 'listen_error') {
                    const code = typeof msg.code === 'string' ? msg.code.trim() : '';
                    finish({ ok: false, listenError: { code, message: msg.message || '' }, port: expectedPort });
                }
            };
            childProc.on('exit', onExit);
            childProc.on('message', onMsg);
            const timer = setTimeout(() => finish({ ok: false, timeout: true, port: expectedPort }), 8000);
        });

    let chosenPort = p;
    for (let attempt = 0; attempt < 6; attempt += 1) {
        const child = spawn(process.execPath, [bootstrapPath], {
            stdio,
            cwd: rootDir,
            env: {
                ...process.env,
                DEV_HTTP_PORT: String(chosenPort),
                ONLINE_ENTRY: entry,
                ONLINE_CWD: rootDir,
                NODE_PATH: rootDir,
            },
        });
        children.set(key, { child, entry, port: chosenPort });

    if (!isPkg && child && (child.stdout || child.stderr) && typeof process.env.CATPAW_LOG_FILE === 'string' && process.env.CATPAW_LOG_FILE.trim()) {
        try {
            if (child.stdout) child.stdout.on('data', (d) => process.stdout.write(d));
        } catch (_) {}
        try {
            if (child.stderr) child.stderr.on('data', (d) => process.stderr.write(d));
        } catch (_) {}
    }

    try {
        // eslint-disable-next-line no-console
        console.log(`${logPrefix} runtime spawning: id=${key} entry=${path.basename(entry)} port=${chosenPort}`);
    } catch (_) {}

    child.on('exit', (code, signal) => {
        const cur = children.get(key);
        if (cur && cur.child && cur.child.pid) {
            try {
                // eslint-disable-next-line no-console
                console.log(`${logPrefix} runtime exited: id=${key} pid=${cur.child.pid} code=${code} signal=${signal || ''}`);
            } catch (_) {}
        }
        const latest = children.get(key);
        if (latest && latest.child === child) children.delete(key);
    });

        const ready = await waitForReady(child, chosenPort);
        if (ready && ready.ok) {
            const cur = children.get(key);
            if (cur && cur.child === child) cur.port = ready.port;
            try {
                // eslint-disable-next-line no-console
                console.log(`${logPrefix} runtime ready: id=${key} entry=${path.basename(entry)} port=${ready.port}`);
            } catch (_) {}
            return { started: true, port: ready.port, entry, reused: false, id: key };
        }

        // If failed, clean up.
        try {
            if (child && !child.killed) child.kill();
        } catch (_) {}

        const cur = children.get(key);
        if (cur && cur.child === child) children.delete(key);

        const code = ready && ready.listenError && ready.listenError.code ? String(ready.listenError.code) : '';
        if (code === 'EADDRINUSE') {
            // Retry with a different port.
            // eslint-disable-next-line no-await-in-loop
            chosenPort = await findAvailablePortInRange(30000, 39999);
            continue;
        }

        return { started: false, port: 0, entry: '' };
    }

    return { started: false, port: 0, entry: '' };
    })();

    starting.set(key, startPromise);
    try {
        return await startPromise;
    } finally {
        starting.delete(key);
    }
}

export function stopOnlineRuntime(id = 'default') {
    const key = typeof id === 'string' && id.trim() ? id.trim() : 'default';
    const cur = children.get(key);
    if (!cur || !cur.child || cur.child.killed) return false;
    try {
        cur.child.kill();
        return true;
    } catch (_) {
        return false;
    } finally {
        children.delete(key);
    }
}

export function stopAllOnlineRuntimes() {
    const keys = Array.from(children.keys());
    keys.forEach((k) => {
        try {
            stopOnlineRuntime(k);
        } catch (_) {}
    });
    return true;
}
