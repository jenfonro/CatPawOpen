const { createServer } = require('http');

globalThis.catServerFactory = (handle) => {
  let port = 0;
  const server = createServer((req, res) => handle(req, res));
  server.on('listening', () => {
    port = server.address().port;
    console.log('Run on ' + port);
  });
  server.on('close', () => {
    console.log('Close on ' + port);
  });
  return server;
};

globalThis.catDartServerPort = () => 0;

const mod = require('./dist/index.js');
const cfgMod = require('./dist/index.config.js');
const cfg = cfgMod && (cfgMod.default || cfgMod);

const start = mod && mod.start ? mod.start : null;
const stop = mod && mod.stop ? mod.stop : null;
if (typeof start !== 'function') {
  console.error('start() not found');
  process.exit(1);
}

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    console.log('Shutting down' + (signal ? ` (${signal})` : '') + '...');
  } catch (_) {}
  try {
    if (typeof stop === 'function') {
      await stop();
    }
  } catch (err) {
    try {
      console.error(err);
    } catch (_) {}
  } finally {
    process.exit(0);
  }
}

try {
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGHUP', () => shutdown('SIGHUP'));
  process.once('SIGBREAK', () => shutdown('SIGBREAK'));
} catch (_) {}

Promise.resolve(start(cfg)).catch((err) => {
  console.error(err);
  process.exit(1);
});
