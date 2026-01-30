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
if (typeof start !== 'function') {
  console.error('start() not found');
  process.exit(1);
}
Promise.resolve(start(cfg)).catch((err) => {
  console.error(err);
  process.exit(1);
});

