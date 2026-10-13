import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import zlib from 'node:zlib';
import { getGlobalDispatcher, request, setGlobalDispatcher, upgrade as undiciUpgrade } from 'undici';
import native from 'proxy-watch';
import { RouteError, Routes, passwordStates, usableSteps } from '../dist/core.mjs';
import { SystemProxyDispatcher, negotiateAuth } from '../dist/undici.mjs';
import { systemProxyAgent } from '../dist/agent.mjs';
import { decodeUserinfo, parseChallenge, withValidEscapes } from '../dist/auth.mjs';
import { selfSigned } from './certs.mjs';

const listen = (server) =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));

const originSeen = [];
const proxySeen = [];
const connectSeen = [];
let origin;
let proxy;
let tlsOrigin;
let connectProxy;
let tlsConnectProxy;
let resetProxy;
let silentProxy;
const silentSockets = [];
const slowSockets = new Map();
let proxyConnections = 0;
let originConnections = 0;
let port;
let tlsPort;
let proxyUrl;
let connectProxyUrl;
let tlsConnectProxyUrl;
let resetProxyUrl;
let silentProxyUrl;
let env;

before(async () => {
  // Records the path, any `Proxy-Authorization` and the body. A path ending in `/slow`
  // answers its first byte at once and the rest 300 ms later, and its connection is kept in
  // `slowSockets`.
  origin = await listen(
    http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        originSeen.push([req.url, req.headers['proxy-authorization'], body]);
        if (!req.url.endsWith('/slow')) return res.end(`origin saw ${req.url}`);
        slowSockets.set(req.url, req.socket);
        res.write('origin saw ');
        setTimeout(() => res.end(req.url), 300);
      });
    }),
  );
  origin.on('upgrade', (req, socket) => {
    originSeen.push([req.url, req.headers['proxy-authorization']]);
    socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  });
  // A forwarding proxy that knows `origin.test`, a name nothing else resolves.
  proxy = await listen(
    http.createServer((req, res) => {
      proxySeen.push([req.url, req.headers['proxy-authorization']]);
      const upstream = http.request(
        req.url.replace('origin.test', '127.0.0.1'),
        { method: req.method },
        (response) => response.pipe(res),
      );
      req.pipe(upstream);
    }),
  );
  const { key, cert } = selfSigned('origin.test');
  tlsOrigin = await listen(
    https.createServer({ key, cert }, (req, res) => {
      originSeen.push([req.url, req.headers['proxy-authorization']]);
      req.resume();
      req.on('end', () => res.end(`origin saw ${req.url}`));
    }),
  );
  // CONNECT opens a tunnel to `origin.test`; the proxy itself dials 127.0.0.1.
  connectProxy = await listen(tunnelling(http.createServer()));
  // The same over TLS, with a certificate no default trust store accepts.
  tlsConnectProxy = await listen(tunnelling(https.createServer({ key, cert })));
  proxy.on('connection', () => (proxyConnections += 1));
  origin.on('connection', () => (originConnections += 1));
  // Accepts the connection, reads the request, and closes without answering.
  resetProxy = await listen(net.createServer((socket) => socket.once('data', () => socket.destroy())));
  // Accepts the connection and never answers.
  silentProxy = await listen(net.createServer((socket) => silentSockets.push(socket)));
  port = origin.address().port;
  tlsPort = tlsOrigin.address().port;
  proxyUrl = `http://user:pass@127.0.0.1:${proxy.address().port}`;
  connectProxyUrl = `http://user:pass@127.0.0.1:${connectProxy.address().port}`;
  tlsConnectProxyUrl = `https://user:pass@127.0.0.1:${tlsConnectProxy.address().port}`;
  resetProxyUrl = `http://127.0.0.1:${resetProxy.address().port}`;
  silentProxyUrl = `http://127.0.0.1:${silentProxy.address().port}`;
  env = { http_proxy: proxyUrl, no_proxy: 'localhost' };
});

after(() => {
  origin.close();
  proxy.close();
  tlsOrigin.close();
  connectProxy.close();
  tlsConnectProxy.close();
  resetProxy.close();
  for (const socket of silentSockets) socket.destroy();
  silentProxy.close();
});

function tunnelling(server) {
  server.on('connect', (req, client, head) => {
    connectSeen.push([req.url, req.headers['proxy-authorization']]);
    const port = Number(String(req.url).split(':').pop());
    const upstream = net.connect(port, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      client.pipe(upstream);
      upstream.pipe(client);
    });
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
  });
  return server;
}

const url = (path, host = 'origin.test') => `http://${host}:${port}${path}`;
const tlsUrl = (path) => `https://origin.test:${tlsPort}${path}`;

// A route that names fixed steps, in place of the OS settings.
class FixedRoutes extends Routes {
  constructor(route) {
    super({ env: {}, precedence: 'ignore', watch: false });
    this.fixed = route;
  }
  async route() {
    return this.fixed;
  }
}

// Holds the route of a URL ending in `hold` until `release()`, and counts route reads.
class GatedRoutes extends FixedRoutes {
  constructor(route, hold) {
    super(route);
    this.hold = hold;
    this.reads = 0;
    this.gate = new Promise((resolve) => (this.release = resolve));
  }
  async route(snapshot, target) {
    this.reads += 1;
    if (target.endsWith(this.hold)) await this.gate;
    return this.fixed;
  }
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

// Settles once the origin has started answering `path`, a `/slow` one: the request is then
// on its connection, and stays there for 300 ms.
async function answering(path) {
  while (!slowSockets.has(path)) await new Promise((resolve) => setTimeout(resolve, 5));
}

// Whether `socket` closes within `ms`.
const closesWithin = (socket, ms) =>
  socket.destroyed
    ? Promise.resolve(true)
    : Promise.race([
        new Promise((resolve) => socket.once('close', () => resolve(true))),
        new Promise((resolve) => setTimeout(() => resolve(false), ms).unref()),
      ]);

test('a PAC route no engine ran, and steps the client cannot speak, are errors', () => {
  assert.throws(() => usableSteps({ kind: 'pac' }, () => true), RouteError);
  assert.deepEqual(usableSteps({ kind: 'steps', steps: ['socks4://p:1', 'direct'] }, () => false), [
    'direct',
  ]);
  assert.throws(() => usableSteps({ kind: 'steps', steps: ['socks4://p:1'] }, () => false), /socks4/);
});

test('fetch: a proxied request carries the credentials to the proxy', async () => {
  const dispatcher = new SystemProxyDispatcher({ env, precedence: 'before-system' });
  const response = await fetch(url('/a'), { dispatcher });
  assert.equal(await response.text(), 'origin saw /a');
  assert.deepEqual(proxySeen.at(-1), [url('/a'), 'Basic dXNlcjpwYXNz']);
  await dispatcher.close();
});

// Node's own `fetch`, given no dispatcher, takes the one undici's `setGlobalDispatcher` set.
test('fetch: the dispatcher set as the global one routes a fetch that names none', async () => {
  const dispatcher = new SystemProxyDispatcher({ env, precedence: 'before-system' });
  const previous = getGlobalDispatcher();
  setGlobalDispatcher(dispatcher);
  try {
    const response = await fetch(url('/global'));
    assert.equal(await response.text(), 'origin saw /global');
    assert.deepEqual(proxySeen.at(-1), [url('/global'), 'Basic dXNlcjpwYXNz']);
  } finally {
    setGlobalDispatcher(previous);
    await dispatcher.close();
  }
});

test('fetch: a bypassed destination goes direct', async () => {
  const dispatcher = new SystemProxyDispatcher({ env, precedence: 'before-system' });
  const before = proxySeen.length;
  const response = await fetch(url('/b', 'localhost'), { dispatcher });
  assert.equal(await response.text(), 'origin saw /b');
  assert.equal(proxySeen.length, before);
  await dispatcher.close();
});

// Port 1 refuses: nothing listens there, and fetch takes it as a proxy's port.
const fallbackSteps = () => ['http://127.0.0.1:1', 'socks4://127.0.0.1:1', proxyUrl];

test('fetch: a step that cannot connect hands the request to the next', async () => {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes({ kind: 'steps', steps: fallbackSteps() }),
  });
  const response = await fetch(url('/f'), { dispatcher });
  assert.equal(await response.text(), 'origin saw /f');
  await dispatcher.close();
});

// fetch hands every body to the dispatcher as a stream, read once. A step that fails to
// connect has read none of it.
test('fetch: a request with a stream body is handed to the next step', async () => {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes({ kind: 'steps', steps: fallbackSteps() }),
  });
  let pulls = 0;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new TextEncoder().encode('streamed'));
      controller.close();
    },
  });
  const response = await fetch(url('/body'), { dispatcher, method: 'POST', body, duplex: 'half' });
  assert.equal(await response.text(), 'origin saw /body');
  assert.equal(originSeen.at(-1)[2], 'streamed');
  assert.equal(pulls, 1);
  await dispatcher.close();
});

test('fetch: a PAC route no engine ran fails rather than going direct', async () => {
  const before = originSeen.length;
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes({ kind: 'pac' }) });
  await assert.rejects(fetch(url('/pac', 'localhost'), { dispatcher }), (error) => {
    assert.equal(error.cause?.code, 'ERR_PROXY_ROUTE');
    return true;
  });
  assert.equal(originSeen.length, before);
  await dispatcher.close();
});

test('http.Agent: a proxied request carries the credentials to the proxy', async () => {
  const agent = systemProxyAgent({ env, precedence: 'before-system' });
  const body = await new Promise((resolve, reject) =>
    http
      .get(url('/agent'), { agent }, (res) => {
        let text = '';
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => resolve(text));
      })
      .on('error', reject),
  );
  assert.equal(body, 'origin saw /agent');
  assert.deepEqual(proxySeen.at(-1), [url('/agent'), 'Basic dXNlcjpwYXNz']);
  agent.destroy();
});

test('fetch: an https request goes through CONNECT and carries credentials to the proxy', async () => {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes({ kind: 'steps', steps: [connectProxyUrl] }),
    requestTls: { rejectUnauthorized: false },
  });
  const tunnels = connectSeen.length;
  const response = await fetch(tlsUrl('/https'), { dispatcher });
  assert.equal(await response.text(), 'origin saw /https');
  assert.deepEqual(connectSeen.slice(tunnels), [[`origin.test:${tlsPort}`, 'Basic dXNlcjpwYXNz']]);
  await dispatcher.close();
});

test('http.Agent: an https request goes through CONNECT and carries credentials to the proxy', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: [connectProxyUrl] }),
  });
  const tunnels = connectSeen.length;
  const body = await new Promise((resolve, reject) =>
    https
      .get(tlsUrl('/agent-https'), { agent, rejectUnauthorized: false }, (res) => {
        let text = '';
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => resolve(text));
      })
      .on('error', reject),
  );
  assert.equal(body, 'origin saw /agent-https');
  assert.deepEqual(connectSeen.slice(tunnels), [[`origin.test:${tlsPort}`, 'Basic dXNlcjpwYXNz']]);
  agent.destroy();
});

test('http.Agent: one agent takes http and https requests whatever the application sets on Error', async (t) => {
  const { prepareStackTrace, stackTraceLimit } = Error;
  t.after(() => Object.assign(Error, { prepareStackTrace, stackTraceLimit }));
  const formatter = () => 'formatted by the application';
  Object.assign(Error, { prepareStackTrace: formatter, stackTraceLimit: 0 });
  const agent = systemProxyAgent({ routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
  assert.equal(await httpText(`https://127.0.0.1:${tlsPort}/both`, agent, true), 'origin saw /both');
  assert.equal(await httpText(url('/both', '127.0.0.1'), agent), 'origin saw /both');
  assert.equal(Error.prepareStackTrace, formatter);
  assert.equal(Error.stackTraceLimit, 0);
  agent.destroy();
});

test('http.Agent: an https URL with no port goes to 443, and a protocol set on the agent stays', async (t) => {
  const { prepareStackTrace, stackTraceLimit } = Error;
  t.after(() => Object.assign(Error, { prepareStackTrace, stackTraceLimit }));
  Object.assign(Error, { prepareStackTrace: () => 'formatted by the application', stackTraceLimit: 0 });
  const agent = systemProxyAgent({ routes: new FixedRoutes({ kind: 'steps', steps: [connectProxyUrl] }) });
  const tunnels = connectSeen.length;
  // The proxy cannot reach port 443 here, and closes the tunnel.
  await assert.rejects(httpText('https://origin.test/', agent, true));
  assert.deepEqual(connectSeen.slice(tunnels).map(([target]) => target), ['origin.test:443']);
  assert.equal(agent.protocol, undefined);
  agent.protocol = 'https:';
  agent.defaultPort = 8443;
  assert.equal(agent.protocol, 'https:');
  assert.equal(agent.defaultPort, 8443);
  agent.destroy();
});

test('http.Agent: an https URL with no port goes to 443 under frozen intrinsics', () => {
  const script = `
    import https from 'node:https';
    import { systemProxyAgent } from ${JSON.stringify(new URL('../dist/agent.mjs', import.meta.url).href)};
    // Direct whatever the OS is set to: the variables come first and bypass the destination.
    const agent = systemProxyAgent({
      env: { all_proxy: 'http://127.0.0.1:1', no_proxy: '127.0.0.1' },
      precedence: 'before-system',
      watch: false,
    });
    https.get('https://127.0.0.1/', { agent }).on('error', (error) => {
      console.log(JSON.stringify({ code: error.code, port: error.port }));
      agent.destroy();
    });`;
  const out = execFileSync(process.execPath, ['--frozen-intrinsics', '--no-warnings', '--input-type=module', '-e', script], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  assert.deepEqual(JSON.parse(out), { code: 'ECONNREFUSED', port: 443 });
});

test('http.Agent: a step that cannot connect hands the request to the next', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: ['http://127.0.0.1:1', proxyUrl] }),
  });
  assert.equal(await httpText(url('/agent-next'), agent), 'origin saw /agent-next');
  assert.deepEqual(proxySeen.at(-1), [url('/agent-next'), 'Basic dXNlcjpwYXNz']);
  agent.destroy();
});

test('http.Agent: a failed proxy does not leave its credentials on a direct request', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({
      kind: 'steps',
      steps: ['http://user:secret@127.0.0.1:1', 'direct'],
    }),
  });
  const before = proxySeen.length;
  assert.equal(await httpText(url('/agent-direct', 'localhost'), agent), 'origin saw /agent-direct');
  assert.equal(proxySeen.length, before);
  assert.equal(originSeen.at(-1)[1], undefined);
  agent.destroy();
});

test('fetch: a failed proxy does not leave its credentials on a direct request', async () => {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes({
      kind: 'steps',
      steps: ['http://user:secret@127.0.0.1:1', 'direct'],
    }),
  });
  const before = proxySeen.length;
  const response = await fetch(url('/fetch-direct', 'localhost'), { dispatcher });
  assert.equal(await response.text(), 'origin saw /fetch-direct');
  assert.equal(proxySeen.length, before);
  assert.equal(originSeen.at(-1)[1], undefined);
  await dispatcher.close();
});

// The HTTP proxy agent rewrites the request, written body included, before it dials; the
// failed step puts it back.
test('http.Agent: a failed proxy hands the next step the request as it was written', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({
      kind: 'steps',
      steps: ['http://user:secret@127.0.0.1:1', 'direct'],
    }),
  });
  const text = await new Promise((resolve, reject) => {
    const req = http.request(url('/agent-post', 'localhost'), { agent, method: 'POST' }, (res) => {
      let text = '';
      res.on('data', (chunk) => (text += chunk));
      res.on('end', () => resolve(text));
    });
    req.on('error', reject);
    req.end('payload');
  });
  assert.equal(text, 'origin saw /agent-post');
  assert.deepEqual(originSeen.at(-1), ['/agent-post', undefined, 'payload']);
  agent.destroy();
});

test('http.Agent: a proxy before the last step is dialled once', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: [proxyUrl, 'direct'] }),
  });
  const before = proxyConnections;
  assert.equal(await httpText(url('/agent-once'), agent), 'origin saw /agent-once');
  assert.equal(proxyConnections - before, 1);
  agent.destroy();
});

// The tunnel is not open until the proxy answers CONNECT, so a silent proxy is a
// connection that took too long.
test('http.Agent: a proxy that does not answer CONNECT in time hands the request on', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: [silentProxyUrl, connectProxyUrl] }),
    connectTimeout: 200,
  });
  assert.equal(await httpText(tlsUrl('/agent-silent'), agent, true), 'origin saw /agent-silent');
  agent.destroy();
});

// The agent of the older settings is destroyed once its request finishes: its pooled
// connection closes then, well before the 5 s an idle one would wait.
test('http.Agent: a request in flight survives a change of settings', async () => {
  const routes = new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  const agent = systemProxyAgent({ routes });
  const slow = httpText(url('/agent/slow', 'localhost'), agent);
  await answering('/agent/slow');
  routes.generation = 1;
  assert.equal(await httpText(url('/agent-after', 'localhost'), agent), 'origin saw /agent-after');
  assert.equal(await slow, 'origin saw /agent/slow');
  assert.ok(await closesWithin(slowSockets.get('/agent/slow'), 2_000));
  agent.destroy();
});

test('http.Agent: a bypassed destination goes direct', async () => {
  const agent = systemProxyAgent({ env, precedence: 'before-system' });
  const before = proxySeen.length;
  assert.equal(await httpText(url('/agent-bypass', 'localhost'), agent), 'origin saw /agent-bypass');
  assert.equal(proxySeen.length, before);
  agent.destroy();
});

test('http.Agent: a PAC route no engine ran fails rather than going direct', async () => {
  const before = originSeen.length;
  const agent = systemProxyAgent({ routes: new FixedRoutes({ kind: 'pac' }) });
  await assert.rejects(httpText(url('/agent-pac', 'localhost'), agent), (error) => {
    assert.equal(error.code, 'ERR_PROXY_ROUTE');
    return true;
  });
  assert.equal(originSeen.length, before);
  agent.destroy();
});

test('http.Agent: an https request falls through a proxy that cannot connect', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: ['http://127.0.0.1:1', connectProxyUrl] }),
  });
  const tunnels = connectSeen.length;
  assert.equal(await httpText(tlsUrl('/agent-https-next'), agent, true), 'origin saw /agent-https-next');
  assert.deepEqual(connectSeen.slice(tunnels), [[`origin.test:${tlsPort}`, 'Basic dXNlcjpwYXNz']]);
  agent.destroy();
});

// The settings change while the first request waits for its route: it reads the route
// again, by the newer snapshot, and is sent.
test('http.Agent: a request whose route was read before a change reads it again', async () => {
  const routes = new GatedRoutes({ kind: 'steps', steps: [proxyUrl] }, '/agent-gen-old');
  const agent = systemProxyAgent({ routes });
  const old = httpText(url('/agent-gen-old'), agent);
  await tick();
  routes.generation = 1;
  assert.equal(await httpText(url('/agent-gen-new'), agent), 'origin saw /agent-gen-new');
  routes.release();
  assert.equal(await old, 'origin saw /agent-gen-old');
  assert.equal(routes.reads, 3);
  agent.destroy();
});

test('http.Agent: destroy refuses a later request', async () => {
  const agent = systemProxyAgent({ env, precedence: 'before-system' });
  agent.destroy();
  await assert.rejects(httpText(url('/agent-closed'), agent), (error) => {
    assert.equal(error.code, 'ERR_PROXY_CLOSED');
    return true;
  });
});

test('fetch: an https request falls through a proxy that cannot connect', async () => {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes({ kind: 'steps', steps: ['http://127.0.0.1:1', connectProxyUrl] }),
    requestTls: { rejectUnauthorized: false },
  });
  const tunnels = connectSeen.length;
  const response = await fetch(tlsUrl('/https-next'), { dispatcher });
  assert.equal(await response.text(), 'origin saw /https-next');
  assert.deepEqual(connectSeen.slice(tunnels), [[`origin.test:${tlsPort}`, 'Basic dXNlcjpwYXNz']]);
  await dispatcher.close();
});

test('fetch: a request whose route was read before a change reads it again', async () => {
  const routes = new GatedRoutes({ kind: 'steps', steps: [proxyUrl] }, '/gen-old');
  const dispatcher = new SystemProxyDispatcher({ routes });
  const old = fetch(url('/gen-old'), { dispatcher });
  await tick();
  routes.generation = 1;
  assert.equal(await (await fetch(url('/gen-new'), { dispatcher })).text(), 'origin saw /gen-new');
  routes.release();
  assert.equal(await (await old).text(), 'origin saw /gen-old');
  assert.equal(routes.reads, 3);
  await dispatcher.close();
});

// Past the bound, the request keeps the last route it read.
test('a route that keeps changing is read a bounded number of times', async () => {
  const routes = new (class extends FixedRoutes {
    async route() {
      this.generation += 1;
      return this.fixed;
    }
  })({ kind: 'steps', steps: ['direct'] });
  assert.deepEqual(await routes.resolve('http://x.test/', () => true), {
    steps: ['direct'],
    generation: 2,
  });
  assert.equal(routes.generation, 3);
});

// The agent of the older settings is closed once its request finishes: its connection closes
// then, well before undici's idle keep-alive of 4 s.
test('fetch: a request in flight survives a change of settings', async () => {
  const routes = new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  const dispatcher = new SystemProxyDispatcher({ routes });
  const slow = fetch(url('/fetch/slow', 'localhost'), { dispatcher }).then((r) => r.text());
  await answering('/fetch/slow');
  routes.generation = 1;
  assert.equal(await (await fetch(url('/fetch-after', 'localhost'), { dispatcher })).text(), 'origin saw /fetch-after');
  assert.equal(await slow, 'origin saw /fetch/slow');
  assert.ok(await closesWithin(slowSockets.get('/fetch/slow'), 2_000));
  await dispatcher.close();
});

// close() settles after the requests it took, the ones still reading their route and the
// ones on agents a change replaced, have finished.
test('fetch: close waits for the requests already taken', async () => {
  const routes = new GatedRoutes({ kind: 'steps', steps: ['direct'] }, '/held');
  const dispatcher = new SystemProxyDispatcher({ routes });
  const order = [];
  const slow = fetch(url('/close/slow', 'localhost'), { dispatcher })
    .then((r) => r.text())
    .then((text) => order.push('slow') && text);
  await answering('/close/slow');
  routes.generation = 1;
  const held = fetch(url('/held', 'localhost'), { dispatcher })
    .then((r) => r.text())
    .then((text) => order.push('held') && text);
  await tick();
  const closing = dispatcher.close().then(() => order.push('closed'));
  assert.equal(dispatcher.close(), dispatcher.close());
  routes.release();
  await Promise.all([slow, held, closing]);
  assert.equal(await held, 'origin saw /held');
  assert.equal(await slow, 'origin saw /close/slow');
  assert.equal(order.at(-1), 'closed');
});

test('fetch: close and destroy take a callback', async () => {
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
  await new Promise((resolve, reject) => dispatcher.close((error) => (error ? reject(error) : resolve())));
  const other = new SystemProxyDispatcher({ routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
  await new Promise((resolve, reject) => other.destroy((error) => (error ? reject(error) : resolve())));
  // With an error, the callback is the second argument; a later request is refused as after
  // any close.
  const third = new SystemProxyDispatcher({ routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
  const reason = new Error('gone');
  await new Promise((resolve, reject) => third.destroy(reason, (error) => (error ? reject(error) : resolve())));
  await assert.rejects(request(url('/destroyed', 'localhost'), { dispatcher: third }), (error) => {
    assert.equal(error.code, 'ERR_PROXY_CLOSED');
    return true;
  });
});

// Both clients show the watcher's last failure, which the routes keep until the next change.
test('watchError is the routes error', async () => {
  const routes = new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  const agent = systemProxyAgent({ routes });
  const dispatcher = new SystemProxyDispatcher({ routes });
  try {
    assert.equal(agent.watchError, null);
    assert.equal(dispatcher.watchError, null);
    routes.error = new Error('the watch stopped');
    assert.equal(agent.watchError, routes.error);
    assert.equal(dispatcher.watchError, routes.error);
  } finally {
    agent.destroy();
    await dispatcher.close();
  }
});

test('a routes passed in stays open when the client closes', async () => {
  let closes = 0;
  const routes = new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  routes.close = () => (closes += 1);
  await new SystemProxyDispatcher({ routes }).close();
  systemProxyAgent({ routes }).destroy();
  assert.equal(closes, 0);
});

// The states macOS and GNOME give cannot be produced on a test machine, so the settings
// are written out as `Snapshot.toJSON()` gives them.
test('decodeUserinfo keeps a run of escapes that does not decode and decodes every other run', () => {
  assert.equal(decodeUserinfo('p%zz'), 'p%zz');
  assert.equal(decodeUserinfo('a%20b%zz%41'), 'a b%zzA');
  assert.equal(decodeUserinfo('%ff%41'), '%ff%41');
  assert.equal(decodeUserinfo('%E2%82%AC'), '€');
});

test('parseChallenge reads parameters, and a long run with no = in linear time', () => {
  assert.deepEqual(
    [...parseChallenge('Basic realm="a, b", charset=UTF-8,x="q\\"t"').params],
    [['realm', 'a, b'], ['charset', 'UTF-8'], ['x', 'q"t']],
  );
  assert.equal(parseChallenge('Negotiate abc==').token68, 'abc==');
  // A run that is not a token68 (the `!`) falls to the parameter reader. Read from each of its
  // characters, 64 KiB (a whole head) takes seconds; read once, a few milliseconds.
  const started = performance.now();
  assert.deepEqual([...parseChallenge(`Basic ${'a'.repeat(64 * 1024)}!`).params], []);
  assert.ok(performance.now() - started < 1_000, `${performance.now() - started} ms`);
});

test('withValidEscapes hands a SOCKS agent credentials decodeURIComponent reads as written', () => {
  const step = withValidEscapes('socks5h://u%zz:p%20x%zz@proxy.example:1080');
  const url = new URL(step);
  assert.equal(decodeURIComponent(url.username), 'u%zz');
  assert.equal(decodeURIComponent(url.password), 'p x%zz');
  assert.equal(url.host, 'proxy.example:1080');
  assert.equal(withValidEscapes('socks5://proxy.example:1080'), 'socks5://proxy.example:1080');
});

test('Routes.passwordState answers a step whose user name has a malformed escape', () => {
  const routes = new Routes({
    env: { http_proxy: 'http://u%zz@proxy.example:8080' },
    precedence: 'before-system',
    watch: false,
  });
  assert.equal(routes.passwordState('http://u%zz@proxy.example:8080/'), 'Absent');
  routes.close();
});

test('passwordStates keys each manual proxy with a user name as a route step is keyed', () => {
  const use = (host, port, username, passwordState) => ({ kind: 'use', scheme: 'http', host, port, username, password: null, passwordState });
  const states = passwordStates({
    mode: {
      kind: 'manual',
      proxies: {
        http: use('proxy.example', 8080, 'alice', 'InKeychain'),
        https: use('[2001:db8::1]', 443, 'bob', 'NotRead'),
        socks: use('socks.example', 1080, null, null),
        ftp: { kind: 'disabled' },
      },
    },
  });
  assert.deepEqual([...states], [
    ['proxy.example:8080|alice', 'InKeychain'],
    ['2001:db8::1:443|bob', 'NotRead'],
  ]);
  assert.equal(passwordStates({ mode: { kind: 'pac', url: 'http://wpad/wpad.dat' } }).size, 0);
  assert.equal(passwordStates(undefined).size, 0);
});

test('Routes.passwordState reads the state of the step a route names', () => {
  const routes = new Routes({
    env: { http_proxy: 'http://alice@[::1]:8080', https_proxy: 'http://bob:pw@proxy.example' },
    precedence: 'before-system',
    watch: false,
  });
  assert.equal(routes.passwordState('http://alice@[::1]:8080/'), 'Absent');
  // The default port of `http:` is the one the settings name.
  assert.equal(routes.passwordState('http://bob:pw@proxy.example/'), 'Present');
  assert.equal(routes.passwordState('http://[::1]:8080/'), null);
  assert.equal(routes.passwordState('http://carol@[::1]:8080/'), null);
  assert.equal(routes.passwordState('direct'), null);
  routes.close();
});

test('a route with no PAC mode is answered without routeAsync', async () => {
  const routes = new Routes({ env: {}, precedence: 'ignore', watch: false });
  const calls = [];
  const snapshot = (kind) => ({
    route: () => (calls.push('route'), { kind, steps: kind === 'steps' ? ['direct'] : null }),
    routeAsync: async () => (calls.push('routeAsync'), { kind: 'steps', steps: ['direct'] }),
  });
  await routes.route(snapshot('steps'), 'http://a.example/');
  assert.deepEqual(calls.splice(0), ['route']);
  await routes.route(snapshot('pac'), 'http://a.example/');
  assert.deepEqual(calls.splice(0), ['route', 'routeAsync']);
  routes.close();
});

// The PAC options reach `routeAsync`; with `pac: 'none'` no engine runs, and a PAC route
// is an error rather than direct.
test('the PAC options reach routeAsync, and pac none runs no engine', async () => {
  const calls = [];
  const snapshot = {
    route: () => ({ kind: 'pac', steps: null }),
    routeAsync: async (...args) => (calls.push(args), { kind: 'steps', steps: ['direct'] }),
  };
  const policy = { myIpAddress: '192.0.2.7' };
  const options = { env: {}, precedence: 'ignore', watch: false, policy };
  const routes = new Routes({ ...options, pac: 'native', script: 'function F(){}', wpad: true });
  await routes.route(snapshot, 'http://a.example/');
  assert.deepEqual(calls, [['http://a.example/', { pac: 'native', script: 'function F(){}', wpad: true, policy }]]);
  routes.close();
  const none = new Routes({ ...options, pac: 'none' });
  const route = await none.route(snapshot, 'http://a.example/');
  assert.equal(calls.length, 1);
  assert.throws(() => usableSteps(route, () => true), RouteError);
  none.close();
});

// A snapshot whose configuration names a PAC script by URL: with a `script` the engine
// answers a route naming it, without one the route is the URL, as where no engine fetches.
const pacSnapshot = (pacUrl, steps = (script) => [`http://${script}:8080`]) => ({
  route: () => ({ kind: 'pac', engine: 'none', pacUrl }),
  routeAsync: async (_url, options) =>
    options.script === undefined
      ? { kind: 'pac', engine: 'none', pacUrl }
      : { kind: 'steps', engine: 'quickjs', steps: steps(options.script) },
});

// A server that answers each path from `answers` and records what it was asked, closed when
// the test ends.
async function pacServer(t, answers) {
  const asked = [];
  const server = await listen(
    http.createServer((req, res) => {
      asked.push(req.url);
      const answer = answers[req.url];
      if (answer === 'hold') return;
      const [status, body, headers] = answer ?? [404, ''];
      res.writeHead(status, headers).end(body);
    }),
  );
  t.after(() => (server.closeAllConnections(), server.close()));
  return { asked, base: `http://127.0.0.1:${server.address().port}` };
}

const pacRoutes = (t, options = {}) => {
  const routes = new Routes({ env: {}, precedence: 'ignore', watch: false, ...options });
  t.after(() => routes.close());
  return routes;
};

async function pacFile(t, body) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pac-'));
  t.after(() => fs.rm(dir, { recursive: true }));
  const file = path.join(dir, 'proxy.pac');
  await fs.writeFile(file, body);
  return pathToFileURL(file).href;
}

test('a script named by URL is fetched once per generation and run', async (t) => {
  const pac = await pacServer(t, { '/a.pac': [200, 'from-a'] });
  const routes = pacRoutes(t);
  const snapshot = pacSnapshot(`${pac.base}/a.pac`);
  const routed = await Promise.all([1, 2, 3].map(() => routes.route(snapshot, 'http://a.example/')));
  assert.deepEqual(routed.map((route) => route.steps), Array(3).fill(['http://from-a:8080']));
  await routes.route(snapshot, 'http://a.example/');
  assert.deepEqual(pac.asked, ['/a.pac']);
  routes.generation += 1;
  await routes.route(snapshot, 'http://a.example/');
  assert.deepEqual(pac.asked, ['/a.pac', '/a.pac']);
});

test('a script named by a file URL is read', async (t) => {
  const route = await pacRoutes(t).route(pacSnapshot(await pacFile(t, 'from-file')), 'http://a.example/');
  assert.deepEqual(route.steps, ['http://from-file:8080']);
});

test('a redirect is followed, but not to a file URL nor past five', async (t) => {
  const pac = await pacServer(t, {
    '/moved.pac': [302, '', { location: '/a.pac' }],
    '/a.pac': [200, 'from-a'],
    '/to-file.pac': [302, '', { location: await pacFile(t, 'from-file') }],
    '/loop.pac': [302, '', { location: '/loop.pac' }],
  });
  const routes = pacRoutes(t);
  const route = await routes.route(pacSnapshot(`${pac.base}/moved.pac`), 'http://a.example/');
  assert.deepEqual(route.steps, ['http://from-a:8080']);
  for (const name of ['to-file', 'loop']) {
    await assert.rejects(routes.route(pacSnapshot(`${pac.base}/${name}.pac`), 'http://a.example/'), RouteError, name);
  }
  assert.equal(pac.asked.filter((url) => url === '/loop.pac').length, 6);
});

// A script that cannot be fetched fails the request rather than sending it direct, and the
// next request fetches it again.
test('a script that cannot be fetched is a RouteError, tried again by the next request', async (t) => {
  const pac = await pacServer(t, { '/big.pac': [200, 'x'.repeat((1 << 20) + 1)] });
  const routes = pacRoutes(t);
  for (const url of [`${pac.base}/missing.pac`, `${pac.base}/missing.pac`, `${pac.base}/big.pac`, 'ftp://127.0.0.1/a.pac']) {
    await assert.rejects(
      routes.route(pacSnapshot(url), 'http://a.example/'),
      (error) => error instanceof RouteError && error.cause instanceof Error,
      url,
    );
  }
  assert.deepEqual(pac.asked, ['/missing.pac', '/missing.pac', '/big.pac']);
});

// A captive portal can answer the PAC URL with its own page and a 200. That body fails to run
// on every request; it is fetched again once 5 s have passed since it was fetched, so the
// script the server sends once the network is back is used without a change of settings.
test('a fetched script that fails to run is fetched again, at most every 5 s', async (t) => {
  const answers = { '/proxy.pac': [200, '<html>Sign in</html>'] };
  const pac = await pacServer(t, answers);
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const snapshot = pacSnapshot(`${pac.base}/proxy.pac`, (script) => {
    if (script.startsWith('<')) throw Object.assign(new Error('the PAC script failed to load'), { code: 'ERR_PAC_EVALUATION' });
    return [`http://${script}:8080`];
  });
  const routes = pacRoutes(t);
  for (let i = 0; i < 3; i += 1) {
    await assert.rejects(routes.route(snapshot, 'http://a.example/'), { code: 'ERR_PAC_EVALUATION' });
  }
  assert.equal(pac.asked.length, 1);
  answers['/proxy.pac'] = [200, 'from-server'];
  t.mock.timers.tick(4_999);
  await assert.rejects(routes.route(snapshot, 'http://a.example/'), { code: 'ERR_PAC_EVALUATION' });
  assert.equal(pac.asked.length, 1);
  t.mock.timers.tick(1);
  assert.deepEqual((await routes.route(snapshot, 'http://a.example/')).steps, ['http://from-server:8080']);
  assert.equal(pac.asked.length, 2);
  // A script that runs stays until the settings change.
  t.mock.timers.tick(60_000);
  await routes.route(snapshot, 'http://a.example/');
  assert.equal(pac.asked.length, 2);
});

// The script is asked for uncoded; one sent compressed regardless is an error, not a body of
// compressed bytes run as a script.
test('a script is asked for uncoded, and one sent compressed is a RouteError', async (t) => {
  const asked = [];
  const server = await listen(
    http.createServer((req, res) => {
      asked.push(req.headers['accept-encoding']);
      if (req.url === '/plain.pac') return res.end('from-plain');
      res.writeHead(200, { 'content-encoding': req.url === '/gzip.pac' ? 'gzip' : 'Identity ' }).end(zlib.gzipSync('from-gzip'));
    }),
  );
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const routes = pacRoutes(t);
  const plain = await routes.route(pacSnapshot(`${base}/plain.pac`), 'http://a.example/');
  assert.deepEqual(plain.steps, ['http://from-plain:8080']);
  await assert.rejects(routes.route(pacSnapshot(`${base}/gzip.pac`), 'http://a.example/'), (error) => /gzip/.test(error.cause?.message));
  await routes.route(pacSnapshot(`${base}/identity.pac`), 'http://a.example/');
  assert.deepEqual(asked, ['identity', 'identity', 'identity']);
});

// Each byte that is not UTF-8 decodes to U+FFFD, three bytes; the engine refuses a script over
// 1 MiB of UTF-8 with an error that is no RouteError, so the fetch refuses it first.
test('a script that is over the limit once read as UTF-8 is a RouteError', async (t) => {
  const pac = await pacServer(t, { '/latin1.pac': [200, Buffer.alloc(400 * 1024, 0xe9)] });
  await assert.rejects(
    pacRoutes(t).route(pacSnapshot(`${pac.base}/latin1.pac`), 'http://a.example/'),
    (error) => error instanceof RouteError && /UTF-8/.test(error.cause?.message),
  );
});

test('a script of exactly the limit is run', async (t) => {
  const pac = await pacServer(t, { '/full.pac': [200, 'x'.repeat(1 << 20)] });
  const route = await pacRoutes(t).route(pacSnapshot(`${pac.base}/full.pac`, (script) => [`direct-${script.length}`]), 'http://a.example/');
  assert.deepEqual(route.steps, [`direct-${1 << 20}`]);
});

test('a PAC URL password is masked in the RouteError', async (t) => {
  const pac = await pacServer(t, {});
  const url = pac.base.replace('//', '//alice:s3cret@') + '/missing.pac';
  await assert.rejects(
    pacRoutes(t).route(pacSnapshot(url), 'http://a.example/'),
    (error) => error instanceof RouteError && !error.message.includes('s3cret') && error.message.includes('alice'),
  );
});

// `pac: 'native'` asks for the OS's engine alone, and a `script` of the caller's own is run in
// place of the configuration's: neither fetches.
test('pac native and a caller script fetch nothing', async (t) => {
  const pac = await pacServer(t, { '/a.pac': [200, 'from-a'] });
  const snapshot = pacSnapshot(`${pac.base}/a.pac`);
  await pacRoutes(t, { pac: 'native' }).route(snapshot, 'http://a.example/');
  await pacRoutes(t, { script: 'mine' }).route(snapshot, 'http://a.example/');
  assert.deepEqual(pac.asked, []);
});

test('close aborts a fetch in flight', async (t) => {
  const pac = await pacServer(t, { '/a.pac': 'hold' });
  const routes = pacRoutes(t);
  const routed = routes.route(pacSnapshot(`${pac.base}/a.pac`), 'http://a.example/');
  while (pac.asked.length === 0) await new Promise((resolve) => setTimeout(resolve, 10));
  routes.close();
  const outcome = await Promise.race([routed.catch((error) => error), new Promise((resolve) => setTimeout(resolve, 2_000, 'pending'))]);
  assert.ok(outcome instanceof RouteError, String(outcome));
});

// The fetch goes direct, never through the dispatcher a `fetch` would take: one set as the
// global dispatcher would otherwise wait on the script it fetches.
test('fetch under the dispatcher set globally fetches its own script', async (t) => {
  const pac = await pacServer(t, { '/a.pac': [200, 'unused'] });
  const target = await listen(http.createServer((_req, res) => res.end('reached')));
  t.after(() => target.close());
  const snapshot = pacSnapshot(`${pac.base}/a.pac`, () => ['direct']);
  t.mock.method(native, 'watchSync', () => ({ current: () => snapshot, close() {} }));
  const dispatcher = new SystemProxyDispatcher({ env: {}, precedence: 'ignore' });
  const previous = getGlobalDispatcher();
  setGlobalDispatcher(dispatcher);
  t.after(() => (setGlobalDispatcher(previous), dispatcher.close()));
  const response = await fetch(`http://127.0.0.1:${target.address().port}/`, { signal: AbortSignal.timeout(5_000) });
  assert.equal(await response.text(), 'reached');
  assert.deepEqual(pac.asked, ['/a.pac']);
});

// The watcher's report is what moves `generation`: a change replaces the snapshot, and a
// failed re-read keeps the snapshot before it and sets `error` until the next change.
test('a change the watcher reports moves the generation, and a failed one keeps the snapshot', (t) => {
  let report;
  let closed = 0;
  const first = { name: 'first' };
  const second = { name: 'second' };
  t.mock.method(native, 'watchSync', (callback) => {
    report = callback;
    return { current: () => first, close: () => (closed += 1) };
  });
  const routes = new Routes({ env: {}, precedence: 'ignore' });
  assert.deepEqual(routes.current(), { snapshot: first, generation: 0 });
  const failure = new Error('re-read failed');
  report(failure);
  assert.deepEqual(routes.current(), { snapshot: first, generation: 0 });
  assert.equal(routes.error, failure);
  report(null, second);
  assert.deepEqual(routes.current(), { snapshot: second, generation: 1 });
  assert.equal(routes.error, null);
  routes.close();
  assert.equal(closed, 1);
});

// Settings with no PAC in them never run an engine, so they never check the PAC options
// either; Routes checks them as it is made, before it starts watching.
test('Routes refuses bad PAC options under settings with no PAC, before it watches', (t) => {
  const watched = t.mock.method(native, 'watchSync');
  const env = { http_proxy: 'http://proxy.test:8080' };
  for (const options of [{ pac: 'bogus' }, { pac: 'none', script: 'x' }, { pac: 'quickjs', wpad: true }, { policy: { timeoutMs: 0 } }]) {
    assert.throws(
      () => new Routes({ env, precedence: 'before-system', ...options }),
      (error) => error.code === 'ERR_INVALID_ARG_VALUE',
      JSON.stringify(options),
    );
  }
  assert.equal(watched.mock.callCount(), 0);
  const script = 'function FindProxyForURL() { return "DIRECT"; }';
  new Routes({ env, precedence: 'before-system', watch: false, pac: 'quickjs', script, policy: { timeoutMs: 100 } }).close();
});

test('pollIntervalMs reaches the watcher', () => {
  assert.throws(
    () => new Routes({ env: {}, precedence: 'ignore', pollIntervalMs: -1 }),
    (error) => error.code === 'ERR_INVALID_ARG_VALUE',
  );
});

test('fetch: close refuses a later request', async () => {
  const dispatcher = new SystemProxyDispatcher({ env, precedence: 'before-system' });
  await dispatcher.close();
  await assert.rejects(fetch(url('/closed'), { dispatcher }), (error) => {
    assert.equal(error.cause?.code, 'ERR_PROXY_CLOSED');
    return true;
  });
});

test('http.Agent: a ws: upgrade on a direct route stays plain', async () => {
  // Direct last takes a pooled agent; direct in the middle dials its own socket.
  for (const steps of [['direct'], ['http://127.0.0.1:1', 'direct', proxyUrl]]) {
    const agent = systemProxyAgent({ routes: new FixedRoutes({ kind: 'steps', steps }) });
    assert.equal(await upgrade(url('/ws', 'localhost'), agent), 101);
    agent.destroy();
  }
});

test('http.Agent: a ws: upgrade through an HTTP proxy is tunnelled', async () => {
  const agent = systemProxyAgent({ routes: new FixedRoutes({ kind: 'steps', steps: [connectProxyUrl] }) });
  for (const value of ['websocket', 'WebSocket']) {
    for (const array of [false, true]) {
      const before = connectSeen.length;
      assert.equal(await upgrade(url('/ws-proxy'), agent, value, array), 101, `${value}, array ${array}`);
      assert.equal(connectSeen.length, before + 1, `${value}, array ${array}`);
    }
  }
  assert.deepEqual(connectSeen.at(-1), [`origin.test:${port}`, 'Basic dXNlcjpwYXNz']);
  agent.destroy();
});

test('fetch: a ws: upgrade through an HTTP proxy is tunnelled', async () => {
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes({ kind: 'steps', steps: [connectProxyUrl] }) });
  const before = connectSeen.length;
  const { socket } = await undiciUpgrade(url('/ws-fetch'), { dispatcher, protocol: 'websocket' });
  socket.destroy();
  assert.equal(connectSeen.length, before + 1);
  assert.deepEqual(connectSeen.at(-1), [`origin.test:${port}`, 'Basic dXNlcjpwYXNz']);
  await dispatcher.destroy();
});

// Records the URL each route is read for.
class RecordingRoutes extends FixedRoutes {
  urls = [];
  async route(snapshot, target) {
    this.urls.push(target);
    return super.route(snapshot, target);
  }
}

// The route of a WebSocket upgrade is read for `ws:` or `wss:`; any other upgrade is read for
// the scheme it goes by.
test('http.Agent: the route of a WebSocket upgrade is read for ws: or wss:', async () => {
  const routes = new RecordingRoutes({ kind: 'steps', steps: ['direct'] });
  const agent = systemProxyAgent({ routes });
  try {
    assert.equal(await upgrade(url('/ws-scheme', 'localhost'), agent), 101);
    assert.equal(await upgrade(url('/h2c-scheme', 'localhost'), agent, 'h2c'), 101);
    // The TLS origin takes no upgrade and answers it as a request.
    await new Promise((resolve, reject) =>
      https
        .get(`https://localhost:${tlsPort}/wss-scheme`, {
          agent,
          rejectUnauthorized: false,
          headers: { Connection: 'Upgrade', Upgrade: 'websocket' },
        })
        .on('response', (res) => res.resume().on('end', resolve))
        .on('upgrade', (res, socket) => resolve(socket.destroy()))
        .on('error', reject),
    );
  } finally {
    agent.destroy();
  }
  assert.deepEqual(routes.urls, [
    `ws://localhost:${port}/ws-scheme`,
    `http://localhost:${port}/h2c-scheme`,
    `wss://localhost:${tlsPort}/wss-scheme`,
  ]);
});

test('fetch: the route of a WebSocket upgrade is read for ws: or wss:', async () => {
  const routes = new RecordingRoutes({ kind: 'steps', steps: ['direct'] });
  const dispatcher = new SystemProxyDispatcher({ routes, requestTls: { rejectUnauthorized: false } });
  try {
    for (const protocol of ['websocket', 'h2c']) {
      const { socket } = await undiciUpgrade(url(`/${protocol}-fetch-scheme`, 'localhost'), { dispatcher, protocol });
      socket.destroy();
    }
    // The TLS origin takes no upgrade; only the route read for it counts here.
    await undiciUpgrade(`https://localhost:${tlsPort}/wss-fetch-scheme`, { dispatcher, protocol: 'websocket' }).then(
      ({ socket }) => socket.destroy(),
      () => {},
    );
  } finally {
    await dispatcher.destroy();
  }
  assert.deepEqual(routes.urls, [
    `ws://localhost:${port}/websocket-fetch-scheme`,
    `http://localhost:${port}/h2c-fetch-scheme`,
    `wss://localhost:${tlsPort}/wss-fetch-scheme`,
  ]);
});

// The proxy agent, with the options it was given, judges the proxy's certificate. Direct
// would fail on the name `origin.test`.
test('http.Agent: an https proxy before direct carries the request', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: [tlsConnectProxyUrl, 'direct'] }),
    rejectUnauthorized: false,
  });
  const tunnels = connectSeen.length;
  assert.equal(await httpText(tlsUrl('/agent-tls-proxy'), agent, true), 'origin saw /agent-tls-proxy');
  assert.deepEqual(connectSeen.slice(tunnels), [[`origin.test:${tlsPort}`, 'Basic dXNlcjpwYXNz']]);
  agent.destroy();
});

// Direct in the middle of a route dials its own socket, with the request's options.
test('http.Agent: a direct step in the middle of a route keeps the request options', async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: ['http://127.0.0.1:1', 'direct', proxyUrl] }),
  });
  const before = proxySeen.length;
  // Only this lookup knows `origin.test`.
  const lookup = (host, options, callback) =>
    options?.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4);
  const body = await new Promise((resolve, reject) =>
    http
      .get(url('/agent-lookup'), { agent, lookup }, (res) => {
        let text = '';
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => resolve(text));
      })
      .on('error', reject),
  );
  assert.equal(body, 'origin saw /agent-lookup');
  assert.equal(proxySeen.length, before);
  agent.destroy();
});

test('http.Agent: keepAlive reuses the connection to a proxy before the last step', async () => {
  const agent = systemProxyAgent({
    keepAlive: true,
    routes: new FixedRoutes({ kind: 'steps', steps: [proxyUrl, 'direct'] }),
  });
  const before = proxyConnections;
  const seen = proxySeen.length;
  for (const path of ['/keep-1', '/keep-2', '/keep-3']) {
    assert.equal(await httpText(url(path), agent), `origin saw ${path}`);
  }
  assert.equal(proxyConnections - before, 1);
  // A reused connection carries the request as the proxy needs it, credentials included.
  assert.deepEqual(proxySeen.slice(seen), [
    [url('/keep-1'), 'Basic dXNlcjpwYXNz'],
    [url('/keep-2'), 'Basic dXNlcjpwYXNz'],
    [url('/keep-3'), 'Basic dXNlcjpwYXNz'],
  ]);
  agent.destroy();
});

test('http.Agent: keepAlive reuses a CONNECT tunnel and a direct connection', async () => {
  const tunnels = connectSeen.length;
  const tunnelled = systemProxyAgent({
    keepAlive: true,
    routes: new FixedRoutes({ kind: 'steps', steps: [connectProxyUrl, 'direct'] }),
  });
  for (const path of ['/tunnel-1', '/tunnel-2']) {
    assert.equal(await httpText(tlsUrl(path), tunnelled, true), `origin saw ${path}`);
  }
  assert.equal(connectSeen.length - tunnels, 1);
  tunnelled.destroy();

  const before = originConnections;
  const direct = systemProxyAgent({ keepAlive: true, routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
  for (const path of ['/direct-1', '/direct-2']) {
    assert.equal(await httpText(url(path, 'localhost'), direct), `origin saw ${path}`);
  }
  assert.equal(originConnections - before, 1);
  direct.destroy();
});

test('http.Agent: keepAlive: false gives each request a connection of its own', async () => {
  const before = originConnections;
  const agent = systemProxyAgent({
    keepAlive: false,
    routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }),
  });
  for (const path of ['/close-1', '/close-2']) {
    assert.equal(await httpText(url(path, 'localhost'), agent), `origin saw ${path}`);
  }
  assert.equal(originConnections - before, 2);
  agent.destroy();
});

test('http.Agent: connections are pooled unless keepAlive is turned off', async () => {
  const before = originConnections;
  const agent = systemProxyAgent({ routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
  for (const path of ['/default-1', '/default-2']) {
    assert.equal(await httpText(url(path, 'localhost'), agent), `origin saw ${path}`);
  }
  assert.equal(originConnections - before, 1);
  agent.destroy();
});

// The tunnel agent sets the idle timeout itself; no `timeout` option is passed here.
test('http.Agent: an idle CONNECT tunnel closes after 5 s', { timeout: 15_000 }, async () => {
  const agent = systemProxyAgent({
    routes: new FixedRoutes({ kind: 'steps', steps: [connectProxyUrl, 'direct'] }),
  });
  const closed = new Promise((resolve) => connectProxy.once('connection', (socket) => socket.once('close', resolve)));
  const started = Date.now();
  assert.equal(await httpText(tlsUrl('/idle'), agent, true), 'origin saw /idle');
  await closed;
  const waited = Date.now() - started;
  assert.ok(waited >= 4_500 && waited < 10_000, `closed after ${waited} ms`);
  agent.destroy();
});

test('http.Agent: a change of settings opens new connections', async () => {
  const routes = new FixedRoutes({ kind: 'steps', steps: [proxyUrl] });
  const agent = systemProxyAgent({ keepAlive: true, routes });
  const before = proxyConnections;
  assert.equal(await httpText(url('/gen-1'), agent), 'origin saw /gen-1');
  routes.generation += 1;
  assert.equal(await httpText(url('/gen-2'), agent), 'origin saw /gen-2');
  assert.equal(proxyConnections - before, 2);
  agent.destroy();
});

test('http.Agent: a request the proxy received and dropped is not sent to the next step', async () => {
  const agent = systemProxyAgent({
    keepAlive: true,
    routes: new FixedRoutes({ kind: 'steps', steps: [resetProxyUrl, proxyUrl] }),
  });
  const before = proxySeen.length;
  await assert.rejects(
    new Promise((resolve, reject) => {
      const req = http.request(url('/agent-reset'), { agent, method: 'POST' }, resolve);
      req.on('error', reject);
      req.end('x');
    }),
    (error) => error.code === 'ECONNRESET' && error.message === 'socket hang up',
  );
  assert.equal(proxySeen.length, before);
  agent.destroy();
});

test('http.Agent: negotiate names the proxy the step dials, and keeps a 407 on that step', async () => {
  const negotiating = await listen(
    http.createServer().on('connect', (req, socket) => {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n');
    }),
  );
  const host = '127.0.0.1';
  const agent = systemProxyAgent({
    proxyAuth: negotiateAuth(),
    routes: new FixedRoutes({ kind: 'steps', steps: [`http://${host}:${negotiating.address().port}`, connectProxyUrl] }),
  });
  const tunnels = connectSeen.length;
  const spn = process.platform === 'win32' ? `HTTP/${host}` : `HTTP@${host}`;
  try {
    await assert.rejects(httpText(tlsUrl('/negotiate'), agent, true), (error) =>
      error.message.includes(`Negotiate as ${spn}`),
    );
    assert.equal(connectSeen.length, tunnels);
  } finally {
    agent.destroy();
    negotiating.close();
  }
});

test('fetch: negotiate names the proxy the step dials, and keeps a 407 on that step', async () => {
  const negotiating = await listen(
    http.createServer().on('connect', (req, socket) => {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n');
    }),
  );
  const host = '127.0.0.1';
  const dispatcher = new SystemProxyDispatcher({
    proxyAuth: negotiateAuth(),
    routes: new FixedRoutes({ kind: 'steps', steps: [`http://${host}:${negotiating.address().port}`, connectProxyUrl] }),
  });
  const tunnels = connectSeen.length;
  const spn = process.platform === 'win32' ? `HTTP/${host}` : `HTTP@${host}`;
  try {
    await assert.rejects(request(tlsUrl('/negotiate'), { dispatcher }), (error) =>
      error.message.includes(`Negotiate as ${spn}`),
    );
    assert.equal(connectSeen.length, tunnels);
  } finally {
    await dispatcher.destroy();
    negotiating.close();
  }
});

test('http.Agent: maxSockets and maxTotalSockets are refused rather than left to hold requests back', () => {
  const routes = () => new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  for (const name of ['maxSockets', 'maxTotalSockets']) {
    for (const value of [2, 0, Number.NaN]) {
      assert.throws(
        () => systemProxyAgent({ [name]: value, routes: routes() }),
        (error) => error.code === 'ERR_INVALID_ARG_VALUE' && error.message.startsWith(name),
        `${name}: ${value}`,
      );
    }
    // No limit is what the agent has anyway.
    systemProxyAgent({ [name]: Infinity, routes: routes() }).destroy();
  }
});

test('http.Agent: proxyEnv is refused rather than handed to Node agents that would proxy direct steps', () => {
  const routes = () => new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  assert.throws(
    () => systemProxyAgent({ proxyEnv: { HTTP_PROXY: 'http://127.0.0.1:9' }, routes: routes() }),
    (error) => error.code === 'ERR_INVALID_ARG_VALUE' && error.message.startsWith('proxyEnv'),
  );
  // Absent, as Node reads it.
  systemProxyAgent({ proxyEnv: undefined, routes: routes() }).destroy();
});

// Node's agent refuses a bad `scheduling` as it is made, after the watcher has started.
test('http.Agent: an option Node refuses closes the watcher the call started', (t) => {
  let closed = 0;
  t.mock.method(native, 'watchSync', () => ({ current: () => ({}), close: () => (closed += 1) }));
  assert.throws(() => systemProxyAgent({ scheduling: 'bogus' }), (error) => error.code === 'ERR_INVALID_ARG_VALUE');
  assert.equal(closed, 1);
  // A `routes` passed in is its owner's to close.
  const routes = new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  let ownerCloses = 0;
  routes.close = () => (ownerCloses += 1);
  assert.throws(() => systemProxyAgent({ scheduling: 'bogus', routes }), (error) => error.code === 'ERR_INVALID_ARG_VALUE');
  assert.equal(ownerCloses, 0);
});

// `setTimeout` fires at once for a delay it cannot take, which would hand every step but the
// last on before it could answer: `Infinity` meant as "no limit" would go around the proxy.
test('a connectTimeout setTimeout cannot take is refused by both clients', () => {
  const routes = () => new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  for (const connectTimeout of [Infinity, Number.NaN, 0, -1, 2 ** 31, '500']) {
    const refused = (error) => error.code === 'ERR_INVALID_ARG_VALUE' && /connectTimeout/.test(error.message);
    assert.throws(() => systemProxyAgent({ connectTimeout, routes: routes() }), refused, String(connectTimeout));
    assert.throws(() => new SystemProxyDispatcher({ connectTimeout, routes: routes() }), refused, String(connectTimeout));
  }
  systemProxyAgent({ connectTimeout: 2 ** 31 - 1, routes: routes() }).destroy();
  // `null`, from a JavaScript caller, is the default on both, as `undefined` is.
  systemProxyAgent({ connectTimeout: null, routes: routes() }).destroy();
  new SystemProxyDispatcher({ connectTimeout: null, routes: routes() }).destroy();
});

// A `Routes` option beside `routes` would go to the watcher `routes` replaces, and do
// nothing; both clients refuse it, naming it, and leave an option set to `undefined` alone.
test('both clients refuse a Routes option beside routes', async (t) => {
  let started = 0;
  t.mock.method(native, 'watchSync', () => (started += 1, { current: () => ({}), close: () => {} }));
  const routes = new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  for (const [name, value] of [['pac', 'none'], ['watch', false], ['env', {}], ['precedence', 'ignore']]) {
    const refused = (error) => error.code === 'ERR_INVALID_ARG_VALUE' && error.message.startsWith(name);
    assert.throws(() => systemProxyAgent({ routes, [name]: value }), refused, name);
    assert.throws(() => new SystemProxyDispatcher({ routes, [name]: value }), refused, name);
  }
  systemProxyAgent({ routes, pac: undefined }).destroy();
  await new SystemProxyDispatcher({ routes, pac: undefined }).destroy();
  assert.equal(started, 0);
});

// An undici option the dispatcher does not list would reach some steps' agents and not
// others; `socketPath` and `factory` would send a step's connection somewhere else.
test('SystemProxyDispatcher refuses an option it does not list', () => {
  const routes = () => new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  const refused = {
    connect: /requestTls/,
    tls: /requestTls/,
    ca: /requestTls/,
    servername: /requestTls/,
    session: /one destination/,
    headers: /each request/,
    token: /proxyAuth/,
    username: /proxyAuth/,
    socketPath: /socketPath option$/,
    factory: /factory option$/,
    proxyTunnel: /proxyTunnel option$/,
    keepAlive: /keepAlive option$/,
    constructor: /constructor option$/,
    toString: /toString option$/,
  };
  for (const [name, hint] of Object.entries(refused)) {
    assert.throws(
      () => new SystemProxyDispatcher({ routes: routes(), [name]: {} }),
      (error) => error.code === 'ERR_INVALID_ARG_VALUE' && error.message.includes(name) && hint.test(error.message),
      name,
    );
  }
  const tlsRefused = {
    proxyTls: { timeout: /connectTimeout/, path: /proxy/, socketPath: /proxy/, socket: /proxy/ },
    requestTls: { timeout: /connectTimeout/, path: /proxy/, socketPath: /proxy/, socket: /proxy/, session: /one destination/ },
  };
  for (const [option, names] of Object.entries(tlsRefused)) {
    for (const [name, hint] of Object.entries(names)) {
      for (const value of [0, 'x']) {
        assert.throws(
          () => new SystemProxyDispatcher({ routes: routes(), [option]: { [name]: value } }),
          (error) =>
            error.code === 'ERR_INVALID_ARG_VALUE' && error.message.includes(`${option}.${name}`) && hint.test(error.message),
          `${option}.${name}`,
        );
      }
    }
  }
  const listed = {
    proxyAuth: undefined,
    proxyTls: { servername: 'proxy.test', rejectUnauthorized: true, timeout: undefined },
    requestTls: { servername: 'origin.test', minVersion: 'TLSv1.2', session: undefined },
    connectTimeout: 1_000,
    connections: 4,
    pipelining: 1,
    headersTimeout: 1_000,
    bodyTimeout: 1_000,
    keepAliveTimeout: 1_000,
    keepAliveMaxTimeout: 2_000,
    allowH2: false,
    connect: undefined,
  };
  new SystemProxyDispatcher({ routes: routes(), ...listed }).destroy();
});

// `compose()` wraps the dispatcher in a Proxy that hands `close` and `destroy` out unbound.
test('fetch: a composed dispatcher closes and destroys', async () => {
  const routes = () => new FixedRoutes({ kind: 'steps', steps: ['direct'] });
  const passThrough = (dispatch) => (opts, handler) => dispatch(opts, handler);
  const closing = new SystemProxyDispatcher({ routes: routes() }).compose(passThrough);
  const response = await fetch(url('/composed', '127.0.0.1'), { dispatcher: closing });
  assert.equal(await response.text(), 'origin saw /composed');
  await closing.close();
  await new SystemProxyDispatcher({ routes: routes() }).compose(passThrough).destroy();
});

// `requestTls` is the destination's TLS through a proxy; a direct step judges the
// destination's certificate by Node's defaults.
test('fetch: requestTls leaves a direct step to judge the certificate', async () => {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }),
    requestTls: { rejectUnauthorized: false },
  });
  await assert.rejects(fetch(`https://127.0.0.1:${tlsPort}/direct-tls`, { dispatcher }), (error) =>
    /certificate|self.signed/i.test(`${error.cause?.code} ${error.cause?.message}`),
  );
  await dispatcher.close();
});

// A pooled socket's idle timeout (5 s) ends when a request takes it; the agent's `timeout`
// then applies again, as on a socket Node's own agent reuses. The second request goes on the
// first one's connection and times out at the agent's 300 ms, well before the idle timeout.
test("http.Agent: the agent's timeout holds on a reused keep-alive socket", { timeout: 10_000 }, async () => {
  let requests = 0;
  let connections = 0;
  const server = await listen(http.createServer((req, res) => ++requests === 1 && res.end('first')));
  server.on('connection', () => (connections += 1));
  const agent = systemProxyAgent({ timeout: 300, routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
  const get = () =>
    new Promise((resolve) => {
      const req = http.get({ agent, host: '127.0.0.1', port: server.address().port, path: '/' }, (res) => {
        res.resume();
        res.on('end', () => resolve('answered'));
      });
      req.on('timeout', () => {
        req.destroy();
        resolve('timeout');
      });
      req.on('error', () => {});
    });
  try {
    assert.equal(await get(), 'answered');
    const started = Date.now();
    assert.equal(await get(), 'timeout');
    assert.ok(Date.now() - started < 2_000, `timed out after ${Date.now() - started} ms`);
    assert.equal(connections, 1);
  } finally {
    agent.destroy();
    server.closeAllConnections();
    server.close();
  }
});

// The pooled socket's 5 s idle timeout does not outlive the pool: a reused socket carries the
// agent's `timeout`, none when the agent sets none, and a longer one than the idle timeout.
for (const [timeout, expected] of [
  [undefined, 0],
  [300, 300],
  [8_000, 8_000],
]) {
  test(`http.Agent: a reused socket carries the agent's timeout (${timeout ?? 'none'})`, async () => {
    const server = await listen(http.createServer((req, res) => res.end('ok')));
    const agent = systemProxyAgent({ timeout, routes: new FixedRoutes({ kind: 'steps', steps: ['direct'] }) });
    const get = () =>
      new Promise((resolve, reject) =>
        http
          .get({ agent, host: '127.0.0.1', port: server.address().port, path: '/' }, (res) => {
            const socket = res.socket;
            const carried = socket.timeout ?? 0;
            res.resume();
            res.on('end', () => resolve({ socket, carried }));
          })
          .on('error', reject),
      );
    try {
      const first = await get();
      const second = await get();
      assert.equal(second.socket, first.socket);
      assert.equal(second.carried, expected);
    } finally {
      agent.destroy();
      server.closeAllConnections();
      server.close();
    }
  });
}

test('undici: a request the proxy received and dropped is not sent to the next step', async () => {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes({ kind: 'steps', steps: [resetProxyUrl, proxyUrl] }),
  });
  const before = proxySeen.length;
  await assert.rejects(request(url('/post-reset'), { dispatcher, method: 'POST', body: 'x' }), { code: 'UND_ERR_SOCKET' });
  assert.equal(proxySeen.length, before);
  await dispatcher.close();
});

// `array` gives the headers as a list, which Node keeps in the stored header alone.
function upgrade(target, agent, value = 'websocket', array = false) {
  const headers = array ? ['Connection', 'Upgrade', 'Upgrade', value] : { Connection: 'Upgrade', Upgrade: value };
  return new Promise((resolve, reject) => {
    http
      .get(target, { agent, headers })
      .on('upgrade', (res, socket) => {
        socket.destroy();
        resolve(res.statusCode);
      })
      .on('response', (res) => resolve(res.statusCode))
      .on('error', reject);
  });
}

function httpText(target, agent, secure = false) {
  return new Promise((resolve, reject) => {
    (secure ? https : http)
      .get(target, { agent, rejectUnauthorized: false }, (res) => {
        let text = '';
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => resolve(text));
      })
      .on('error', reject);
  });
}
