// Negotiate against a real KDC, through both clients: a proxy that answers CONNECT with
// `407 Negotiate` and accepts the token by its keytab, as `kerberos.initializeServer` does.
// Needs the realm `test/kdc/start-kdc.sh` starts, its environment sourced (which sets
// SYSTEM_PROXY_FETCH_KDC=1), and the `kerberos` package; skipped otherwise.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { request } from 'undici';
import { SystemProxyDispatcher, negotiateAuth } from '../dist/undici.mjs';
import { systemProxyAgent } from '../dist/agent.mjs';
import { selfSigned } from './certs.mjs';

const KERBEROS = 'kerberos';
const skip = process.env.SYSTEM_PROXY_FETCH_KDC === '1' ? false : 'no KDC: run test/kdc/start-kdc.sh and source its env';
const kerberos = skip ? null : await import(KERBEROS).then((loaded) => loaded.default ?? loaded);

// The mechanism a Negotiate token names, by the OID near its start.
const SPNEGO = Buffer.from('06062b0601050502', 'hex');
const KRB5 = Buffer.from('06092a864886f712010202', 'hex');
const mechanismOf = (token) => {
  const head = Buffer.from(token, 'base64').subarray(0, 24);
  return head.includes(SPNEGO) ? 'spnego' : head.includes(KRB5) ? 'krb5' : `unknown ${head.toString('hex')}`;
};

const listen = (server) =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));

let origin;
let proxy;
let target;
let proxyUrl;
const seen = [];

before(async () => {
  if (skip) return;
  origin = await listen(https.createServer(selfSigned('localhost'), (req, res) => res.end(`origin saw ${req.url}`)));
  target = (path) => `https://localhost:${origin.address().port}${path}`;
  proxy = await listen(
    http.createServer().on('connect', async (req, socket) => {
      socket.on('error', () => {});
      const deny = () =>
        socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n');
      const authorization = req.headers['proxy-authorization'];
      if (!authorization?.startsWith('Negotiate ')) {
        seen.push('407');
        return deny();
      }
      const token = authorization.slice('Negotiate '.length);
      try {
        const server = await kerberos.initializeServer('HTTP@proxy.test');
        await server.step(token);
        seen.push(`${mechanismOf(token)} ${server.username}`);
      } catch (error) {
        seen.push(`${mechanismOf(token)} rejected: ${error.message}`);
        return deny();
      }
      const upstream = net.connect(origin.address().port, '127.0.0.1', () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        socket.pipe(upstream);
        upstream.pipe(socket);
      });
      upstream.on('error', () => socket.destroy());
    }),
  );
  proxyUrl = `http://proxy.test:${proxy.address().port}`;
});

after(() => {
  origin?.closeAllConnections();
  origin?.close();
  proxy?.close();
});

// In place of the OS settings: every request goes to the proxy.
const routes = () => ({ resolve: async () => ({ steps: [proxyUrl], generation: 0 }), error: null, close() {} });

async function viaAgent(proxyAuth, path) {
  const agent = systemProxyAgent({ proxyAuth, routes: routes() });
  try {
    return await new Promise((resolve, reject) =>
      https
        .get(target(path), { agent, rejectUnauthorized: false }, (res) => {
          let text = '';
          res.on('data', (chunk) => (text += chunk));
          res.on('end', () => resolve(text));
        })
        .on('error', reject),
    );
  } finally {
    agent.destroy();
  }
}

async function viaFetch(proxyAuth, path) {
  const dispatcher = new SystemProxyDispatcher({ proxyAuth, routes: routes(), requestTls: { rejectUnauthorized: false } });
  try {
    const response = await request(target(path), { dispatcher });
    return await response.body.text();
  } finally {
    await dispatcher.destroy();
  }
}

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  for (const [mechanism, token] of [
    [undefined, 'spnego'],
    ['spnego', 'spnego'],
    ['kerberos', 'krb5'],
  ]) {
    test(`${client}: negotiateAuth(${mechanism ?? ''}) is accepted as alice with a ${token} token`, { skip, timeout: 20_000 }, async () => {
      seen.length = 0;
      const path = `/${client}-${mechanism ?? 'default'}`;
      assert.equal(await via(negotiateAuth(mechanism && { mechanism }), path), `origin saw ${path}`);
      assert.deepEqual(seen, ['407', `${token} alice@TEST.LOCAL`]);
    });
  }
}
