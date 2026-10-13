// The CONNECT tunnel and the `proxyAuth` hook, through both clients.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { request } from 'undici';
import { RouteError, Routes } from '../dist/core.mjs';
import { SystemProxyDispatcher, ProxyTunnelError, basicAuth, negotiateAuth } from '../dist/undici.mjs';
import { systemProxyAgent } from '../dist/agent.mjs';
import { chunkedReader, openTunnel, proxyAddress } from '../dist/tunnel.mjs';
import { restoreRequest, rewriteHeader, saveRequest } from '../dist/request.mjs';
import { createHash, createHmac } from 'node:crypto';
import { once } from 'node:events';
import dns from 'node:dns';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { selfSigned } from './certs.mjs';
import { ntlmAuth } from '../examples/ntlm-proxy-auth.mjs';

const listen = (server) =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));

const servers = [];
const sockets = new Set();
const originSeen = [];
let tlsPort;
let plainPort;
let originCert;

before(async () => {
  const { key, cert } = selfSigned('origin.test');
  originCert = cert;
  const tlsOrigin = await listen(
    https.createServer({ key, cert }, (req, res) => {
      originSeen.push(req.url);
      res.end(`origin saw ${req.url}`);
    }),
  );
  const plainOrigin = await listen(
    http.createServer((req, res) => {
      originSeen.push(req.url);
      res.end(`origin saw ${req.url}`);
    }),
  );
  servers.push(tlsOrigin, plainOrigin);
  tlsPort = tlsOrigin.address().port;
  plainPort = plainOrigin.address().port;
});

after(() => {
  for (const socket of sockets) socket.destroy();
  for (const server of servers) {
    server.closeAllConnections?.();
    server.close();
  }
});

// A proxy that reads each request head itself, so that one connection can carry several
// CONNECTs. `decide(authorization, index)` answers each: `'ok'` opens the tunnel to
// 127.0.0.1, `{ status, challenge, close, chunked, body }` refuses, `chunked` sending `body`
// in chunked framing (or `body` as it is, when it is a string ending in a newline). A
// forwarded `GET` is passed to the plain origin. `seen` holds `[connection, method,
// Proxy-Authorization]` for each request, `targets` the request target and `Host` of each.
// `host` is where it listens.
async function scriptedProxy(decide, { secure = false, host = '127.0.0.1' } = {}) {
  const seen = [];
  const targets = [];
  let connections = 0;
  const accept = (client) => {
    const connection = ++connections;
    let buffer = '';
    sockets.add(client);
    client.on('close', () => sockets.delete(client));
    client.on('error', () => {});
    const onData = (chunk) => {
      buffer += chunk.toString('latin1');
      const end = buffer.indexOf('\r\n\r\n');
      if (end === -1) return;
      const [line, ...lines] = buffer.slice(0, end).split('\r\n');
      buffer = buffer.slice(end + 4);
      const [method, target] = line.split(' ');
      const authorization = lines
        .find((header) => /^proxy-authorization:/i.test(header))
        ?.replace(/^[^:]*:\s*/, '');
      seen.push([connection, method, authorization]);
      const hostHeader = lines.find((header) => /^host:/i.test(header))?.replace(/^[^:]*:\s*/, '');
      targets.push([target, hostHeader]);
      if (method !== 'CONNECT') {
        client.off('data', onData);
        const forwarded = http.get(target.replace('origin.test', '127.0.0.1'), (res) => {
          client.write(`HTTP/1.1 ${res.statusCode} OK\r\nConnection: close\r\n\r\n`);
          res.pipe(client);
        });
        forwarded.on('error', () => client.destroy());
        return;
      }
      const answer = decide(authorization, seen.length - 1);
      if (answer === 'ok') {
        client.off('data', onData);
        const upstream = net.connect(Number(target.split(':').pop()), '127.0.0.1', () => {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.on('error', () => client.destroy());
        return;
      }
      const reason = answer.status === 407 ? 'Proxy Authentication Required' : 'Forbidden';
      const challenge = answer.challenge ? `Proxy-Authenticate: ${answer.challenge}\r\n` : '';
      const body = answer.body ?? 'denied';
      // `proxyConnectionClose` says so in `Proxy-Connection` and keeps the connection open.
      const close = answer.close
        ? 'Connection: close\r\n'
        : answer.proxyConnectionClose
          ? 'Proxy-Connection: close\r\n'
          : '';
      const framed = !answer.chunked
        ? `Content-Length: ${body.length}\r\n\r\n${body}`
        : body.endsWith('\n')
          ? `Transfer-Encoding: chunked\r\n\r\n${body}`
          : `Transfer-Encoding: chunked\r\n\r\n${body.length.toString(16)};ext=1\r\n${body}\r\n0\r\nX-Trailer: t\r\n\r\n`;
      const response = `HTTP/1.1 ${answer.status} ${reason}\r\n${challenge}${close}${framed}`;
      if (answer.close) client.end(response);
      else client.write(response);
    };
    client.on('data', onData);
  };
  // Over TLS, with a certificate no default trust store accepts.
  const credentials = secure ? selfSigned('proxy.test') : null;
  const server = secure ? tls.createServer(credentials, accept) : net.createServer(accept);
  await new Promise((resolve) => server.listen(0, host, resolve));
  servers.push(server);
  const scheme = secure ? 'https' : 'http';
  const authority = host.includes(':') ? `[${host}]` : host;
  return { url: `${scheme}://user:pass@${authority}:${server.address().port}`, seen, targets, cert: credentials?.cert };
}

// `proxyTls` that trusts a `secure` scripted proxy's certificate and nothing else.
const trustProxyOnly = (cert) => ({ ca: cert, checkServerIdentity: () => undefined });

// Whether this machine can listen on IPv6 loopback; some containers cannot.
const ipv6 = await new Promise((resolve) => {
  const probe = net.createServer().on('error', () => resolve(false));
  probe.listen(0, '::1', () => probe.close(() => resolve(true)));
});

// A `proxyAuth` that answers with `answers` in turn and records what it was asked.
function recording(answers, initial) {
  const calls = [];
  const auth = {
    start(proxy, target) {
      calls.push(['start', proxy.hostname, target]);
      let next = 0;
      return {
        ...(initial !== undefined && { initial: async () => initial }),
        async respond(challenges, sameConnection) {
          calls.push([challenges, sameConnection]);
          return answers[next++];
        },
      };
    },
  };
  return { auth, calls };
}

class FixedRoutes extends Routes {
  constructor(steps) {
    super({ env: {}, precedence: 'ignore', watch: false });
    this.fixed = { kind: 'steps', steps };
  }
  async route() {
    return this.fixed;
  }
}

const tlsUrl = (path) => `https://origin.test:${tlsPort}${path}`;

async function viaAgent(steps, options, target, request = { rejectUnauthorized: false }) {
  const agent = systemProxyAgent({ routes: new FixedRoutes(steps), ...options });
  try {
    return await new Promise((resolve, reject) =>
      (target.startsWith('https:') ? https : http)
        .get(target, { agent, ...request }, (res) => {
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

async function viaFetch(steps, options, target) {
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes(steps),
    requestTls: { rejectUnauthorized: false },
    ...options,
  });
  try {
    const response = await request(target, { dispatcher });
    return await response.body.text();
  } finally {
    await dispatcher.destroy();
  }
}

// A client that writes its request into a refused tunnel waits on an answer that never
// comes; the timeout turns that into a failure.
const bounded = (name, fn) => test(name, { timeout: 10_000 }, fn);

const refused = (status) => (error) => {
  assert.ok(error instanceof ProxyTunnelError, `${error?.name}: ${error?.message}`);
  assert.equal(error.code, 'ERR_PROXY_TUNNEL');
  assert.equal(error.statusCode, status);
  return true;
};

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: a proxyAuth session answers 407s on the connection the proxy keeps`, async () => {
    const proxy = await scriptedProxy((authorization, index) =>
      authorization === 'Token second' ? 'ok' : { status: 407, challenge: index === 0 ? 'Token' : 'Token round-2' },
    );
    const { auth, calls } = recording(['Token first', 'Token second']);
    assert.equal(await via([proxy.url], { proxyAuth: auth }, tlsUrl('/rounds')), 'origin saw /rounds');
    assert.deepEqual(proxy.seen, [
      [1, 'CONNECT', 'Basic dXNlcjpwYXNz'],
      [1, 'CONNECT', 'Token first'],
      [1, 'CONNECT', 'Token second'],
    ]);
    assert.deepEqual(calls, [
      ['start', '127.0.0.1', `origin.test:${tlsPort}`],
      [['Token'], true],
      [['Token round-2'], true],
    ]);
  });

  bounded(`${client}: a proxy that closes after its 407 gets the next CONNECT on a new connection`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === 'Token again' ? 'ok' : { status: 407, challenge: 'Token', close: true },
    );
    const { auth, calls } = recording(['Token again']);
    assert.equal(await via([proxy.url], { proxyAuth: auth }, tlsUrl('/closed')), 'origin saw /closed');
    assert.deepEqual(proxy.seen, [
      [1, 'CONNECT', 'Basic dXNlcjpwYXNz'],
      [2, 'CONNECT', 'Token again'],
    ]);
    assert.deepEqual(calls.at(-1), [['Token'], false]);
  });

  bounded(`${client}: a 407 with Proxy-Connection: close gets the next CONNECT on a new connection`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === 'Token again' ? 'ok' : { status: 407, challenge: 'Token', proxyConnectionClose: true },
    );
    const { auth, calls } = recording(['Token again']);
    assert.equal(await via([proxy.url], { proxyAuth: auth }, tlsUrl('/proxy-connection-close')), 'origin saw /proxy-connection-close');
    assert.deepEqual(proxy.seen, [
      [1, 'CONNECT', 'Basic dXNlcjpwYXNz'],
      [2, 'CONNECT', 'Token again'],
    ]);
    assert.deepEqual(calls.at(-1), [['Token'], false]);
  });

  bounded(`${client}: a 407 with a chunked body keeps its connection for the next CONNECT`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === 'Token again' ? 'ok' : { status: 407, challenge: 'Token', chunked: true },
    );
    const { auth, calls } = recording(['Token again']);
    assert.equal(await via([proxy.url], { proxyAuth: auth }, tlsUrl('/chunked')), 'origin saw /chunked');
    assert.deepEqual(proxy.seen, [
      [1, 'CONNECT', 'Basic dXNlcjpwYXNz'],
      [1, 'CONNECT', 'Token again'],
    ]);
    assert.deepEqual(calls.at(-1), [['Token'], true]);
  });

  // Over TLS: a security product that filters HTTP on loopback can strip a chunked body that
  // does not parse, and the client then waits on a body that never comes.
  bounded(`${client}: a 407 whose chunked framing does not parse gets the next CONNECT on a new connection`, async () => {
    const proxy = await scriptedProxy(
      (authorization) =>
        authorization === 'Token again' ? 'ok' : { status: 407, challenge: 'Token', chunked: true, body: 'zz\r\n' },
      { secure: true },
    );
    const { auth, calls } = recording(['Token again']);
    const options = { proxyAuth: auth, proxyTls: trustProxyOnly(proxy.cert) };
    assert.equal(await via([proxy.url], options, tlsUrl('/bad-chunks')), 'origin saw /bad-chunks');
    assert.deepEqual(proxy.seen.map(([connection]) => connection), [1, 2]);
    assert.deepEqual(calls.at(-1), [['Token'], false]);
  });

  bounded(`${client}: a challenge folded onto a second line reaches proxyAuth as one value`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === 'Token again' ? 'ok' : { status: 407, challenge: 'Token\r\n  realm="folded"' },
    );
    const { auth, calls } = recording(['Token again']);
    assert.equal(await via([proxy.url], { proxyAuth: auth }, tlsUrl('/folded')), 'origin saw /folded');
    assert.deepEqual(calls.at(-1), [['Token realm="folded"'], true]);
  });

  bounded(`${client}: a proxy password with a malformed escape is sent as written`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    const url = proxy.url.replace('user:pass@', 'u%zz:p%zz%20x@');
    const plain = `http://origin.test:${plainPort}/bad-escape`;
    assert.equal(await via([url], {}, plain), 'origin saw /bad-escape');
    assert.equal(await via([url], {}, tlsUrl('/bad-escape')), 'origin saw /bad-escape');
    const sent = `Basic ${Buffer.from('u%zz:p%zz x').toString('base64')}`;
    assert.deepEqual(proxy.seen.map(([, method, authorization]) => [method, authorization]), [
      ['GET', sent],
      ['CONNECT', sent],
    ]);
  });

  bounded(`${client}: a session answers at most three 407s, and the request fails with the last`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Token' }));
    const { auth, calls } = recording(['Token 1', 'Token 2', 'Token 3', 'Token 4']);
    await assert.rejects(via([proxy.url], { proxyAuth: auth }, tlsUrl('/endless')), refused(407));
    assert.equal(proxy.seen.length, 4);
    assert.equal(calls.length, 1 + 3);
  });

  // `null`, from a JavaScript caller, gives up as `undefined` does.
  for (const answer of [undefined, null]) {
    bounded(`${client}: a session that answers ${answer} gives up and fails the request with the 407`, async () => {
      const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Unknown' }));
      const { auth } = recording([answer]);
      await assert.rejects(via([proxy.url], { proxyAuth: auth }, tlsUrl('/give-up')), refused(407));
      assert.equal(proxy.seen.length, 1);
    });
  }

  bounded(`${client}: without proxyAuth a 407 fails the request`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Basic realm="x"' }));
    await assert.rejects(via([proxy.url], {}, tlsUrl('/no-auth')), refused(407));
    assert.deepEqual(proxy.seen, [[1, 'CONNECT', 'Basic dXNlcjpwYXNz']]);
  });

  // The proxy's answer is not the destination's: it fails the request rather than reaching
  // the client as a response, and the request is never written to the proxy.
  bounded(`${client}: a refused CONNECT fails the request and stays on its step`, async () => {
    const refusing = await scriptedProxy(() => ({ status: 403 }));
    const next = await scriptedProxy(() => 'ok');
    const seen = originSeen.length;
    await assert.rejects(via([refusing.url, next.url], {}, tlsUrl('/refused')), refused(403));
    assert.equal(refusing.seen.length, 1);
    assert.equal(next.seen.length, 0);
    assert.equal(originSeen.length, seen);
  });

  bounded(`${client}: initial() replaces the proxy URL's credentials on the first CONNECT`, async () => {
    const proxy = await scriptedProxy((authorization) => (authorization === 'Bearer early' ? 'ok' : { status: 407 }));
    const { auth } = recording([], 'Bearer early');
    assert.equal(await via([proxy.url], { proxyAuth: auth }, tlsUrl('/initial')), 'origin saw /initial');
    assert.deepEqual(proxy.seen, [[1, 'CONNECT', 'Bearer early']]);
  });

  bounded(`${client}: an initial() that answers undefined keeps the proxy URL's credentials`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    const auth = { start: () => ({ initial: async () => undefined, respond: async () => undefined }) };
    assert.equal(await via([proxy.url], { proxyAuth: auth }, tlsUrl('/initial-none')), 'origin saw /initial-none');
    assert.deepEqual(proxy.seen, [[1, 'CONNECT', basic('user', 'pass')]]);
  });

  bounded(`${client}: a Proxy-Authorization with a line break is refused before it is written`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Token' }));
    const { auth } = recording(['Token x\r\nX-Injected: 1']);
    await assert.rejects(via([proxy.url], { proxyAuth: auth }, tlsUrl('/inject')), /line break/);
    assert.equal(proxy.seen.length, 1);
  });

  bounded(`${client}: proxyAuth is not started for a forwarded http: request or a direct step`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    const { auth, calls } = recording([]);
    const plain = `http://origin.test:${plainPort}/forwarded`;
    assert.equal(await via([proxy.url], { proxyAuth: auth }, plain), 'origin saw /forwarded');
    assert.deepEqual(proxy.seen, [[1, 'GET', 'Basic dXNlcjpwYXNz']]);
    const direct = `http://127.0.0.1:${plainPort}/direct`;
    assert.equal(await via(['direct'], { proxyAuth: auth }, direct), 'origin saw /direct');
    assert.deepEqual(calls, []);
  });
}

// A Digest (RFC 7616) session for the tests: MD5, `qop=auth`. CONNECT's `uri` is its
// target, which `start` hands the session.
const md5 = (text) => createHash('md5').update(text).digest('hex');
const DIGEST = { realm: 'proxy', nonce: 'b2f4a6c8', user: 'alice', password: 'secret' };

function digestAuth() {
  return {
    start(proxy, target) {
      return {
        async respond(challenges) {
          const challenge = challenges.find((value) => /^Digest\s/i.test(value));
          if (!challenge) return undefined;
          const field = (name) => new RegExp(`${name}="([^"]*)"`).exec(challenge)?.[1];
          const [realm, nonce, cnonce, nc] = [field('realm'), field('nonce'), 'c0ffee', '00000001'];
          const ha1 = md5(`${DIGEST.user}:${realm}:${DIGEST.password}`);
          const response = md5(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${md5(`CONNECT:${target}`)}`);
          return `Digest username="${DIGEST.user}", realm="${realm}", nonce="${nonce}", uri="${target}", qop=auth, nc=${nc}, cnonce="${cnonce}", response="${response}"`;
        },
      };
    },
  };
}

// The check a proxy makes of a Digest answer to CONNECT `target`.
function digestValid(authorization, target) {
  const field = (name) => new RegExp(`${name}="?([^",]*)"?`).exec(authorization ?? '')?.[1];
  if (!/^Digest\s/i.test(authorization ?? '') || field('uri') !== target) return false;
  const ha1 = md5(`${DIGEST.user}:${DIGEST.realm}:${DIGEST.password}`);
  const expected = md5(`${ha1}:${DIGEST.nonce}:${field('nc')}:${field('cnonce')}:auth:${md5(`CONNECT:${target}`)}`);
  return field('response') === expected;
}

// The proxy's URL with only a user name, as the macOS settings give it when the password is
// in the keychain.
const userOnly = (url) => url.replace('user:pass@', 'alice@');

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: a Digest session answers the 407 to CONNECT with the target it was given`, async () => {
    const target = `origin.test:${tlsPort}`;
    const proxy = await scriptedProxy((authorization) =>
      digestValid(authorization, target)
        ? 'ok'
        : { status: 407, challenge: `Digest realm="${DIGEST.realm}", nonce="${DIGEST.nonce}", qop="auth"` },
    );
    assert.equal(await via([proxy.url], { proxyAuth: digestAuth() }, tlsUrl('/digest')), 'origin saw /digest');
    assert.equal(proxy.seen.length, 2);
  });

  // A `Basic` with an empty password on every request would be a failed login each time.
  bounded(`${client}: a proxy URL with a user name and no password sends no Basic on CONNECT`, async () => {
    const proxy = await scriptedProxy((authorization, index) => (index === 0 ? { status: 407, challenge: 'Basic' } : 'ok'));
    // The session still sees the user name, to look the password up by.
    const users = [];
    const keychain = {
      start(proxy) {
        users.push(proxy.username);
        return { respond: async () => `Basic from-the-keychain-for-${proxy.username}` };
      },
    };
    assert.equal(await via([userOnly(proxy.url)], { proxyAuth: keychain }, tlsUrl('/user-only')), 'origin saw /user-only');
    assert.deepEqual(proxy.seen, [
      [1, 'CONNECT', undefined],
      [1, 'CONNECT', 'Basic from-the-keychain-for-alice'],
    ]);
    assert.deepEqual(users, ['alice']);
  });

  bounded(`${client}: a proxy URL with a user name and no password sends no Basic when forwarding`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    const plain = `http://origin.test:${plainPort}/forward-user-only`;
    assert.equal(await via([userOnly(proxy.url)], {}, plain), 'origin saw /forward-user-only');
    assert.deepEqual(proxy.seen, [[1, 'GET', undefined]]);
  });
}

// Settings that keep the proxy's password in the macOS keychain, as `passwordState` reports.
class KeychainRoutes extends FixedRoutes {
  passwordState(step) {
    return new URL(step).username ? 'InKeychain' : null;
  }
}

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: proxyAuth learns that the password is in the keychain`, async () => {
    const proxy = await scriptedProxy((authorization) => (authorization ? 'ok' : { status: 407, challenge: 'Basic' }));
    const url = userOnly(proxy.url);
    const contexts = [];
    const keychain = {
      start(proxy, target, context) {
        contexts.push(context);
        return { respond: async () => (context.passwordState === 'InKeychain' ? 'Basic looked-up' : undefined) };
      },
    };
    const routes = new KeychainRoutes([url]);
    assert.equal(await via([url], { routes, proxyAuth: keychain }, tlsUrl('/keychain')), 'origin saw /keychain');
    assert.deepEqual(contexts, [{ passwordState: 'InKeychain' }]);
  });

  bounded(`${client}: a 407 left unanswered says the password is in the keychain`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Basic' }));
    const url = userOnly(proxy.url);
    await assert.rejects(via([url], { routes: new KeychainRoutes([url]) }, tlsUrl('/keychain-407')), (error) => {
      refused(407)(error);
      assert.equal(error.passwordState, 'InKeychain');
      assert.match(error.message, /keychain.*; answer with proxyAuth$/);
      return true;
    });
    // With a proxyAuth there that gave up, the message does not send the caller to one.
    const proxyAuth = basicAuth(() => undefined);
    await assert.rejects(via([url], { routes: new KeychainRoutes([url]), proxyAuth }, tlsUrl('/keychain-407')), (error) => {
      refused(407)(error);
      assert.match(error.message, /keychain, which is not read$/);
      return true;
    });
  });
}

// basicAuth: the lookup runs only on a 407 Basic, once per tunnel.
const basic = (user, password) => `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: basicAuth asks for the keychain's password only when the proxy asks`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === basic('alice', 'secret') ? 'ok' : { status: 407, challenge: 'Basic realm="corp \\"proxy\\""' },
    );
    const url = userOnly(proxy.url);
    const asked = [];
    const proxyAuth = basicAuth((request) => {
      asked.push({ ...request, proxy: request.proxy.host });
      return request.passwordState === 'InKeychain' ? 'secret' : undefined;
    });
    const routes = new KeychainRoutes([url]);
    assert.equal(await via([url], { routes, proxyAuth }, tlsUrl('/basic')), 'origin saw /basic');
    assert.deepEqual(proxy.seen, [
      [1, 'CONNECT', undefined],
      [1, 'CONNECT', basic('alice', 'secret')],
    ]);
    assert.deepEqual(asked, [
      {
        proxy: new URL(url).host,
        target: `origin.test:${tlsPort}`,
        username: 'alice',
        passwordState: 'InKeychain',
        realm: 'corp "proxy"',
      },
    ]);
  });

  bounded(`${client}: basicAuth takes a user name and password for a proxy URL with no user`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === basic('bob', 'pw') ? 'ok' : { status: 407, challenge: 'Basic' },
    );
    const url = proxy.url.replace('user:pass@', '');
    const proxyAuth = basicAuth(({ username }) => (username === null ? { username: 'bob', password: 'pw' } : undefined));
    assert.equal(await via([url], { proxyAuth }, tlsUrl('/basic-user')), 'origin saw /basic-user');
  });

  // Sending refused credentials again would be another failed login for the directory.
  bounded(`${client}: basicAuth does not answer a 407 that follows its answer`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Basic' }));
    let asked = 0;
    const proxyAuth = basicAuth(() => {
      asked += 1;
      return 'wrong';
    });
    await assert.rejects(via([userOnly(proxy.url)], { proxyAuth }, tlsUrl('/basic-wrong')), refused(407));
    assert.equal(asked, 1);
    assert.equal(proxy.seen.length, 2);
  });

  bounded(`${client}: a basicAuth lookup that finds nothing fails with the state of the password`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Basic' }));
    const url = userOnly(proxy.url);
    const proxyAuth = basicAuth(() => undefined);
    await assert.rejects(via([url], { routes: new KeychainRoutes([url]), proxyAuth }, tlsUrl('/basic-none')), (error) => {
      refused(407)(error);
      assert.match(error.message, /keychain/);
      return true;
    });
    assert.equal(proxy.seen.length, 1);
  });

  bounded(`${client}: basicAuth is not asked for a scheme other than Basic`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Negotiate' }));
    let asked = 0;
    const proxyAuth = basicAuth(() => {
      asked += 1;
      return 'secret';
    });
    await assert.rejects(via([userOnly(proxy.url)], { proxyAuth }, tlsUrl('/basic-negotiate')), refused(407));
    assert.equal(asked, 0);
  });

  bounded(`${client}: basicAuth refuses a user name Basic cannot carry`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Basic' }));
    const proxyAuth = basicAuth(() => ({ username: 'a:b', password: 'pw' }));
    await assert.rejects(via([proxy.url], { proxyAuth }, tlsUrl('/basic-colon')), /cannot contain ":"/);
    assert.equal(proxy.seen.length, 1);
  });
}

// The agent judges the proxy's certificate by its own TLS options, the dispatcher by
// `proxyTls`. A certificate the client rejects keeps the request on its step.
for (const [client, via, trust] of [
  ['http.Agent', viaAgent, { rejectUnauthorized: false }],
  ['fetch', viaFetch, { proxyTls: { rejectUnauthorized: false } }],
]) {
  bounded(`${client}: an https: proxy carries the tunnel when its certificate is accepted`, async () => {
    const proxy = await scriptedProxy(() => 'ok', { secure: true });
    assert.equal(await via([proxy.url], trust, tlsUrl('/tls-proxy')), 'origin saw /tls-proxy');
    assert.deepEqual(proxy.seen, [[1, 'CONNECT', 'Basic dXNlcjpwYXNz']]);
  });

  bounded(`${client}: an https: proxy whose certificate is rejected keeps the request on its step`, async () => {
    const proxy = await scriptedProxy(() => 'ok', { secure: true });
    const next = await scriptedProxy(() => 'ok');
    // The agent's TLS options override the request's, which trust any destination; the
    // proxy's certificate is judged, and fails, before the destination's.
    const options = client === 'fetch' ? {} : { rejectUnauthorized: true };
    await assert.rejects(via([proxy.url, next.url], options, tlsUrl('/tls-rejected')), (error) =>
      /self[- ]signed/i.test(`${error.code} ${error.message}`),
    );
    assert.equal(proxy.seen.length, 0);
    assert.equal(next.seen.length, 0);
  });
}

// The NTLM example in `examples/`, against a proxy that issues its own Type 2 and checks
// the NTLMv2 proof in the Type 3. User `User`, domain `Domain` (sent upper-cased), password
// `Password`.
const NT_HASH = Buffer.from('a4f49c406510bdcab6824ee7c30fd852', 'hex'); // MD4 of UTF-16LE `Password`
const SERVER_CHALLENGE = Buffer.from('0123456789abcdef', 'hex');

function ntlmType2({ extendedSecurity = true, targetInfo = true } = {}) {
  const name = Buffer.from('DOMAIN', 'utf16le');
  const pair = Buffer.alloc(4);
  pair.writeUInt16LE(2, 0); // MsvAvNbDomainName
  pair.writeUInt16LE(name.length, 2);
  const info = targetInfo ? Buffer.concat([pair, name, Buffer.alloc(4)]) : Buffer.alloc(0);
  const flags = 0x1 | 0x200 | (extendedSecurity ? 0x80000 : 0) | (targetInfo ? 0x800000 : 0);
  const head = Buffer.alloc(48);
  head.write('NTLMSSP\0', 0, 'latin1');
  head.writeUInt32LE(2, 8);
  head.writeUInt16LE(name.length, 12);
  head.writeUInt16LE(name.length, 14);
  head.writeUInt32LE(48, 16);
  head.writeUInt32LE(flags, 20);
  SERVER_CHALLENGE.copy(head, 24);
  head.writeUInt16LE(info.length, 40);
  head.writeUInt16LE(info.length, 42);
  head.writeUInt32LE(48 + name.length, 44);
  return `NTLM ${Buffer.concat([head, name, info]).toString('base64')}`;
}

// The NTLMv2 check a server makes: NTProofStr = HMAC-MD5(NTOWFv2, challenge ‖ blob).
function ntlmType3Valid(authorization) {
  const message = Buffer.from(authorization.replace(/^NTLM\s+/i, ''), 'base64');
  if (message.readUInt32LE(8) !== 3) return false;
  const field = (at) => message.subarray(message.readUInt32LE(at + 4), message.readUInt32LE(at + 4) + message.readUInt16LE(at));
  const response = field(20);
  if (response.length <= 24) return false; // NTLMv1
  const key = createHmac('md5', NT_HASH).update(Buffer.from('USERDOMAIN', 'utf16le')).digest();
  const proof = createHmac('md5', key).update(Buffer.concat([SERVER_CHALLENGE, response.subarray(16)])).digest();
  return proof.equals(response.subarray(0, 16)) && field(36).toString('utf16le') === 'User';
}

const isType = (authorization, type) =>
  /^NTLM\s+\S/i.test(authorization ?? '') &&
  Buffer.from(authorization.replace(/^NTLM\s+/i, ''), 'base64').readUInt32LE(8) === type;

const ntlm = () => ntlmAuth({ username: 'User', password: 'Password', domain: 'Domain' });

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: the NTLM example sends its three messages on one connection`, async () => {
    const proxy = await scriptedProxy((authorization) => {
      if (isType(authorization, 1)) return { status: 407, challenge: ntlmType2() };
      if (isType(authorization, 3)) return ntlmType3Valid(authorization) ? 'ok' : { status: 407, challenge: 'NTLM' };
      return { status: 407, challenge: 'NTLM' };
    });
    assert.equal(await via([proxy.url], { proxyAuth: ntlm() }, tlsUrl('/ntlm')), 'origin saw /ntlm');
    assert.deepEqual(
      proxy.seen.map(([connection, , authorization]) => [connection, authorization.split(' ')[0]]),
      [
        [1, 'Basic'],
        [1, 'NTLM'],
        [1, 'NTLM'],
      ],
    );
  });
}

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  for (const [what, type2] of [
    ['without extended session security', ntlmType2({ extendedSecurity: false })],
    ['without target information', ntlmType2({ targetInfo: false })],
  ]) {
    bounded(`${client}: the NTLM example sends no Type 3 to a Type 2 ${what}`, async () => {
      const proxy = await scriptedProxy((authorization) =>
        isType(authorization, 1) ? { status: 407, challenge: type2 } : { status: 407, challenge: 'NTLM' },
      );
      await assert.rejects(via([proxy.url], { proxyAuth: ntlm() }, tlsUrl('/ntlm-v1')), refused(407));
      assert.ok(proxy.seen.every(([, , authorization]) => !isType(authorization, 3)));
    });
  }

  bounded(`${client}: the NTLM example gives up when the proxy closes the connection after its Type 2`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      isType(authorization, 1) ? { status: 407, challenge: ntlmType2(), close: true } : { status: 407, challenge: 'NTLM' },
    );
    await assert.rejects(via([proxy.url], { proxyAuth: ntlm() }, tlsUrl('/ntlm-closed')), refused(407));
    assert.ok(proxy.seen.every(([, , authorization]) => !isType(authorization, 3)));
  });
}

// negotiateAuth with a `kerberos` that plays NTLM inside SPNEGO: the first step gives
// `first`, the proxy's `challenge-2` gives `last` and completes the context.
function fakeKerberos() {
  const made = [];
  const kerberos = {
    GSS_MECH_OID_KRB5: 9,
    GSS_MECH_OID_SPNEGO: 6,
    async initializeClient(service, { mechOID }) {
      const client = {
        steps: [],
        contextComplete: false,
        async step(token) {
          client.steps.push(token);
          if (token === '') return 'first';
          if (token === 'challenge-2') {
            client.contextComplete = true;
            return 'last';
          }
          throw new Error(`unexpected token ${token}`);
        },
      };
      made.push({ service, mechOID, client });
      return client;
    },
  };
  return { kerberos, made };
}

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: negotiateAuth continues one context across 407s on the same connection`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === 'Negotiate last'
        ? 'ok'
        : { status: 407, challenge: authorization === 'Negotiate first' ? 'Negotiate challenge-2' : 'Negotiate' },
    );
    const { kerberos, made } = fakeKerberos();
    const url = proxy.url.replace('user:pass@', '');
    assert.equal(await via([url], { proxyAuth: negotiateAuth({ kerberos }) }, tlsUrl('/spnego-ntlm')), 'origin saw /spnego-ntlm');
    assert.deepEqual(proxy.seen, [
      [1, 'CONNECT', undefined],
      [1, 'CONNECT', 'Negotiate first'],
      [1, 'CONNECT', 'Negotiate last'],
    ]);
    assert.equal(made.length, 1);
    assert.deepEqual(made[0].client.steps, ['', 'challenge-2']);
    const spn = process.platform === 'win32' ? 'HTTP/127.0.0.1' : 'HTTP@127.0.0.1';
    assert.equal(made[0].service, spn);
    assert.equal(made[0].mechOID, 6);
  });

  // The context belongs to the connection the proxy closed.
  bounded(`${client}: negotiateAuth does not continue a context on a new connection`, async () => {
    const proxy = await scriptedProxy((authorization) =>
      authorization === 'Negotiate first'
        ? { status: 407, challenge: 'Negotiate challenge-2', close: true }
        : { status: 407, challenge: 'Negotiate' },
    );
    const { kerberos, made } = fakeKerberos();
    const url = proxy.url.replace('user:pass@', '');
    await assert.rejects(via([url], { proxyAuth: negotiateAuth({ kerberos }) }, tlsUrl('/spnego-closed')), refused(407));
    assert.deepEqual(made[0].client.steps, ['']);
    assert.equal(proxy.seen.length, 2);
  });

  // A bare Negotiate after a token is the proxy refusing it.
  bounded(`${client}: negotiateAuth does not start over after the proxy refuses its token`, async () => {
    const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Negotiate' }));
    const { kerberos, made } = fakeKerberos();
    const url = proxy.url.replace('user:pass@', '');
    await assert.rejects(via([url], { proxyAuth: negotiateAuth({ kerberos, mechanism: 'kerberos' }) }, tlsUrl('/spnego-refused')), refused(407));
    assert.equal(made.length, 1);
    assert.equal(made[0].mechOID, 9);
    assert.equal(proxy.seen.length, 2);
  });
}

// The agent's `proxyTls` judges the proxy alone. The destination's certificate is judged by
// the request, which trusts any here.
// The destination is checked against its own certificate alone: the proxy's, trusted
// through `proxyTls`, fails it.
bounded('http.Agent: proxyTls trusts the proxy without touching the destination', async () => {
  const proxy = await scriptedProxy(() => 'ok', { secure: true });
  const options = { proxyTls: trustProxyOnly(proxy.cert) };
  assert.equal(await viaAgent([proxy.url], options, tlsUrl('/proxy-tls'), { ca: originCert }), 'origin saw /proxy-tls');
  assert.equal(proxy.seen.length, 1);
  await assert.rejects(viaAgent([proxy.url], options, tlsUrl('/proxy-tls-untrusted'), {}), (error) =>
    /self[- ]signed/i.test(`${error.code} ${error.message}`),
  );
});

// An `https:` proxy's certificate is checked against the proxy's address too, on both
// clients: one the CA trusts but issued for another name fails its step, and the request
// goes no further.
for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: an https proxy's certificate must name the proxy`, async () => {
    const proxy = await scriptedProxy(() => 'ok', { secure: true });
    const next = await scriptedProxy(() => 'ok');
    await assert.rejects(via([proxy.url, next.url], { proxyTls: { ca: proxy.cert } }, tlsUrl('/proxy-name')), (error) =>
      /ERR_TLS_CERT_ALTNAME_INVALID/.test(`${error.code} ${error.cause?.code}`),
    );
    assert.deepEqual(proxy.seen, []);
    assert.deepEqual(next.seen, []);
  });
}

// A proxy that opens every CONNECT and goes nowhere, and says when a connection closes.
async function acceptingProxy() {
  let connections = 0;
  let close;
  const closed = new Promise((resolve) => (close = resolve));
  const server = net.createServer((socket) => {
    connections += 1;
    sockets.add(socket);
    socket.once('data', () => socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'));
    socket.on('close', close);
  });
  await listen(server);
  servers.push(server);
  return { url: `http://127.0.0.1:${server.address().port}`, closed, connections: () => connections };
}

bounded('http.Agent: TLS options that tls.connect refuses fail the request and close the tunnel', async () => {
  const proxy = await acceptingProxy();
  await assert.rejects(viaAgent([proxy.url], {}, tlsUrl('/bad-tls'), { minVersion: 'foo' }), {
    code: 'ERR_TLS_INVALID_PROTOCOL_VERSION',
  });
  await proxy.closed;
});

bounded('fetch: requestTls that tls.connect refuses fails the request and closes the tunnel', async () => {
  const proxy = await acceptingProxy();
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes([proxy.url]), requestTls: { minVersion: 'foo' } });
  try {
    await assert.rejects(request(tlsUrl('/bad-tls'), { dispatcher }), { code: 'ERR_TLS_INVALID_PROTOCOL_VERSION' });
    await proxy.closed;
  } finally {
    await dispatcher.destroy();
  }
});

// `setHost: false` skips Node's own check of the host, which would otherwise reach the
// CONNECT line or a forwarded request's target as written.
bounded('http.Agent: a host with a line break in it is refused before any proxy', async () => {
  const proxy = await acceptingProxy();
  const agent = systemProxyAgent({ routes: new FixedRoutes([proxy.url]) });
  try {
    for (const [client, port] of [
      [http, plainPort],
      [https, tlsPort],
    ]) {
      const options = { agent, host: 'origin.test\r\nX-Injected: 1', port, path: '/', setHost: false };
      await assert.rejects(
        new Promise((resolve, reject) => client.get(options, resolve).on('error', reject)),
        { code: 'ERR_INVALID_CHAR' },
      );
    }
    assert.equal(proxy.connections(), 0);
  } finally {
    agent.destroy();
  }
});

// The route reads the host out of a URL; a host that URL would cut short (`#`, `?`, `/`, `\`,
// `@`, `:`) or decode (`%`) is routed as one host and connected to as another, so it is
// refused, with an empty part as well as a full one.
bounded('http.Agent: a host a URL would read as another is refused before any proxy', async () => {
  const proxy = await acceptingProxy();
  const routes = new RecordingRoutes([proxy.url]);
  const agent = systemProxyAgent({ routes });
  try {
    for (const host of [
      'internal.corp#@origin.test',
      'origin.test?@x',
      'origin.test/x',
      'origin.test\\@x',
      'u@origin.test',
      ':p@origin.test',
      'origin.test:81',
      'origin.test:80',
      'origin.test#',
      'origin.test?',
      'origin.test/',
      '@origin.test',
      'a%41b.test',
      'ex[ample.test',
      'ex<ample.test',
    ]) {
      for (const [client, port] of [
        [http, plainPort],
        [https, tlsPort],
      ]) {
        await assert.rejects(
          new Promise((resolve, reject) => client.get({ agent, host, port, path: '/', setHost: false }, resolve).on('error', reject)),
          { code: 'ERR_INVALID_ARG_VALUE' },
          host,
        );
      }
    }
    assert.deepEqual(routes.urls, []);
    assert.equal(proxy.connections(), 0);
  } finally {
    agent.destroy();
  }
});

bounded('http.Agent: proxyTls wins over the agent options for the proxy', async () => {
  const proxy = await scriptedProxy(() => 'ok', { secure: true });
  const options = { rejectUnauthorized: false, proxyTls: { rejectUnauthorized: true } };
  await assert.rejects(viaAgent([proxy.url], options, tlsUrl('/proxy-tls-strict')), (error) =>
    /self[- ]signed/i.test(`${error.code} ${error.message}`),
  );
  assert.equal(proxy.seen.length, 0);
});

bounded('http.Agent: proxyTls reaches the proxy of a forwarded http: request', async () => {
  const proxy = await scriptedProxy(() => 'ok', { secure: true });
  const plain = `http://origin.test:${plainPort}/proxy-tls-forward`;
  assert.equal(await viaAgent([proxy.url], { proxyTls: trustProxyOnly(proxy.cert) }, plain), 'origin saw /proxy-tls-forward');
  assert.deepEqual(proxy.seen, [[1, 'GET', 'Basic dXNlcjpwYXNz']]);
});

bounded('fetch: proxyTls reaches the proxy of a forwarded http: request', async () => {
  const proxy = await scriptedProxy(() => 'ok', { secure: true });
  const plain = `http://origin.test:${plainPort}/proxy-tls-forward-fetch`;
  assert.equal(await viaFetch([proxy.url], { proxyTls: trustProxyOnly(proxy.cert) }, plain), 'origin saw /proxy-tls-forward-fetch');
  assert.deepEqual(proxy.seen, [[1, 'GET', 'Basic dXNlcjpwYXNz']]);
});

// A forwarding step's connection is held to connectTimeout, its TLS handshake with an
// `https:` proxy included; nothing of the request has left by then.
bounded('fetch: a forwarding step whose https: proxy never answers the handshake hands the request on', async () => {
  const silent = await silentProxy();
  const next = await scriptedProxy(() => 'ok');
  const steps = [`https://127.0.0.1:${silent.port}`, next.url];
  const plain = `http://origin.test:${plainPort}/silent-tls-fetch`;
  assert.equal(await viaFetch(steps, { connectTimeout: 200 }, plain), 'origin saw /silent-tls-fetch');
  assert.deepEqual(next.seen, [[1, 'GET', 'Basic dXNlcjpwYXNz']]);
});

// The agent's destination is the request's host and port. A `Host` header naming another
// host, or none at all (`setHost: false`), changes neither the route nor where a forwarding
// proxy sends the request; the header itself goes as the request set it.
class RecordingRoutes extends FixedRoutes {
  urls = [];
  async route(snapshot, url) {
    this.urls.push(url);
    return super.route(snapshot, url);
  }
}

for (const [name, headers] of [
  ['a Host header naming another host', { host: 'elsewhere.test' }],
  ['no Host header (setHost: false)', null],
]) {
  bounded(`http.Agent: ${name} leaves the route and the forwarded target on the request's host`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    const routes = new RecordingRoutes([proxy.url]);
    const agent = systemProxyAgent({ routes });
    try {
      const options = { agent, host: '127.0.0.1', port: plainPort, path: '/by-host', ...(headers ? { headers } : { setHost: false }) };
      const text = await new Promise((resolve, reject) =>
        http
          .get(options, (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => resolve(body));
          })
          .on('error', reject),
      );
      assert.equal(text, 'origin saw /by-host');
    } finally {
      agent.destroy();
    }
    const target = `http://127.0.0.1:${plainPort}/by-host`;
    assert.deepEqual(routes.urls, [target]);
    assert.deepEqual(proxy.targets, [[target, headers?.host]]);
  });
}

// A request path is joined to the destination as written. Read as a URL reference, `//x/y`
// would name host `x`, and dot-segments and backslashes would be rewritten.
for (const path of ['//other.example/x', '/a/../b', '/\\other.example/y', '/q{1}']) {
  bounded(`http.Agent: the path ${JSON.stringify(path)} is routed and forwarded on the request's host as written`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    const routes = new RecordingRoutes([proxy.url]);
    const agent = systemProxyAgent({ routes });
    try {
      await new Promise((resolve, reject) =>
        http.get({ agent, host: '127.0.0.1', port: plainPort, path }, (res) => res.resume().on('end', resolve)).on('error', reject),
      );
    } finally {
      agent.destroy();
    }
    const target = `http://127.0.0.1:${plainPort}${path}`;
    assert.deepEqual(routes.urls, [target]);
    assert.deepEqual(proxy.targets, [[target, `127.0.0.1:${plainPort}`]]);
  });
}

bounded('http.Agent: OPTIONS * is routed and forwarded to the origin itself', async () => {
  const proxy = await scriptedProxy(() => 'ok');
  const routes = new RecordingRoutes([proxy.url]);
  const agent = systemProxyAgent({ routes });
  try {
    await new Promise((resolve, reject) =>
      http
        .request({ agent, host: '127.0.0.1', port: plainPort, path: '*', method: 'OPTIONS' }, (res) => res.resume().on('end', resolve))
        .on('error', reject)
        .end(),
    );
  } finally {
    agent.destroy();
  }
  const origin = `http://127.0.0.1:${plainPort}`;
  assert.deepEqual(routes.urls, [origin]);
  assert.deepEqual(proxy.targets, [[origin, `127.0.0.1:${plainPort}`]]);
});

bounded('fetch: a path that starts with // is routed on the request\'s host', async () => {
  const routes = new RecordingRoutes(['direct']);
  const dispatcher = new SystemProxyDispatcher({ routes });
  try {
    const response = await request(`http://127.0.0.1:${plainPort}//other.example/x`, { dispatcher });
    assert.equal(await response.body.text(), 'origin saw //other.example/x');
  } finally {
    await dispatcher.destroy();
  }
  assert.deepEqual(routes.urls, [`http://127.0.0.1:${plainPort}//other.example/x`]);
});

// IPv6: a destination given by an IPv6 address goes in brackets in CONNECT and `Host`; the
// proxy, not this machine, connects to it, so it needs no IPv6 here.
for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: an IPv6 destination is bracketed in CONNECT`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    assert.equal(await via([proxy.url], {}, `https://[::1]:${tlsPort}/v6-target`), 'origin saw /v6-target');
    assert.deepEqual(proxy.targets, [[`[::1]:${tlsPort}`, `[::1]:${tlsPort}`]]);
  });

  test(`${client}: a proxy at an IPv6 address carries the tunnel`, { skip: !ipv6 && 'no IPv6 loopback here', timeout: 10_000 }, async () => {
    const proxy = await scriptedProxy(() => 'ok', { host: '::1' });
    assert.match(proxy.url, /@\[::1\]:\d+$/);
    assert.equal(await via([proxy.url], {}, tlsUrl('/v6-proxy')), 'origin saw /v6-proxy');
    assert.deepEqual(proxy.seen, [[1, 'CONNECT', 'Basic dXNlcjpwYXNz']]);
  });
}

// A URL's `hostname` keeps the brackets of an IPv6 address, and a caller can pass it as is.
bounded('http.Agent: a bracketed IPv6 hostname is the same destination', async () => {
  const proxy = await scriptedProxy(() => 'ok');
  const request = { rejectUnauthorized: false, hostname: '[::1]' };
  assert.equal(await viaAgent([proxy.url], {}, `https://[::1]:${tlsPort}/v6-bracketed`, request), 'origin saw /v6-bracketed');
  assert.deepEqual(proxy.targets, [[`[::1]:${tlsPort}`, `[::1]:${tlsPort}`]]);
});

test('the proxy of an IPv6 step is dialled and named without its brackets', async () => {
  assert.deepEqual(proxyAddress(new URL('http://[::1]:3128')), { host: '::1', port: 3128 });
  assert.deepEqual(proxyAddress(new URL('https://[2001:db8::1]')), { host: '2001:db8::1', port: 443 });
  const { kerberos, made } = fakeKerberos();
  const session = negotiateAuth({ kerberos }).start(new URL('http://[2001:db8::1]:3128'), 'origin.test:443', { passwordState: null });
  assert.equal(await session.respond(['Negotiate'], true), 'Negotiate first');
  assert.equal(made[0].service, process.platform === 'win32' ? 'HTTP/2001:db8::1' : 'HTTP@2001:db8::1');
});

// A misspelt mechanism would otherwise fall to the SPNEGO default and let NTLM out.
test('negotiateAuth refuses a mechanism it does not know', () => {
  assert.throws(
    () => negotiateAuth({ mechanism: 'krb5' }),
    (error) => error.code === 'ERR_INVALID_ARG_VALUE' && /krb5/.test(error.message),
  );
  for (const mechanism of [undefined, 'spnego', 'kerberos']) negotiateAuth({ mechanism });
});

// The tunnel opens and the destination never answers TLS: `connectTimeout` covers the
// handshake too, since undici puts no timer on a `connect` function of its own.
bounded('fetch: a TLS handshake that stalls behind an open tunnel times out', async () => {
  const stalled = await listen(net.createServer((socket) => sockets.add(socket)));
  servers.push(stalled);
  const proxy = await scriptedProxy(() => 'ok');
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes([proxy.url]),
    connectTimeout: 300,
    requestTls: { rejectUnauthorized: false },
  });
  const started = Date.now();
  await assert.rejects(request(`https://origin.test:${stalled.address().port}/stall`, { dispatcher }), (error) =>
    [error.code, error.cause?.code].includes('ETIMEDOUT'),
  );
  assert.ok(Date.now() - started < 5_000, `took ${Date.now() - started} ms`);
  // Nothing is left for close() to wait on.
  await dispatcher.close();
});

// A proxy that reads what it is sent and never answers, or answers the first read with
// `answer` and nothing after it; `reached` settles on the first bytes it reads, `closed` when
// the client drops the connection.
async function silentProxy(answer) {
  let close;
  let reach;
  const closed = new Promise((resolve) => (close = resolve));
  const reached = new Promise((resolve) => (reach = resolve));
  const server = await listen(
    net.createServer((socket) => {
      sockets.add(socket);
      if (answer) socket.once('data', () => socket.write(answer));
      socket.once('data', reach);
      socket.resume();
      socket.on('close', close);
    }),
  );
  servers.push(server);
  return { port: server.address().port, closed, reached };
}

// The step agent hands the request on when connectTimeout passes; the connection it was
// opening to the silent proxy is closed then, not left open for the life of the process.
for (const [what, scheme, target, answer] of [
  ['a CONNECT the proxy never answers', 'http', () => tlsUrl('/silent-connect')],
  ['a TLS handshake an https: proxy never answers', 'https', () => `http://origin.test:${plainPort}/silent-tls`],
  [
    'a TLS handshake with the destination that stalls behind an open tunnel',
    'http',
    () => tlsUrl('/silent-destination'),
    'HTTP/1.1 200 Connection Established\r\n\r\n',
  ],
]) {
  bounded(`http.Agent: ${what} is closed when the request moves on`, async () => {
    const silent = await silentProxy(answer);
    const next = await scriptedProxy(() => 'ok');
    const steps = [`${scheme}://127.0.0.1:${silent.port}`, next.url];
    assert.match(await viaAgent(steps, { connectTimeout: 200 }, target()), /^origin saw/);
    const outcome = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 2_000).unref())]);
    assert.equal(outcome, 'closed');
  });
}

// A proxyAuth that never answers is held to connectTimeout like the proxy is.
bounded('fetch: a proxyAuth that never answers times out with the connection', async () => {
  const proxy = await scriptedProxy(() => ({ status: 407, challenge: 'Token' }));
  const proxyAuth = { start: () => ({ respond: () => new Promise(() => {}) }) };
  const dispatcher = new SystemProxyDispatcher({
    routes: new FixedRoutes([proxy.url]),
    connectTimeout: 300,
    requestTls: { rejectUnauthorized: false },
    proxyAuth,
  });
  await assert.rejects(request(tlsUrl('/auth-hangs'), { dispatcher }), (error) =>
    [error.code, error.cause?.code].includes('ETIMEDOUT'),
  );
  await dispatcher.close();
});

bounded('fetch: a proxy that does not answer CONNECT in time hands the request on', async () => {
  const silent = await listen(net.createServer((socket) => sockets.add(socket)));
  servers.push(silent);
  const next = await scriptedProxy(() => 'ok');
  const steps = [`http://127.0.0.1:${silent.address().port}`, next.url];
  assert.equal(await viaFetch(steps, { connectTimeout: 200 }, tlsUrl('/silent')), 'origin saw /silent');
  assert.equal(next.seen.length, 1);
});

// A proxy that answers each read, on whichever connection, with the next of `answers`,
// counting the connections it is opened on.
async function rawProxy(answers) {
  const state = { connections: 0 };
  let next = 0;
  const server = await listen(
    net.createServer((socket) => {
      sockets.add(socket);
      state.connections += 1;
      socket.on('data', () => next < answers.length && socket.write(answers[next++]));
      socket.on('error', () => {});
    }),
  );
  servers.push(server);
  return { url: new URL(`http://127.0.0.1:${server.address().port}`), state };
}

bounded('a refusal other than 407 fails at its head, without waiting on its body', async () => {
  const proxy = await rawProxy(['HTTP/1.1 403 Forbidden\r\nContent-Length: 100\r\n\r\nshort']);
  const started = Date.now();
  await assert.rejects(openTunnel({ proxy: proxy.url, host: 'a.test', port: 443 }), refused(403));
  assert.ok(Date.now() - started < 3_000, `took ${Date.now() - started} ms`);
});

bounded('a 407 whose body is longer than a megabyte is not waited on, and its connection is dropped', async () => {
  const huge = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Token\r\nContent-Length: 2000000\r\n\r\n';
  const proxy = await rawProxy([huge, 'HTTP/1.1 200 OK\r\n\r\n']);
  const { auth, calls } = recording(['Token again']);
  const socket = await openTunnel({ proxy: proxy.url, host: 'a.test', port: 443, auth, timeout: 3_000 });
  socket.destroy();
  assert.deepEqual(calls.at(-1), [['Token'], false]);
  assert.equal(proxy.state.connections, 2);
});

// A 407 no session answers fails at its head: its body is read only to keep the connection
// for another round.
for (const [framing, head] of [
  ['a Content-Length', 'Content-Length: 100'],
  ['chunked framing', 'Transfer-Encoding: chunked'],
]) {
  bounded(`a 407 with ${framing} and no body fails at once without proxyAuth`, async () => {
    const proxy = await rawProxy([`HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n${head}\r\n\r\n`]);
    const started = Date.now();
    await assert.rejects(openTunnel({ proxy: proxy.url, host: 'a.test', port: 443 }), refused(407));
    assert.ok(Date.now() - started < 3_000, `took ${Date.now() - started} ms`);
  });
}

bounded('a complete chunked 407 body longer than a megabyte drops its connection', async () => {
  const body = 'x'.repeat(1024 * 1024 + 100);
  const chunked = `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`;
  const huge = `HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Token\r\nTransfer-Encoding: chunked\r\n\r\n${chunked}`;
  const proxy = await rawProxy([huge, 'HTTP/1.1 200 OK\r\n\r\n']);
  const { auth, calls } = recording(['Token again']);
  const socket = await openTunnel({ proxy: proxy.url, host: 'a.test', port: 443, auth, timeout: 5_000 });
  socket.destroy();
  assert.deepEqual(calls.at(-1), [['Token'], false]);
  assert.equal(proxy.state.connections, 2);
});

// Whether a 407's connection carries the next CONNECT: HTTP/1.1 keeps it unless a side asks
// to close, HTTP/1.0 only where `Connection` or `Proxy-Connection` asks to keep it, and only
// a body whose end its framing gives is read past. Anything else goes on a new connection.
for (const [name, head, same] of [
  ['an HTTP/1.0 407 without keep-alive', 'HTTP/1.0 407 X\r\nProxy-Authenticate: Token\r\nContent-Length: 4\r\n\r\nnope', false],
  ['an HTTP/1.0 407 with Connection: keep-alive', 'HTTP/1.0 407 X\r\nProxy-Authenticate: Token\r\nConnection: keep-alive\r\nContent-Length: 4\r\n\r\nnope', true],
  ['an HTTP/1.0 407 with Proxy-Connection: keep-alive', 'HTTP/1.0 407 X\r\nProxy-Authenticate: Token\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 4\r\n\r\nnope', true],
  ['a 407 with neither a length nor chunked framing', 'HTTP/1.1 407 X\r\nProxy-Authenticate: Token\r\n\r\nnope', false],
  ['a 407 with two Content-Lengths', 'HTTP/1.1 407 X\r\nProxy-Authenticate: Token\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nnope', false],
  ['a 407 whose Content-Length is not a number', 'HTTP/1.1 407 X\r\nProxy-Authenticate: Token\r\nContent-Length: 4x\r\n\r\nnope', false],
]) {
  bounded(`${name} ${same ? 'keeps its connection' : 'gets the next CONNECT on a new connection'}`, async () => {
    // The proxy never closes a connection itself, so a body read to the close would time out.
    const proxy = await rawProxy([head, 'HTTP/1.1 200 OK\r\n\r\n']);
    const { auth, calls } = recording(['Token again']);
    const socket = await openTunnel({ proxy: proxy.url, host: 'a.test', port: 443, auth, timeout: 3_000 });
    socket.destroy();
    assert.deepEqual(calls.at(-1), [['Token'], same]);
    assert.equal(proxy.state.connections, same ? 1 : 2);
  });
}

// A proxy that closes a kept 407 connection while `respond` runs gets the answer on a new one.
bounded('a 407 connection the proxy closes while respond runs gets the next CONNECT on a new one', async () => {
  let connections = 0;
  let closed;
  const firstClosed = new Promise((resolve) => (closed = resolve));
  const server = await listen(
    net.createServer((socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
      if ((connections += 1) > 1) return socket.once('data', () => socket.write('HTTP/1.1 200 OK\r\n\r\n'));
      socket.once('data', () => {
        socket.write('HTTP/1.1 407 X\r\nProxy-Authenticate: Token\r\nContent-Length: 0\r\n\r\n');
        socket.end();
        socket.on('close', closed);
      });
    }),
  );
  servers.push(server);
  const sessions = [];
  const auth = {
    start() {
      return {
        async respond(challenges, sameConnection) {
          sessions.push(sameConnection);
          await firstClosed;
          // The client's side of the close lands after the server's.
          await new Promise((resolve) => setTimeout(resolve, 50));
          return 'Token again';
        },
      };
    },
  };
  const proxy = new URL(`http://127.0.0.1:${server.address().port}`);
  const socket = await openTunnel({ proxy, host: 'a.test', port: 443, auth, timeout: 3_000 });
  socket.destroy();
  assert.deepEqual(sessions, [true]);
  assert.equal(connections, 2);
});

// A kept 407 connection the proxy closes on the next CONNECT, unanswered, is a stale one: the
// CONNECT goes again on a new connection, once, rather than failing with a reset that would
// hand the request to the next step. A new connection that closes the same way fails.
for (const close of ['destroy', 'end']) {
  bounded(`a kept 407 connection the proxy closes (${close}) on the next CONNECT sends it again on a new one`, async () => {
    let connections = 0;
    const seen = [];
    const server = await listen(
      net.createServer((socket) => {
        sockets.add(socket);
        socket.on('error', () => {});
        const connection = (connections += 1);
        let requests = 0;
        socket.on('data', (chunk) => {
          seen.push([connection, /proxy-authorization: (.*)/i.exec(String(chunk))?.[1]]);
          requests += 1;
          if (connection === 1 && requests === 1) {
            socket.write('HTTP/1.1 407 X\r\nProxy-Authenticate: Token\r\nContent-Length: 0\r\n\r\n');
          } else if (connection === 1) socket[close]();
          else socket.write('HTTP/1.1 200 OK\r\n\r\n');
        });
      }),
    );
    servers.push(server);
    const auth = { start: () => ({ respond: async () => 'Token again' }) };
    const proxy = new URL(`http://127.0.0.1:${server.address().port}`);
    const socket = await openTunnel({ proxy, host: 'a.test', port: 443, auth, timeout: 3_000 });
    socket.destroy();
    assert.deepEqual(seen, [
      [1, undefined],
      [1, 'Token again'],
      [2, 'Token again'],
    ]);
  });
}

bounded('a CONNECT is sent again once only when connections keep closing unanswered', async () => {
  let connections = 0;
  const server = await listen(
    net.createServer((socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
      const connection = (connections += 1);
      socket.once('data', () => {
        if (connection === 1) {
          socket.write('HTTP/1.1 407 X\r\nProxy-Authenticate: Token\r\nContent-Length: 0\r\n\r\n');
          socket.once('data', () => socket.destroy());
        } else socket.destroy();
      });
    }),
  );
  servers.push(server);
  const auth = { start: () => ({ respond: async () => 'Token again' }) };
  const proxy = new URL(`http://127.0.0.1:${server.address().port}`);
  await assert.rejects(openTunnel({ proxy, host: 'a.test', port: 443, auth, timeout: 3_000 }), { code: 'ECONNRESET' });
  assert.equal(connections, 2);
});

for (const [name, answer, message] of [
  ['no HTTP status line', 'HTP/1.1 200 OK\r\n\r\n', /no HTTP status line/],
  ['a header without a colon', 'HTTP/1.1 200 OK\r\nno colon here\r\n\r\n', /malformed header/],
  ['a header with an empty name', 'HTTP/1.1 200 OK\r\n: value\r\n\r\n', /malformed header/],
]) {
  bounded(`an answer to CONNECT with ${name} fails the tunnel`, async () => {
    const proxy = await rawProxy([answer]);
    await assert.rejects(openTunnel({ proxy: proxy.url, host: 'a.test', port: 443, timeout: 3_000 }), message);
  });
}

// A direct step before the last holds its TLS handshake to connectTimeout: a destination
// that accepts the connection and never answers the handshake hands the request on, and the
// connection to it is closed. The proxy after it tunnels to the real origin whatever the
// CONNECT names.
bounded('a direct step whose TLS handshake stalls hands the request on', async () => {
  const proxy = await listen(
    net.createServer((client) => {
      sockets.add(client);
      client.once('data', () => {
        const upstream = net.connect(tlsPort, '127.0.0.1', () => {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.on('error', () => client.destroy());
      });
      client.on('error', () => {});
    }),
  );
  servers.push(proxy);
  const steps = ['direct', `http://127.0.0.1:${proxy.address().port}`];
  for (const [via, path] of [
    [viaAgent, '/stalled-direct'],
    [viaFetch, '/stalled-direct-fetch'],
  ]) {
    const silent = await silentProxy();
    const target = `https://127.0.0.1:${silent.port}${path}`;
    assert.equal(await via(steps, { connectTimeout: 300 }, target), `origin saw ${path}`);
    const outcome = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 2_000).unref())]);
    assert.equal(outcome, 'closed', via.name);
  }
});

bounded('http.Agent: an IPv6 destination with a zone id is routed without it', async () => {
  let routed;
  const read = new Promise((resolve) => (routed = resolve));
  const routes = new (class extends RecordingRoutes {
    async route(snapshot, url) {
      const route = await super.route(snapshot, url);
      routed();
      return route;
    }
  })(['direct']);
  const agent = systemProxyAgent({ routes });
  try {
    // The connection to the address may fail, or on Windows hang until the system gives up
    // on it; only the route is checked, so the request ends once its connection starts.
    const outcome = await new Promise((resolve) => {
      const req = http
        .get({ agent, host: 'fe80::1%lo', port: 9, path: '/zone' }, (res) => res.resume().on('end', () => resolve('answered')))
        .on('error', (error) => resolve(error));
      read.then(() => setTimeout(() => req.destroy(), 50));
    });
    assert.ok(!(outcome instanceof RouteError) && !/IPv6/.test(outcome?.message ?? ''), String(outcome?.message));
  } finally {
    agent.destroy();
  }
  assert.deepEqual(routes.urls, ['http://[fe80::1]:9/zone']);
});

// A SOCKS5 proxy with user name and password authentication (RFC 1928, RFC 1929) that
// connects every request to `port` (the plain origin's) and records the credentials it was
// given and what each request asked for: the command, the address type (1 IPv4, 3 name,
// 4 IPv6), the address or name, and the port.
async function socks5Proxy(port = plainPort) {
  const credentials = [];
  const requests = [];
  const server = await listen(
    net.createServer((client) => {
      sockets.add(client);
      client.on('error', () => {});
      let buffer = Buffer.alloc(0);
      let stage = 'greeting';
      client.on('data', function onData(chunk) {
        buffer = Buffer.concat([buffer, chunk]);
        if (stage === 'greeting' && buffer.length >= 2 && buffer.length >= 2 + buffer[1]) {
          buffer = buffer.subarray(2 + buffer[1]);
          client.write(Buffer.from([5, 2]));
          stage = 'auth';
        }
        if (stage === 'auth' && buffer.length >= 2) {
          const userLength = buffer[1];
          if (buffer.length < 3 + userLength) return;
          const passwordLength = buffer[2 + userLength];
          if (buffer.length < 3 + userLength + passwordLength) return;
          credentials.push([
            buffer.subarray(2, 2 + userLength).toString(),
            buffer.subarray(3 + userLength, 3 + userLength + passwordLength).toString(),
          ]);
          buffer = buffer.subarray(3 + userLength + passwordLength);
          client.write(Buffer.from([1, 0]));
          stage = 'request';
        }
        if (stage === 'request' && buffer.length >= 5) {
          const addressLength = { 1: 4, 3: 1 + buffer[4], 4: 16 }[buffer[3]];
          if (buffer.length < 4 + addressLength + 2) return;
          client.off('data', onData);
          const address = buffer.subarray(4, 4 + addressLength);
          const host =
            buffer[3] === 1
              ? [...address].join('.')
              : buffer[3] === 3
                ? address.subarray(1).toString()
                : [...Array(8).keys()].map((i) => address.readUInt16BE(2 * i).toString(16)).join(':');
          requests.push([buffer[1], buffer[3], host, buffer.readUInt16BE(4 + addressLength)]);
          const upstream = net.connect(port, '127.0.0.1', () => {
            client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
            client.pipe(upstream);
            upstream.pipe(client);
          });
          upstream.on('error', () => client.destroy());
        }
      });
    }),
  );
  servers.push(server);
  return { port: server.address().port, credentials, requests };
}

// A SOCKS4 proxy, SOCKS4a included, that connects every request to `port` and records what
// each asked for: the version, the user ID, the address or (SOCKS4a, address 0.0.0.x) the
// name, and the port.
async function socks4Proxy(port = plainPort) {
  const requests = [];
  const server = await listen(
    net.createServer((client) => {
      sockets.add(client);
      client.on('error', () => {});
      let buffer = Buffer.alloc(0);
      client.on('data', function onData(chunk) {
        buffer = Buffer.concat([buffer, chunk]);
        const userEnd = buffer.length > 8 ? buffer.indexOf(0, 8) : -1;
        if (userEnd === -1) return;
        const address = [...buffer.subarray(4, 8)];
        let target = address.join('.');
        if (address[0] === 0 && address[1] === 0 && address[2] === 0 && address[3] !== 0) {
          const nameEnd = buffer.indexOf(0, userEnd + 1);
          if (nameEnd === -1) return;
          target = buffer.subarray(userEnd + 1, nameEnd).toString();
        }
        client.off('data', onData);
        requests.push([buffer[0], buffer.subarray(8, userEnd).toString(), target, buffer.readUInt16BE(2)]);
        const upstream = net.connect(port, '127.0.0.1', () => {
          client.write(Buffer.from([0, 0x5a, 0, 0, 0, 0, 0, 0]));
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.on('error', () => client.destroy());
      });
    }),
  );
  servers.push(server);
  return { port: server.address().port, requests };
}

// A `socks4` step sends the destination's address, a `socks4a` step its name; both send the
// URL's user name as the user ID. Each is checked as the last step and before it.
bounded('http.Agent: a socks4 step sends the address and a socks4a step the name', async () => {
  const plainProxy = await socks4Proxy(plainPort);
  const tlsProxy = await socks4Proxy(tlsPort);
  const next = await scriptedProxy(() => 'ok');
  for (const tail of [[], [next.url]]) {
    const plain = `socks4://u@127.0.0.1:${plainProxy.port}`;
    const named = `socks4a://u@127.0.0.1:${plainProxy.port}`;
    const tls = `socks4a://u@127.0.0.1:${tlsProxy.port}`;
    assert.equal(await viaAgent([plain, ...tail], {}, `http://127.0.0.1:${plainPort}/socks4`), 'origin saw /socks4');
    assert.equal(await viaAgent([named, ...tail], {}, `http://origin.test:${plainPort}/socks4a`), 'origin saw /socks4a');
    assert.equal(await viaAgent([tls, ...tail], {}, tlsUrl('/socks4a-tls')), 'origin saw /socks4a-tls');
  }
  const twice = (requests) => [...requests, ...requests];
  assert.deepEqual(
    plainProxy.requests,
    twice([
      [4, 'u', '127.0.0.1', plainPort],
      [4, 'u', 'origin.test', plainPort],
    ]),
  );
  assert.deepEqual(tlsProxy.requests, twice([[4, 'u', 'origin.test', tlsPort]]));
  assert.deepEqual(next.seen, []);
});

// A `socks4` step sends an IPv4 address for a name that also has an IPv6 one, whichever the
// lookup puts first: the SOCKS client would send the IPv6 one as a SOCKS4a name.
bounded('http.Agent: a socks4 step sends the IPv4 address of a name', async () => {
  const proxy = await socks4Proxy(plainPort);
  const step = `socks4://127.0.0.1:${proxy.port}`;
  const lookup = (host, options, callback) =>
    options.family === 4 ? callback(null, '127.0.0.1', 4) : callback(null, '::1', 6);
  assert.equal(await viaAgent([step], { lookup }, `http://dual.test:${plainPort}/dual`), 'origin saw /dual');
  assert.deepEqual(proxy.requests, [[4, '', '127.0.0.1', plainPort]]);
});

// A route to an IPv6 address leaves out the SOCKS steps that cannot carry it, as steps the
// client does not speak: `socks4` on http.Agent, and every SOCKS step on `fetch`, whose
// SOCKS5 agent would send the address as a name. The request goes to the next step, and a
// route of such steps alone fails.
for (const [client, via, socks, step] of [
  ['http.Agent', viaAgent, socks4Proxy, (port) => `socks4://127.0.0.1:${port}`],
  ['fetch', viaFetch, socks5Proxy, (port) => `socks5h://u:p@127.0.0.1:${port}`],
]) {
  bounded(`${client}: a route to an IPv6 address leaves out a SOCKS step that cannot carry it`, async () => {
    const proxy = await socks();
    const next = await scriptedProxy(() => ({ status: 403 }));
    const target = `https://[::1]:${tlsPort}/v6`;
    await assert.rejects(via([step(proxy.port), next.url], {}, target));
    assert.deepEqual(
      next.targets.map(([target]) => target),
      [`[::1]:${tlsPort}`],
    );
    await assert.rejects(via([step(proxy.port)], {}, target), { code: 'ERR_PROXY_ROUTE' });
    assert.deepEqual(proxy.requests, []);
  });
}

bounded('http.Agent: a bracketed IPv6 hostname leaves out a socks4 step too', async () => {
  const proxy = await socks4Proxy();
  const request = { rejectUnauthorized: false, hostname: '[::1]' };
  await assert.rejects(
    viaAgent([`socks4://127.0.0.1:${proxy.port}`], {}, `https://[::1]:${tlsPort}/v6`, request),
    { code: 'ERR_PROXY_ROUTE' },
  );
  assert.deepEqual(proxy.requests, []);
});

// A SOCKS proxy written as an IPv6 address is dialled at that address, not looked up as the
// name `[::1]`. Nothing listens there, so the dial fails.
for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: a SOCKS proxy written as an IPv6 address is dialled at it`, async () => {
    await assert.rejects(via(['socks5h://[::1]:1'], {}, `http://127.0.0.1:${plainPort}/v6-proxy`), (error) => {
      assert.doesNotMatch(
        `${error.code} ${error.cause?.code} ${error.message} ${error.cause?.message}`,
        /ENOTFOUND|getaddrinfo/,
      );
      return true;
    });
  });
}

// A SOCKS5 step asks its proxy to CONNECT to the destination's name and port, or to its
// address where the URL has one. `socks5h://` leaves the name to the proxy on both clients;
// `socks5://` does on `fetch`, which has undici's SOCKS5 agent send the name either way. Each
// is checked as the last step and before it.
for (const [client, via, cases] of [
  [
    'http.Agent',
    viaAgent,
    () => [
      ['socks5', `http://127.0.0.1:${plainPort}/v4`, [1, 1, '127.0.0.1', plainPort]],
      ['socks5h', `http://[::1]:${plainPort}/v6`, [1, 4, '0:0:0:0:0:0:0:1', plainPort]],
    ],
  ],
  ['fetch', viaFetch, () => [['socks5', `http://origin.test:${plainPort}/name`, [1, 3, 'origin.test', plainPort]]]],
]) {
  bounded(`${client}: a SOCKS5 step sends the destination's name or address and port`, async () => {
    const plainProxy = await socks5Proxy(plainPort);
    const tlsProxy = await socks5Proxy(tlsPort);
    const next = await scriptedProxy(() => 'ok');
    const all = [
      ['socks5h', `http://origin.test:${plainPort}/name`, [1, 3, 'origin.test', plainPort]],
      ['socks5h', `http://127.0.0.1:${plainPort}/v4`, [1, 1, '127.0.0.1', plainPort]],
      ...cases(),
    ];
    for (const tail of [[], [next.url]]) {
      for (const [scheme, target] of all) {
        const step = `${scheme}://u:p@127.0.0.1:${plainProxy.port}`;
        assert.equal(await via([step, ...tail], {}, target), `origin saw ${new URL(target).pathname}`);
      }
      const tls = `socks5h://u:p@127.0.0.1:${tlsProxy.port}`;
      assert.equal(await via([tls, ...tail], {}, tlsUrl('/tls')), 'origin saw /tls');
    }
    const expected = all.map(([, , request]) => request);
    assert.deepEqual(plainProxy.requests, [...expected, ...expected]);
    assert.deepEqual(tlsProxy.requests, Array(2).fill([1, 3, 'origin.test', tlsPort]));
    assert.deepEqual(next.seen, []);
  });
}

// The SOCKS agents decode a step's credentials with `decodeURIComponent`; a malformed escape
// reaches the proxy as the characters it stands for instead of throwing.
for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: a SOCKS5 password with a malformed escape reaches the proxy as written`, async () => {
    const socks = await socks5Proxy();
    const step = `socks5h://u%zz:p%20x%zz@127.0.0.1:${socks.port}`;
    assert.equal(await via([step], {}, `http://origin.test:${plainPort}/socks`), 'origin saw /socks');
    assert.deepEqual(socks.credentials, [['u%zz', 'p x%zz']]);
  });

  // `proxyTls` is for an `https:` proxy; a SOCKS step speaks plain SOCKS to its proxy.
  bounded(`${client}: proxyTls leaves a SOCKS step's connection to its proxy plain`, async () => {
    const socks = await socks5Proxy();
    const step = `socks5h://u:p@127.0.0.1:${socks.port}`;
    const target = `http://origin.test:${plainPort}/socks-proxy-tls`;
    assert.equal(await via([step], { proxyTls: {} }, target), 'origin saw /socks-proxy-tls');
  });
}

// The agent's `timeout` on a SOCKS step closes no connection, as on Node's agent.
bounded('http.Agent: the agent timeout leaves a slow answer through a SOCKS step to arrive', async () => {
  const slow = await listen(http.createServer((req, res) => setTimeout(() => res.end(`slow ${req.url}`), 400)));
  servers.push(slow);
  const socks = await socks5Proxy(slow.address().port);
  const agent = systemProxyAgent({ routes: new FixedRoutes([`socks5h://u:p@127.0.0.1:${socks.port}`]), timeout: 150 });
  try {
    const body = await new Promise((resolve, reject) =>
      http
        .get(`http://origin.test/socks-slow`, { agent }, (res) => {
          let text = '';
          res.on('data', (chunk) => (text += chunk));
          res.on('end', () => resolve(text));
        })
        .on('error', reject),
    );
    assert.equal(body, 'slow /socks-slow');
  } finally {
    agent.destroy();
  }
});

// The connection waits on `initial()` with no exchange on it; the timeout's destroy there is
// the tunnel's failure, not an uncaught error.
bounded('a timeout while initial() runs fails the tunnel', async () => {
  const silent = await silentProxy();
  const uncaught = [];
  const record = (error) => uncaught.push(error);
  process.on('uncaughtException', record);
  try {
    const auth = { start: () => ({ initial: () => new Promise((r) => setTimeout(() => r('Token x'), 500)), respond: async () => undefined }) };
    const proxy = new URL(`http://127.0.0.1:${silent.port}`);
    await assert.rejects(openTunnel({ proxy, host: 'a.test', port: 443, auth, timeout: 200 }), { code: 'ETIMEDOUT' });
    await new Promise((r) => setTimeout(r, 400));
  } finally {
    process.off('uncaughtException', record);
  }
  assert.deepEqual(uncaught, []);
});

// A plain HTTP server that records each request's raw bytes, and answers it once its body
// has come.
async function rawOrigin() {
  const requests = [];
  // Every byte received, across connections and past the first request on one.
  let received = '';
  const server = await listen(
    net.createServer((socket) => {
      sockets.add(socket);
      let raw = '';
      socket.on('data', (chunk) => {
        received += chunk.toString('latin1');
        raw += chunk.toString('latin1');
        const end = raw.indexOf('\r\n\r\n');
        if (end === -1) return;
        const head = raw.slice(0, end);
        if (/\r\ntransfer-encoding: *chunked/i.test(head)) {
          if (!raw.endsWith('\r\n0\r\n\r\n')) return;
        } else if (raw.length < end + 4 + Number(/\r\ncontent-length: *(\d+)/i.exec(head)?.[1] ?? 0)) {
          return;
        }
        requests.push(raw);
        raw = '';
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
      });
    }),
  );
  servers.push(server);
  return { port: server.address().port, requests, received: () => received };
}

// `req` ended after `ms`, with `x-late` set first, through `agent`; resolves with the status.
function lateRequest(agent, url, ms) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { agent, method: 'POST' }, (res) => res.resume().on('end', () => resolve(res.statusCode)));
    req.on('error', reject);
    setTimeout(() => {
      try {
        req.setHeader('x-late', '1');
        req.end('hello');
      } catch (error) {
        req.destroy(error);
      }
    }, ms);
  });
}

// A forwarded request whose header is not stored yet takes headers the caller sets later,
// and keeps the Content-Length that `end(body)` gives it.
bounded('http.Agent: a forwarded request takes headers set after it was handed to the agent', async () => {
  const origin = await rawOrigin();
  const proxy = await listen(
    net.createServer((client) => {
      sockets.add(client);
      const upstream = net.connect(origin.port, '127.0.0.1');
      client.pipe(upstream);
      upstream.pipe(client);
    }),
  );
  servers.push(proxy);
  const agent = systemProxyAgent({ routes: new FixedRoutes([`http://127.0.0.1:${proxy.address().port}`]) });
  try {
    assert.equal(await lateRequest(agent, `http://origin.test:${origin.port}/late`, 100), 200);
  } finally {
    agent.destroy();
  }
  assert.equal(origin.requests.length, 1);
  const [head, body] = origin.requests[0].split('\r\n\r\n');
  assert.match(head, /^POST http:\/\/origin\.test:\d+\/late /);
  assert.match(head, /\r\nx-late: 1(\r\n|$)/i);
  assert.match(head, /\r\ncontent-length: 5(\r\n|$)/i);
  assert.equal(body, 'hello');
});

// A request ended while a forwarding step held it, rewritten for that proxy, goes to the
// next step as the caller wrote it: no proxy credentials, its own path, one framing.
bounded('http.Agent: a request ended while a forwarding step failed reaches the next step without the rewrite', async () => {
  const origin = await rawOrigin();
  const silent = await silentProxy();
  const steps = [`https://user:secret@127.0.0.1:${silent.port}`, 'direct'];
  const agent = systemProxyAgent({ routes: new FixedRoutes(steps), connectTimeout: 300 });
  try {
    assert.equal(await lateRequest(agent, `http://127.0.0.1:${origin.port}/restored`, 100), 200);
  } finally {
    agent.destroy();
  }
  assert.equal(origin.requests.length, 1);
  const [head, body] = origin.requests[0].split('\r\n\r\n');
  assert.match(head, /^POST \/restored HTTP\/1\.1\r\n/);
  assert.doesNotMatch(head, /proxy-/i);
  assert.match(head, /\r\nx-late: 1(\r\n|$)/i);
  assert.match(head, /\r\ncontent-length: 5(\r\n|$)/i);
  assert.equal(body, 'hello');
});

// A header the request sent into its queue before the agent rewrote it (`flushHeaders()`, a
// `write()`) goes out once, rewritten, on a forwarding step and on the step after a failed
// one alike.
// `Expect` makes Node queue the header as the request is made, and again each time it is
// stored.
for (const [what, early, headers] of [
  ['flushHeaders()', (req) => req.flushHeaders(), {}],
  ['an early write()', (req) => req.write('a'), {}],
  ['Expect: 100-continue', () => {}, { expect: '100-continue' }],
]) {
  for (const route of ['a forwarding step', 'the step after a failed forwarding step']) {
    bounded(`http.Agent: a request that sent its header with ${what} carries it once through ${route}`, async () => {
      const origin = await rawOrigin();
      let steps;
      if (route === 'a forwarding step') {
        const proxy = await listen(
          net.createServer((client) => {
            sockets.add(client);
            const upstream = net.connect(origin.port, '127.0.0.1');
            client.pipe(upstream);
            upstream.pipe(client);
          }),
        );
        servers.push(proxy);
        steps = [`http://u:p@127.0.0.1:${proxy.address().port}`];
      } else {
        steps = [`https://u:p@127.0.0.1:${(await silentProxy()).port}`, 'direct'];
      }
      const agent = systemProxyAgent({ routes: new FixedRoutes(steps), connectTimeout: 300 });
      try {
        const status = await new Promise((resolve, reject) => {
          const req = http.request(`http://127.0.0.1:${origin.port}/once`, { agent, method: 'POST', headers }, (res) =>
            res.resume().on('end', () => resolve(res.statusCode)),
          );
          req.on('error', reject);
          early(req);
          setTimeout(() => req.end('b'), 100);
        });
        assert.equal(status, 200);
      } finally {
        agent.destroy();
      }
      await new Promise((r) => setTimeout(r, 100));
      const received = origin.received();
      assert.equal(origin.requests.length, 1);
      assert.equal(received.match(/ HTTP\/1\.1\r\n/g).length, 1, JSON.stringify(received));
      // The proxy here is a pipe: what the origin reads is what the agent wrote to it.
      if (route === 'a forwarding step') {
        assert.ok(received.startsWith(`POST http://127.0.0.1:${origin.port}/once HTTP/1.1\r\n`), JSON.stringify(received));
        assert.equal(received.match(/\r\nproxy-authorization: Basic dTpw\r\n/gi)?.length, 1, JSON.stringify(received));
      } else {
        assert.ok(received.startsWith('POST /once HTTP/1.1\r\n'), JSON.stringify(received));
        assert.doesNotMatch(received, /\r\nproxy-/i);
      }
    });
  }
}

// The last step has no limit of its own; the request's timeout fires while it connects, as
// on Node's own agent, and destroying the request closes the connection being opened.
for (const [what, scheme, target, set] of [
  ['a CONNECT the proxy never answers', 'http', () => tlsUrl('/last-connect'), (req) => req.setTimeout(300)],
  ['a TLS handshake an https: proxy never answers', 'https', () => `http://origin.test:${plainPort}/last-tls`, null],
]) {
  bounded(`http.Agent: the request timeout fires through ${what} on the last step`, async () => {
    const silent = await silentProxy();
    const agent = systemProxyAgent({ routes: new FixedRoutes([`${scheme}://127.0.0.1:${silent.port}`]) });
    const mine = new Error('given up');
    try {
      const outcome = await new Promise((resolve) => {
        const req = (target().startsWith('https:') ? https : http).get(target(), { agent, rejectUnauthorized: false, ...(set ? {} : { timeout: 300 }) });
        set?.(req);
        req.on('timeout', () => req.destroy(mine));
        req.on('error', resolve);
      });
      assert.equal(outcome, mine);
      const closed = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 2_000).unref())]);
      assert.equal(closed, 'closed');
    } finally {
      agent.destroy();
    }
  });
}

// Headers given as an array live in the stored header alone; the rewrite keeps them, and
// putting the request back for the next step takes the proxy's lines out of it.
for (const route of ['a forwarding step', 'the step after a failed forwarding step']) {
  bounded(`http.Agent: a request with its headers as an array keeps them through ${route}`, async () => {
    const origin = await rawOrigin();
    let steps;
    if (route === 'a forwarding step') {
      const proxy = await listen(
        net.createServer((client) => {
          sockets.add(client);
          const upstream = net.connect(origin.port, '127.0.0.1');
          client.pipe(upstream);
          upstream.pipe(client);
        }),
      );
      servers.push(proxy);
      steps = [`http://u:p@127.0.0.1:${proxy.address().port}`];
    } else {
      steps = [`https://x:y@127.0.0.1:${(await silentProxy()).port}`, 'direct'];
    }
    const agent = systemProxyAgent({ routes: new FixedRoutes(steps), connectTimeout: 300 });
    try {
      const status = await new Promise((resolve, reject) => {
        const req = http.request(`http://127.0.0.1:${origin.port}/array`, { agent, method: 'POST', headers: ['A', '1', 'A', '2'] }, (res) =>
          res.resume().on('end', () => resolve(res.statusCode)),
        );
        req.on('error', reject);
        setTimeout(() => req.end('hi'), 100);
      });
      assert.equal(status, 200);
    } finally {
      agent.destroy();
    }
    const [head] = origin.received().split('\r\n\r\n');
    assert.match(head, /\r\nA: 1\r\nA: 2\r\n/);
    if (route === 'a forwarding step') {
      assert.match(head, /^POST http:\/\/127\.0\.0\.1:\d+\/array /);
      assert.match(head, /\r\nProxy-Authorization: Basic dTpw(\r\n|$)/);
    } else {
      assert.match(head, /^POST \/array /);
      assert.doesNotMatch(head, /proxy-/i);
    }
  });
}

// The stored header's request target is replaced as written: `$&` and `$1` are characters of
// a path, not replacement patterns.
test('a stored header rewritten and put back keeps a path with $ in it', () => {
  const path = "/a$&b$1c$'d$`e$$f?q=$&";
  const req = http.request({ host: 'a.test', path, agent: { addRequest() {} } });
  req.on('error', () => {});
  req.end();
  const saved = saveRequest(req);
  rewriteHeader(req, () => {
    req.path = `http://a.test${path}`;
  });
  assert.ok(req.outputData[0].data.startsWith(`GET http://a.test${path} HTTP/1.1\r\n`), req.outputData[0].data);
  restoreRequest(req, saved);
  assert.ok(req.outputData[0].data.startsWith(`GET ${path} HTTP/1.1\r\n`), req.outputData[0].data);
  req.destroy();
});

// destroy() ends the tunnels being opened as well as the requests under way.
bounded('fetch: destroy() closes a CONNECT still waiting on the proxy', async () => {
  const silent = await silentProxy();
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes([`http://127.0.0.1:${silent.port}`]), connectTimeout: 5_000 });
  const pending = request(tlsUrl('/destroyed'), { dispatcher });
  pending.catch(() => {});
  await silent.reached;
  await dispatcher.destroy();
  await assert.rejects(pending);
  const closed = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 1_000).unref())]);
  assert.equal(closed, 'closed');
});

// proxyAuth answers a 407 to CONNECT; a forwarded http: request carries the URL's Basic
// alone, and a 407 to it reaches each client as that client reports a response it cannot
// use.
bounded('a 407 to a forwarded http: request comes back as the response, or fails fetch', async () => {
  const proxy = await rawProxy([
    'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n',
    'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n',
  ]);
  const steps = [proxy.url.href];
  const started = [];
  const proxyAuth = { start: () => (started.push(1), { respond: async () => undefined }) };
  const agent = systemProxyAgent({ routes: new FixedRoutes(steps), proxyAuth });
  try {
    const status = await new Promise((resolve, reject) =>
      http.get(`http://origin.test:${plainPort}/forwarded-407`, { agent }, (res) => res.resume().on('end', () => resolve(res.statusCode))).on('error', reject),
    );
    assert.equal(status, 407);
  } finally {
    agent.destroy();
  }
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes(steps), proxyAuth });
  try {
    await assert.rejects(request(`http://origin.test:${plainPort}/forwarded-407`, { dispatcher }), { code: 'UND_ERR_INVALID_ARG' });
  } finally {
    await dispatcher.destroy();
  }
  assert.deepEqual(started, []);
});

// Basic cannot carry a `:` in the user name on a forwarded request either.
for (const [client, send] of [
  ['http.Agent', (steps) => viaAgent(steps, {}, `http://origin.test:${plainPort}/colon`)],
  ['fetch', (steps) => viaFetch(steps, {}, `http://origin.test:${plainPort}/colon`)],
]) {
  bounded(`${client}: a forwarding step whose user name decodes to a colon fails the request`, async () => {
    const proxy = await scriptedProxy(() => 'ok');
    const step = proxy.url.replace('user:pass@', 'us%3Aer:pw@');
    await assert.rejects(send([step]), TypeError);
    assert.deepEqual(proxy.seen, []);
  });
}

// Between the connection to a proxy opening and the request taking it, nothing but the
// agent listens on the socket; a request destroyed then closes it without an uncaught error.
bounded('http.Agent: a request destroyed as its proxy connection opens throws nothing', async (t) => {
  const server = net.createServer((socket) => socket.on('error', () => {}));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let req;
  const setNoDelay = net.Socket.prototype.setNoDelay;
  // The connection to the proxy sets `noDelay` as it opens.
  t.mock.method(net.Socket.prototype, 'setNoDelay', function (...args) {
    if (req) {
      const opening = req;
      req = undefined;
      queueMicrotask(() => opening.destroy());
    }
    return setNoDelay.apply(this, args);
  });
  const agent = systemProxyAgent({ routes: new FixedRoutes([`http://127.0.0.1:${server.address().port}`]) });
  req = http.get(`http://origin.test:${plainPort}/destroyed`, { agent });
  // `once(req, 'close')` would reject on the request's own error.
  await new Promise((resolve) => req.on('error', () => {}).on('close', resolve));
  await new Promise((resolve) => setTimeout(resolve, 50));
  agent.destroy();
  await new Promise((resolve) => server.close(resolve));
});

// A CONNECT step's user name is checked before its proxy is dialled: a refused connection
// would hand the request to the next step and leave the setting unreported.
for (const [client, send] of [
  ['http.Agent', (steps) => viaAgent(steps, {}, tlsUrl('/colon-down'))],
  ['fetch', (steps) => viaFetch(steps, {}, tlsUrl('/colon-down'))],
]) {
  bounded(`${client}: a CONNECT step whose user name decodes to a colon fails while its proxy is down`, async () => {
    const closed = net.createServer();
    await new Promise((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const { port: down } = closed.address();
    await new Promise((resolve) => closed.close(resolve));
    await assert.rejects(send([`http://us%3Aer:pw@127.0.0.1:${down}`, 'direct']), TypeError);
  });
}

// A 407 body arrives in pieces of any size; where it ends does not depend on how it is cut.
test('the chunked reader finds the end of a body fed whole or a byte at a time', () => {
  const body = Buffer.from('5;ext=1\r\nhello\r\nA\r\n0123456789\r\n0\r\nX-Trailer: t\r\n\r\nnext');
  const end = body.length - 'next'.length;
  assert.equal(chunkedReader()(body), end);
  const read = chunkedReader();
  for (let i = 0; i < body.length; i += 1) {
    const found = read(body.subarray(i, i + 1));
    if (found !== null) {
      assert.equal(i + found, end);
      return;
    }
  }
  assert.fail('the end was not found');
});

test('the chunked reader refuses what is not chunked framing', () => {
  for (const text of ['zz\r\n', '5\r\nhelloXY', '5\nhello\r\n', '0\r\nX: t\n', `${'1'.repeat(5000)}`]) {
    assert.equal(chunkedReader()(Buffer.from(text)), -1, JSON.stringify(text.slice(0, 20)));
  }
});

// A proxy can send its body in tiny pieces; each byte is read once, however many there are.
// Reading the whole body again on each piece takes minutes for this one.
test('the chunked reader takes a body of many small pieces in linear time', () => {
  const read = chunkedReader();
  const piece = Buffer.from('1\r\nx\r\n');
  const started = performance.now();
  for (let i = 0; i < 170_000; i += 1) assert.equal(read(piece), null);
  assert.equal(read(Buffer.from('0\r\n\r\n')), 5);
  assert.ok(performance.now() - started < 2_000, `${performance.now() - started} ms`);
});

// An interim answer comes before the final one (RFC 9110 §15.2) and has no body.
bounded('a 1xx answer before the 200 opens the tunnel', async () => {
  const proxy = await rawProxy(['HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\nearly']);
  const socket = await openTunnel({ proxy: proxy.url, host: 'a.test', port: 443, timeout: 3_000 });
  socket.resume();
  const [early] = await once(socket, 'data');
  assert.equal(early.toString(), 'early');
  socket.destroy();
});

bounded('interim answers past the head limit fail the tunnel without a timeout', async () => {
  const interim = `HTTP/1.1 102 Processing\r\nX-Pad: ${'x'.repeat(1000)}\r\n\r\n`;
  const proxy = await rawProxy([interim.repeat(70)]);
  await assert.rejects(openTunnel({ proxy: proxy.url, host: 'a.test', port: 443 }), /interim answers too long/);
});

// A Negotiate token is the token68 after the scheme, without a parameter that follows it.
test('negotiateAuth steps with the token alone when the challenge carries a parameter', async () => {
  const { kerberos, made } = fakeKerberos();
  const session = negotiateAuth({ kerberos }).start(new URL('http://proxy.test:8080'), 'a.test:443', { passwordState: null });
  assert.equal(await session.respond(['Negotiate'], true), 'Negotiate first');
  assert.equal(await session.respond(['Negotiate challenge-2, realm=x'], true), 'Negotiate last');
  assert.deepEqual(made[0].client.steps, ['', 'challenge-2']);
});

// What a Negotiate session gives up on: a challenge its own context cannot take the next
// step from.
test('negotiateAuth answers only the challenges its own context can take', async () => {
  const start = (kerberos) =>
    negotiateAuth({ kerberos }).start(new URL('http://proxy.test:8080'), 'a.test:443', { passwordState: null });
  // No Negotiate among the challenges.
  let { kerberos, made } = fakeKerberos();
  assert.equal(await start(kerberos).respond(['Basic realm="x"'], true), undefined);
  assert.equal(made.length, 0);
  // A token before any of ours.
  ({ kerberos, made } = fakeKerberos());
  assert.equal(await start(kerberos).respond(['Negotiate challenge-2'], true), undefined);
  assert.equal(made.length, 0);
  // A challenge with parameters and no token, after ours.
  ({ kerberos, made } = fakeKerberos());
  let session = start(kerberos);
  assert.equal(await session.respond(['Negotiate'], true), 'Negotiate first');
  assert.equal(await session.respond(['Negotiate realm=x'], true), undefined);
  assert.deepEqual(made[0].client.steps, ['']);
  // A token after the context is complete.
  ({ kerberos, made } = fakeKerberos());
  session = start(kerberos);
  assert.equal(await session.respond(['Negotiate'], true), 'Negotiate first');
  assert.equal(await session.respond(['Negotiate challenge-2'], true), 'Negotiate last');
  assert.equal(await session.respond(['Negotiate challenge-3'], true), undefined);
  assert.deepEqual(made[0].client.steps, ['', 'challenge-2']);
});

test('negotiateAuth gives up where its context has no token to send', async () => {
  const kerberos = { GSS_MECH_OID_KRB5: 9, GSS_MECH_OID_SPNEGO: 6, initializeClient: async () => ({ step: async () => '' }) };
  const session = negotiateAuth({ kerberos }).start(new URL('http://proxy.test:8080'), 'a.test:443', { passwordState: null });
  assert.equal(await session.respond(['Negotiate'], true), undefined);
});

// A failure of the `kerberos` package names the principal and keeps the package's error.
const noCredentials = async () => {
  throw new Error('no credentials');
};
for (const [where, initializeClient] of [
  ['initializeClient', noCredentials],
  ['step', async () => ({ step: noCredentials })],
]) {
  test(`negotiateAuth names the principal when ${where} fails`, async () => {
    const kerberos = { GSS_MECH_OID_KRB5: 9, GSS_MECH_OID_SPNEGO: 6, initializeClient };
    const session = negotiateAuth({ kerberos }).start(new URL('http://proxy.test:8080'), 'a.test:443', { passwordState: null });
    const spn = process.platform === 'win32' ? 'HTTP/proxy.test' : 'HTTP@proxy.test';
    await assert.rejects(session.respond(['Negotiate'], true), (error) => {
      assert.equal(error.message, `Negotiate as ${spn} failed: no credentials`);
      assert.equal(error.cause?.message, 'no credentials');
      return true;
    });
  });
}

// A parameter is not a token: a first `Negotiate` that carries one starts the context.
test('negotiateAuth starts a context on a first challenge that carries a parameter alone', async () => {
  for (const challenge of ['Negotiate realm="proxy"', 'Negotiate charset=UTF-8']) {
    const { kerberos, made } = fakeKerberos();
    const session = negotiateAuth({ kerberos }).start(new URL('http://proxy.test:8080'), 'a.test:443', { passwordState: null });
    assert.equal(await session.respond([challenge], true), 'Negotiate first', challenge);
    assert.deepEqual(made[0].client.steps, [''], challenge);
  }
});

// `realm` is read as a parameter of its own, not from inside another one's quoted value.
test('basicAuth reads the realm parameter, not text inside another parameter', async () => {
  const realms = [];
  const auth = basicAuth(({ realm }) => void realms.push(realm));
  for (const challenge of ['Basic charset="realm=evil", realm="corp"', 'Basic realm = "a \\"q\\" b"', 'Basic']) {
    await auth.start(new URL('http://u@proxy.test:8080'), 'a.test:443', { passwordState: null }).respond([challenge], true);
  }
  assert.deepEqual(realms, ['corp', 'a "q" b', null]);
});

// The agent's destroy() ends the requests still connecting and closes their connections.
bounded('http.Agent: destroy() fails a request still waiting on CONNECT and closes it', async () => {
  const silent = await silentProxy();
  const agent = systemProxyAgent({ routes: new FixedRoutes([`http://127.0.0.1:${silent.port}`]) });
  const error = await new Promise((resolve) => {
    https.get(tlsUrl('/agent-destroyed'), { agent }).on('error', resolve);
    silent.reached.then(() => agent.destroy());
  });
  assert.equal(error.code, 'ERR_PROXY_CLOSED');
  const closed = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 1_000).unref())]);
  assert.equal(closed, 'closed');
});

// A request destroyed before it connects fails as on Node's own agent.
bounded('http.Agent: a request destroyed before it connects fails with socket hang up', async () => {
  const silent = await silentProxy();
  const agent = systemProxyAgent({ routes: new FixedRoutes([`http://127.0.0.1:${silent.port}`]) });
  try {
    const error = await new Promise((resolve) => {
      const req = https.get(tlsUrl('/hang-up'), { agent });
      req.on('error', resolve);
      silent.reached.then(() => req.destroy());
    });
    assert.equal(error.code, 'ECONNRESET');
    assert.equal(error.message, 'socket hang up');
    const closed = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 1_000).unref())]);
    assert.equal(closed, 'closed');
  } finally {
    agent.destroy();
  }
});

// The caller's error to destroy() is the request's, however early it comes.
bounded('http.Agent: a request destroyed with an error before its route is read fails with it', async () => {
  const agent = systemProxyAgent({ routes: new FixedRoutes(['direct']) });
  const mine = new Error('mine');
  try {
    const error = await new Promise((resolve) => {
      const req = http.get(`http://127.0.0.1:${plainPort}/early`, { agent });
      req.on('error', resolve);
      req.destroy(mine);
    });
    assert.equal(error, mine);
  } finally {
    agent.destroy();
  }
});

// A method the caller wraps after making the request stays wrapped once it has a socket.
bounded('http.Agent: a destroy() the caller wrapped stays in place after the socket comes', async () => {
  const agent = systemProxyAgent({ routes: new FixedRoutes(['direct']) });
  try {
    let wrapped = 0;
    const req = http.get(`http://127.0.0.1:${plainPort}/wrapped`, { agent });
    const original = req.destroy;
    const wrapper = function (...args) {
      wrapped += 1;
      return original.apply(this, args);
    };
    req.destroy = wrapper;
    await once(req, 'response');
    assert.equal(req.destroy, wrapper);
    req.destroy();
    assert.equal(wrapped, 1);
  } finally {
    agent.destroy();
  }
});

// A URL cannot keep an empty password apart from none, and the settings can: `alice:@` is an
// empty password, which goes as `alice:`, and `alice@` none, which sends nothing.
for (const [client, send] of [
  [
    'http.Agent',
    async (env, target) => {
      const agent = systemProxyAgent({ env, precedence: 'before-system', watch: false });
      try {
        return await new Promise((resolve, reject) =>
          (target.startsWith('https:') ? https : http)
            .get(target, { agent, rejectUnauthorized: false }, (res) => res.resume().on('end', resolve))
            .on('error', reject),
        );
      } finally {
        agent.destroy();
      }
    },
  ],
  [
    'fetch',
    async (env, target) => {
      const dispatcher = new SystemProxyDispatcher({ env, precedence: 'before-system', watch: false, requestTls: { rejectUnauthorized: false } });
      try {
        await (await request(target, { dispatcher })).body.text();
      } finally {
        await dispatcher.destroy();
      }
    },
  ],
]) {
  for (const [userinfo, expected] of [
    ['alice:@', 'Basic YWxpY2U6'],
    ['alice@', undefined],
  ]) {
    bounded(`${client}: a proxy URL with ${userinfo} sends ${expected ? 'an empty password' : 'no Basic'}`, async () => {
      const proxy = await scriptedProxy(() => 'ok');
      const step = proxy.url.replace('user:pass@', userinfo);
      await send({ http_proxy: step, https_proxy: step }, `http://origin.test:${plainPort}/empty-password`);
      await send({ http_proxy: step, https_proxy: step }, tlsUrl('/empty-password'));
      assert.deepEqual(
        proxy.seen.map(([, method, authorization]) => [method, authorization]),
        [
          ['GET', expected],
          ['CONNECT', expected],
        ],
      );
    });
  }
}

// A request that fails without a socket closes without destroy(); its timeout ends with it.
bounded('http.Agent: a request whose proxy refuses it emits no timeout after it closes', async () => {
  const dead = await listen(net.createServer());
  const port = dead.address().port;
  await new Promise((resolve) => dead.close(resolve));
  const agent = systemProxyAgent({ routes: new FixedRoutes([`http://127.0.0.1:${port}`]) });
  const events = [];
  try {
    await new Promise((resolve) => {
      const req = https.get(tlsUrl('/refused'), { agent, timeout: 300 });
      req.on('timeout', () => events.push('timeout'));
      req.on('error', () => events.push('error'));
      req.on('close', () => {
        events.push('close');
        resolve();
      });
    });
    await new Promise((r) => setTimeout(r, 500));
  } finally {
    agent.destroy();
  }
  assert.deepEqual(events, ['error', 'close']);
});

// The request's `signal` destroys it from inside Node; that too closes the connection the
// agent was opening.
bounded('http.Agent: aborting the request signal closes a CONNECT still waiting on the proxy', async () => {
  const silent = await silentProxy();
  const agent = systemProxyAgent({ routes: new FixedRoutes([`http://127.0.0.1:${silent.port}`]) });
  const controller = new AbortController();
  try {
    const error = await new Promise((resolve) => {
      https.get(tlsUrl('/signal'), { agent, signal: controller.signal }).on('error', resolve);
      silent.reached.then(() => controller.abort());
    });
    assert.equal(error.name, 'AbortError');
    const closed = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 2_000).unref())]);
    assert.equal(closed, 'closed');
  } finally {
    agent.destroy();
  }
});

// A `signal` that has already aborted fails the request with Node's `AbortError`, its reason
// as the cause, before the route is read.
bounded('http.Agent: a signal already aborted fails the request before its route is read', async () => {
  const routes = new FixedRoutes(['direct']);
  let read = 0;
  routes.route = async () => (read += 1, routes.fixed);
  const agent = systemProxyAgent({ routes });
  const controller = new AbortController();
  controller.abort('gone');
  try {
    const error = await new Promise((resolve) =>
      http.get(`http://127.0.0.1:${plainPort}/`, { agent, signal: controller.signal }).on('error', resolve),
    );
    assert.equal(error.name, 'AbortError');
    assert.equal(error.cause, 'gone');
    assert.equal(read, 0);
  } finally {
    agent.destroy();
  }
});

// The queue's size stays the sum of what is queued when the agent rewrites the request and
// puts it back, for write()'s backpressure.
for (const [what, write] of [
  ['a string', (req) => req.write('abc')],
  ['a Buffer', (req) => req.write(Buffer.from('abc'))],
  ['Expect', () => {}],
]) {
  test(`a request rewritten and put back keeps its queued size, after ${what}`, () => {
    const req = http.request({ host: 'a.test', path: '/q', method: 'POST', agent: { addRequest() {} }, headers: what === 'Expect' ? { expect: '100-continue' } : {} });
    req.on('error', () => {});
    write(req);
    const saved = saveRequest(req);
    rewriteHeader(req, () => {
      req.path = 'http://a.test/q';
      req.setHeader('Proxy-Authorization', 'Basic eDp5');
    });
    restoreRequest(req, saved);
    const queued = req.outputData.reduce((sum, entry) => sum + entry.data.length, 0);
    assert.equal(req.outputSize, queued);
    assert.doesNotMatch(req.outputData.map((entry) => String(entry.data)).join(''), /proxy-|http:\/\//i);
    req.destroy();
  });
}

// The SOCKS agent hands back a TLS socket before its handshake; a handshake that stalls is
// held to connectTimeout like the rest of the step.
// A connection of every kind of step, as the last step and before it, waits idle for 5 s
// at most once its response ends. The agent here sets no `timeout`.
bounded('http.Agent: an idle connection of every kind of step waits 5 s', async () => {
  const proxy = await scriptedProxy(() => 'ok');
  // The scripted proxy closes a forwarded request's connection; this one keeps it.
  const forwarding = await listen(
    http.createServer((req, res) => {
      http.get(req.url.replace('origin.test', '127.0.0.1'), (answer) => {
        const chunks = [];
        answer.on('data', (chunk) => chunks.push(chunk));
        answer.on('end', () => res.end(Buffer.concat(chunks)));
      });
    }),
  );
  servers.push(forwarding);
  const socksPlain = await socks5Proxy(plainPort);
  const socksTls = await socks5Proxy(tlsPort);
  const next = await scriptedProxy(() => 'ok');
  const plain = `http://origin.test:${plainPort}/idle`;
  const cases = [
    ['direct http:', 'direct', `http://127.0.0.1:${plainPort}/idle`],
    ['direct https:', 'direct', `https://127.0.0.1:${tlsPort}/idle`],
    ['forward', `http://127.0.0.1:${forwarding.address().port}`, plain],
    ['CONNECT', proxy.url, tlsUrl('/idle')],
    ['SOCKS http:', `socks5h://u:p@127.0.0.1:${socksPlain.port}`, plain],
    ['SOCKS https:', `socks5h://u:p@127.0.0.1:${socksTls.port}`, tlsUrl('/idle')],
  ];
  for (const [kind, step, target] of cases) {
    for (const steps of [[step], [step, next.url]]) {
      const agent = systemProxyAgent({ routes: new FixedRoutes(steps) });
      try {
        const socket = await new Promise((resolve, reject) =>
          (target.startsWith('https:') ? https : http)
            .get(target, { agent, rejectUnauthorized: false }, (res) => {
              const { socket } = res;
              res.resume();
              res.on('end', () => setImmediate(() => resolve(socket)));
            })
            .on('error', reject),
        );
        assert.equal(socket.timeout, 5_000, `${kind}, ${steps.length} step(s)`);
      } finally {
        agent.destroy();
      }
    }
  }
  assert.deepEqual(next.seen, []);
});

for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: a TLS handshake that stalls behind a SOCKS step hands the request on`, async () => {
    const silent = await silentProxy();
    const socks = await socks5Proxy(silent.port);
    const next = await scriptedProxy(() => 'ok');
    const steps = [`socks5h://u:p@127.0.0.1:${socks.port}`, next.url];
    assert.equal(await via(steps, { connectTimeout: 300 }, tlsUrl('/socks-tls')), 'origin saw /socks-tls');
    assert.equal(next.seen.length, 1);
    const outcome = await Promise.race([silent.closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('open'), 2_000).unref())]);
    assert.equal(outcome, 'closed');
  });
}

bounded('http.Agent: a CONNECT names an IPv6 destination without its zone id', async () => {
  const proxy = await scriptedProxy(() => 'ok');
  const agent = systemProxyAgent({ routes: new FixedRoutes([proxy.url]) });
  try {
    await new Promise((resolve) =>
      https
        .get({ agent, host: 'fe80::1%lo', port: 9, path: '/zone', rejectUnauthorized: false }, (res) => res.resume().on('end', resolve))
        .on('error', resolve),
    );
  } finally {
    agent.destroy();
  }
  assert.deepEqual(proxy.targets, [['[fe80::1]:9', '[fe80::1]:9']]);
});

// A request under way on an agent of older settings is one that agent's `destroy()` no
// longer reaches: `close()` has taken its connections.
bounded('fetch: destroy() ends a request still on the agent of older settings', async () => {
  const hanging = await listen(net.createServer((socket) => sockets.add(socket)));
  servers.push(hanging);
  const routes = new FixedRoutes(['direct']);
  const dispatcher = new SystemProxyDispatcher({ routes });
  const reached = once(hanging, 'connection');
  const pending = request(`http://127.0.0.1:${hanging.address().port}/never`, { dispatcher });
  pending.catch(() => {});
  await reached;
  routes.generation += 1;
  await (await request(`http://127.0.0.1:${plainPort}/newer`, { dispatcher })).body.text();
  const closed = dispatcher.close();
  await dispatcher.destroy();
  await assert.rejects(pending);
  const outcome = await Promise.race([closed.then(() => 'closed'), new Promise((r) => setTimeout(() => r('pending'), 2_000).unref())]);
  assert.equal(outcome, 'closed');
});

// One header can list several challenges, and a comma inside a challenge separates its
// parameters (RFC 9110 §11.6.1); `respond` gets one challenge per element.
bounded('a Proxy-Authenticate that lists several challenges reaches respond one by one', async () => {
  const listed = 'Basic realm="a, b", Negotiate abc==, NTLM, Digest realm=x, nonce="n"';
  const proxy = await rawProxy([`HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: ${listed}\r\nProxy-Authenticate: Token\r\nContent-Length: 0\r\n\r\n`]);
  const given = [];
  const auth = { start: () => ({ respond: async (challenges) => void given.push(challenges) }) };
  await assert.rejects(openTunnel({ proxy: proxy.url, host: 'a.test', port: 443, auth }), refused(407));
  assert.deepEqual(given, [['Basic realm="a, b"', 'Negotiate abc==', 'NTLM', 'Digest realm=x, nonce="n"', 'Token']]);
});

bounded('basicAuth reads a realm given as a token', async () => {
  const proxy = await rawProxy(['HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate, Basic realm=corp\r\nContent-Length: 0\r\n\r\n']);
  const realms = [];
  const auth = basicAuth(({ realm }) => void realms.push(realm));
  await assert.rejects(openTunnel({ proxy: proxy.url, host: 'a.test', port: 443, auth }), refused(407));
  assert.deepEqual(realms, ['corp']);
});

// Basic cannot carry a `:` in the user name; the proxy would read the rest as the password.
bounded('a proxy URL whose user name decodes to a colon sends no Basic', async () => {
  const proxy = await rawProxy(['HTTP/1.1 200 OK\r\n\r\n']);
  const url = new URL(proxy.url);
  url.username = 'us%3Aer';
  url.password = 'pw';
  await assert.rejects(openTunnel({ proxy: url, host: 'a.test', port: 443 }), TypeError);
});

// The settings can change while a route is computed; a route the older snapshot could not
// give is read again from the newer one.
test('Routes.resolve reads a failed route again after a change', async () => {
  const routes = new FixedRoutes(['direct']);
  let calls = 0;
  routes.route = async () => {
    calls += 1;
    if (calls === 1) {
      routes.generation += 1;
      return { kind: 'pac', url: 'http://pac.test/' };
    }
    return routes.fixed;
  };
  assert.deepEqual(await routes.resolve('http://a.test/', () => true), { steps: ['direct'], generation: 1 });
});

// A request whose origin does not parse fails through its handler and is not counted as
// under way, so `close()` does not wait on it.
bounded('fetch: a request with no usable origin fails without holding close()', async () => {
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes(['direct']) });
  await assert.rejects(dispatcher.request({ path: '/x', method: 'GET' }), TypeError);
  const outcome = await Promise.race([dispatcher.close().then(() => 'closed'), new Promise((r) => setTimeout(() => r('pending'), 2_000).unref())]);
  assert.equal(outcome, 'closed');
});

bounded('fetch: the dispatcher passes on the hooks undici calls only where a handler has them', async () => {
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes(['direct']) });
  const called = new Set();
  await new Promise((resolve, reject) => {
    dispatcher.dispatch(
      { origin: `http://127.0.0.1:${plainPort}`, path: '/hooks', method: 'POST', body: 'x' },
      {
        onRequestStart() {},
        onRequestSent: () => called.add('onRequestSent'),
        onBodySent: () => called.add('onBodySent'),
        onResponseStarted: () => called.add('onResponseStarted'),
        onResponseStart() {},
        onResponseData() {},
        onResponseEnd: resolve,
        onResponseError: (_, error) => reject(error),
      },
    );
  });
  await dispatcher.close();
  assert.deepEqual([...called].sort(), ['onBodySent', 'onRequestSent', 'onResponseStarted']);
});

// A legacy handler may leave out `onHeaders` and `onError`; it is still given the response.
bounded('fetch: a legacy handler with only onData and onComplete is given the body', async () => {
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes(['direct']) });
  const chunks = [];
  await new Promise((resolve) => {
    dispatcher.dispatch(
      { origin: `http://127.0.0.1:${plainPort}`, path: '/legacy', method: 'GET' },
      { onConnect() {}, onData: (chunk) => void chunks.push(chunk), onComplete: resolve },
    );
  });
  await dispatcher.close();
  assert.equal(Buffer.concat(chunks).toString(), 'origin saw /legacy');
});

// A request's own `Proxy-Authorization` is refused before any step: past a proxy that cannot
// be reached, the next step is the origin. The same request without it reaches the origin.
for (const [form, headers] of [
  ['an object', { 'Proxy-Authorization': 'Basic c2VjcmV0' }],
  ['an array', ['proxy-authorization', 'Basic c2VjcmV0']],
]) {
  // Node adds no `Host` to headers given as an array; the control names it.
  bounded(`http.Agent: a Proxy-Authorization set on the request as ${form} is refused`, async () => {
    const agent = systemProxyAgent({ routes: new FixedRoutes(['http://127.0.0.1:9', 'direct']) });
    const get = (headers) =>
      new Promise((resolve, reject) => {
        http
          .get({ host: '127.0.0.1', port: plainPort, path: '/pa', agent, headers }, (res) => {
            res.setEncoding('utf8');
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => resolve(body));
          })
          .on('error', reject);
      });
    const seen = originSeen.length;
    await assert.rejects(get(headers), { code: 'ERR_INVALID_ARG_VALUE' });
    assert.equal(originSeen.length, seen);
    assert.equal(await get(Array.isArray(headers) ? ['host', `127.0.0.1:${plainPort}`] : { 'X-Other': 'a' }), 'origin saw /pa');
    agent.destroy();
  });
}

for (const [form, headers] of [
  ['an object', { 'proxy-authorization': 'Basic c2VjcmV0' }],
  ['an array', ['Proxy-Authorization', 'Basic c2VjcmV0']],
  ['a Map', new Map([['Proxy-Authorization', 'Basic c2VjcmV0']])],
]) {
  bounded(`fetch: a Proxy-Authorization set on the request as ${form} is refused`, async () => {
    const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes(['http://127.0.0.1:9', 'direct']) });
    const url = `http://127.0.0.1:${plainPort}/pa`;
    const seen = originSeen.length;
    await assert.rejects(request(url, { dispatcher, headers }), { code: 'ERR_INVALID_ARG_VALUE' });
    assert.equal(originSeen.length, seen);
    const other = headers instanceof Map ? new Map([['x-other', 'a']]) : { 'x-other': 'a' };
    assert.equal(await (await request(url, { dispatcher, headers: other })).body.text(), 'origin saw /pa');
    await dispatcher.close();
  });
}

// The error given to `destroy()` is the one a request under way fails with.
bounded('fetch: destroy(error) fails a request still waiting on CONNECT with that error', async () => {
  const silent = await silentProxy();
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes([`http://127.0.0.1:${silent.port}`]), connectTimeout: 5_000 });
  const pending = request(tlsUrl('/destroyed-with'), { dispatcher });
  pending.catch(() => {});
  await silent.reached;
  const mine = new Error('mine');
  await dispatcher.destroy(mine);
  await assert.rejects(pending, (error) => error === mine || error.cause === mine);
});

// A destination on its scheme's default port is named without it, as a browser hands it to
// a PAC script and as a forwarding proxy is given it.
bounded('http.Agent: a destination on port 80 is routed and forwarded without the port', async () => {
  const proxy = await scriptedProxy(() => 'ok');
  const routes = new RecordingRoutes([proxy.url]);
  const agent = systemProxyAgent({ routes });
  try {
    // The proxy here forwards to 127.0.0.1:80, where nothing need listen: only what it was
    // asked for is checked.
    await new Promise((resolve) =>
      http.get({ agent, host: 'origin.test', port: 80, path: '/default-port' }, (res) => res.resume().on('end', resolve)).on('error', resolve),
    );
  } finally {
    agent.destroy();
  }
  assert.deepEqual(routes.urls, ['http://origin.test/default-port']);
  assert.equal(proxy.targets[0]?.[0], 'http://origin.test/default-port');
});

// A `lookup` that resolves every name to 127.0.0.1 and records the names it was asked for.
function recordingLookup() {
  const names = [];
  const lookup = (hostname, options, callback) => {
    names.push(hostname);
    if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
    else callback(null, '127.0.0.1', 4);
  };
  return { names, lookup };
}

// The agent's socket options reach its connection to a proxy of every kind, as they reach a
// direct one. `proxy.test` resolves through the agent's `lookup` alone.
bounded('http.Agent: lookup resolves the name of a proxy of every kind', async () => {
  const plainProxy = await scriptedProxy(() => 'ok');
  const secureProxy = await scriptedProxy(() => 'ok', { secure: true });
  const socks = await socks5Proxy();
  const named = (url) => url.replace('127.0.0.1', 'proxy.test');
  const socksStep = `socks5h://u:p@proxy.test:${socks.port}`;
  const plain = (path) => `http://origin.test:${plainPort}${path}`;
  const cases = [
    ['CONNECT', [named(plainProxy.url)], {}, tlsUrl('/lookup-connect')],
    ['forwarded', [named(plainProxy.url)], {}, plain('/lookup-forward')],
    ['https: proxy', [named(secureProxy.url)], { proxyTls: trustProxyOnly(secureProxy.cert) }, tlsUrl('/lookup-secure')],
    ['SOCKS', [socksStep], {}, plain('/lookup-socks')],
    // A SOCKS step before the last is probed first; a probe that cannot resolve the name
    // would hand the request to the direct step.
    ['SOCKS probe', [socksStep, 'direct'], {}, plain('/lookup-probe')],
  ];
  for (const [kind, steps, options, target] of cases) {
    const { names, lookup } = recordingLookup();
    const path = new URL(target).pathname;
    assert.equal(await viaAgent(steps, { lookup, ...options }, target), `origin saw ${path}`, kind);
    assert.ok(names.includes('proxy.test'), `${kind}: ${JSON.stringify(names)}`);
  }
  assert.equal(socks.credentials.length, 2);
});

// `socketOptions` is the SOCKS client's own option for its connection to the proxy. The probe
// of a SOCKS step before the last connects to the same proxy, and takes it too: a probe that
// cannot resolve `proxy.test` would hand the request to the direct step.
bounded('http.Agent: the probe of a SOCKS step takes socketOptions, as its connection does', async () => {
  const socks = await socks5Proxy();
  const { names, lookup } = recordingLookup();
  const target = `http://origin.test:${plainPort}/socket-options-probe`;
  const steps = [`socks5h://u:p@proxy.test:${socks.port}`, 'direct'];
  assert.equal(await viaAgent(steps, { socketOptions: { lookup } }, target), 'origin saw /socket-options-probe');
  assert.ok(names.includes('proxy.test'), JSON.stringify(names));
  assert.equal(socks.credentials.length, 1);
});

// 192.0.2.1 (TEST-NET-1) is no address of this machine: a connection made from it fails.
bounded('http.Agent: localAddress reaches the connection to a proxy of every kind', async () => {
  const plainProxy = await scriptedProxy(() => 'ok');
  const secureProxy = await scriptedProxy(() => 'ok', { secure: true });
  const socks = await socks5Proxy();
  const plain = `http://origin.test:${plainPort}/local-address`;
  const cases = [
    ['CONNECT', plainProxy.url, {}, tlsUrl('/local-address')],
    ['forwarded', plainProxy.url, {}, plain],
    ['https: proxy', secureProxy.url, { proxyTls: trustProxyOnly(secureProxy.cert) }, tlsUrl('/local-address')],
    ['SOCKS', `socks5h://u:p@127.0.0.1:${socks.port}`, {}, plain],
  ];
  for (const [kind, step, options, target] of cases) {
    await assert.rejects(viaAgent([step], { localAddress: '192.0.2.1', ...options }, target), (error) => {
      assert.match(`${error.code} ${error.message}`, /EADDRNOTAVAIL|address/i, kind);
      return true;
    });
  }
  assert.deepEqual([plainProxy.seen, secureProxy.seen, socks.credentials], [[], [], []]);
});

// A destination named by an IP address has its certificate checked against that address. The
// socket under the destination's TLS is the proxy's, so a check that falls back to the
// socket's host checks the proxy's name instead. Every proxy here connects 192.0.2.1 to the
// origin at 127.0.0.1.
const withRequestTls = [
  ['http.Agent', (steps, options, target, tls) => viaAgent(steps, options, target, tls)],
  ['fetch', (steps, options, target, tls) => viaFetch(steps, { ...options, requestTls: tls }, target)],
];

for (const [client, via] of withRequestTls) {
  bounded(`${client}: the certificate of an IP destination is checked against the IP, through every proxy`, async () => {
    const plainProxy = await scriptedProxy(() => 'ok');
    const secureProxy = await scriptedProxy(() => 'ok', { secure: true });
    const socks = await socks5Proxy(tlsPort);
    const target = `https://192.0.2.1:${tlsPort}/ip-identity`;
    const cases = [
      ['CONNECT', plainProxy.url, {}],
      ['https: proxy', secureProxy.url, { proxyTls: trustProxyOnly(secureProxy.cert) }],
      ['SOCKS', `socks5h://u:p@127.0.0.1:${socks.port}`, {}],
    ];
    for (const [kind, step, options] of cases) {
      const names = [];
      const checkServerIdentity = (name) => void names.push(name);
      assert.equal(await via([step], options, target, { ca: originCert, checkServerIdentity }), 'origin saw /ip-identity', kind);
      assert.deepEqual(names, ['192.0.2.1'], kind);
    }
  });
}

// The same with Node's own check: a certificate for the destination's address passes, and one
// for the proxy's (127.0.0.1) fails. A certificate error is no connection error: on a step
// before the last it fails the request, where the next step would go around the check.
for (const [client, via] of withRequestTls) {
  bounded(`${client}: a certificate for the proxy's address fails an IP destination, without the next step`, async () => {
    const origin = async (ip) => {
      const { key, cert } = selfSigned('origin', { ips: [ip] });
      const server = await listen(https.createServer({ key, cert }, (req, res) => res.end(`origin saw ${req.url}`)));
      servers.push(server);
      return { port: server.address().port, cert };
    };
    const next = await scriptedProxy(() => 'ok');
    for (const [ip, passes] of [['192.0.2.1', true], ['127.0.0.1', false]]) {
      const { port, cert } = await origin(ip);
      const plainProxy = await scriptedProxy(() => 'ok');
      const secureProxy = await scriptedProxy(() => 'ok', { secure: true });
      const socks = await socks5Proxy(port);
      const target = `https://192.0.2.1:${port}/ip-check`;
      const cases = [
        ['CONNECT', plainProxy.url, {}],
        ['https: proxy', secureProxy.url, { proxyTls: trustProxyOnly(secureProxy.cert) }],
        ['SOCKS', `socks5h://u:p@127.0.0.1:${socks.port}`, {}],
      ];
      for (const [kind, step, options] of cases) {
        // As a step before the last and as the last.
        for (const steps of [[step, next.url], [step]]) {
          const reached = via(steps, options, target, { ca: cert });
          if (passes) {
            assert.equal(await reached, 'origin saw /ip-check', kind);
          } else {
            await assert.rejects(reached, (error) => {
              assert.match(`${error.code} ${error.cause?.code}`, /ERR_TLS_CERT_ALTNAME_INVALID/, `${kind} ${steps.length}`);
              return true;
            });
          }
        }
      }
    }
    assert.deepEqual(next.seen, []);
  });
}

// A destination that closes the connection during the TLS handshake through a SOCKS step
// before the last is a lost connection, as through a CONNECT step: the request goes to the
// next step.
for (const [client, via] of [
  ['http.Agent', (steps, target) => viaAgent(steps, {}, target, { ca: originCert })],
  ['fetch', (steps, target) => viaFetch(steps, {}, target)],
]) {
  bounded(`${client}: a handshake the destination resets through a SOCKS step hands the request on`, async () => {
    const resetting = await listen(
      net.createServer((socket) => {
        sockets.add(socket);
        socket.on('error', () => {});
        socket.once('data', () => socket.resetAndDestroy());
      }),
    );
    servers.push(resetting);
    const first = await socks5Proxy(resetting.address().port);
    const second = await socks5Proxy(tlsPort);
    const steps = [`socks5h://u:p@127.0.0.1:${first.port}`, `socks5h://u:p@127.0.0.1:${second.port}`];
    assert.equal(await via(steps, tlsUrl('/reset-handshake')), 'origin saw /reset-handshake');
    assert.deepEqual([first.credentials.length, second.credentials.length], [1, 1]);
  });
}

// A request to a `socketPath` goes to that local socket whatever the route: its URL names
// `localhost`, and a proxy would take it there.
// No route is read for it, so it may carry its own Proxy-Authorization.
bounded('http.Agent: a request to a socketPath goes to the local socket, past every proxy', async () => {
  const name = `node-http-ipc-${process.pid}`;
  const path = process.platform === 'win32' ? join('\\\\?\\pipe', name) : join(tmpdir(), `${name}.sock`);
  const local = http.createServer((req, res) => res.end(`local saw ${req.url}`));
  await new Promise((resolve) => local.listen(path, resolve));
  servers.push(local);
  const proxy = await scriptedProxy(() => 'ok');
  for (const steps of [[proxy.url], [proxy.url, 'direct'], ['direct', proxy.url]]) {
    const agent = systemProxyAgent({ routes: new FixedRoutes(steps) });
    try {
      const text = await new Promise((resolve, reject) =>
        http
          .get({ socketPath: path, path: '/ipc', agent, headers: { 'Proxy-Authorization': 'Basic eDp5' } }, (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => resolve(body));
          })
          .on('error', reject),
      );
      assert.equal(text, 'local saw /ipc', steps.join(' '));
    } finally {
      agent.destroy();
    }
  }
  assert.deepEqual(proxy.seen, []);
});

// The agent's `timeout` reaches a new connection through a proxy, as Node's agent sets it on
// one it opens: an answer that never comes times the request out.
bounded('http.Agent: the agent timeout reaches a new connection through each kind of step', async () => {
  const mute = await listen(
    net.createServer((socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
    }),
  );
  servers.push(mute);
  const port = mute.address().port;
  const forward = await scriptedProxy(() => 'ok');
  const socks = await socks5Proxy(port);
  const cases = [
    [[forward.url], `http://origin.test:${port}/forward`],
    [[forward.url, 'direct'], `http://origin.test:${port}/forward-first`],
    [[`socks5h://u:p@127.0.0.1:${socks.port}`], `http://origin.test:${port}/socks`],
    [[`socks5h://u:p@127.0.0.1:${socks.port}`, 'direct'], `http://origin.test:${port}/socks-first`],
  ];
  for (const [steps, target] of cases) {
    const agent = systemProxyAgent({ routes: new FixedRoutes(steps), timeout: 200 });
    try {
      const outcome = await new Promise((resolve) => {
        const req = http.get(target, { agent });
        req.on('timeout', () => {
          resolve('timeout');
          req.destroy();
        });
        req.on('error', () => {});
        req.on('response', () => resolve('response'));
        setTimeout(() => resolve('no timeout'), 2_000).unref();
      });
      assert.equal(outcome, 'timeout', steps.join(' '));
    } finally {
      agent.destroy();
    }
  }
});

// A header the proxy names after a property of a plain object is read as any other header.
bounded('openTunnel reads a refusal whose headers are named after object properties', async () => {
  const proxy = await listen(
    net.createServer((client) => {
      sockets.add(client);
      client.on('error', () => {});
      client.once('data', () =>
        client.end(
          'HTTP/1.1 403 Forbidden\r\nConstructor: a\r\n__proto__: b\r\ntoString: c\r\nContent-Length: 0\r\n\r\n',
        ),
      );
    }),
  );
  servers.push(proxy);
  await assert.rejects(
    openTunnel({ proxy: new URL(`http://127.0.0.1:${proxy.address().port}`), host: 'a.test', port: 443, timeout: 3_000 }),
    (error) => {
      assert.ok(error instanceof ProxyTunnelError, `${error?.name}: ${error?.message}`);
      assert.equal(error.statusCode, 403);
      assert.deepEqual(
        [error.headers.constructor, error.headers.__proto__, error.headers.tostring],
        [['a'], ['b'], ['c']],
      );
      return true;
    },
  );
});

// destroy() ends a request still queued behind a busy connection with the same reason as the
// one under way.
bounded('fetch: destroy() fails a queued request with ERR_PROXY_CLOSED too', async () => {
  const slow = await listen(http.createServer((req, res) => setTimeout(() => res.end('late'), 1_000)));
  servers.push(slow);
  const target = `http://127.0.0.1:${slow.address().port}/`;
  const dispatcher = new SystemProxyDispatcher({ routes: new FixedRoutes(['direct']), connections: 1 });
  const code = (pending) => pending.then(() => 'answered', (error) => error.code ?? error.cause?.code);
  const started = code(request(target, { dispatcher }));
  const queued = code(request(target, { dispatcher }));
  await new Promise((resolve) => setTimeout(resolve, 200));
  await dispatcher.destroy();
  assert.deepEqual([await started, await queued], ['ERR_PROXY_CLOSED', 'ERR_PROXY_CLOSED']);
});

// The 64 KiB limit on a proxy's answer head holds when its end comes in the same read. The
// head ends 4 bytes past the limit, so the read that brings the excess brings the end too.
bounded('openTunnel fails an answer head over 64 KiB that arrives whole', async () => {
  const proxy = await listen(
    net.createServer((client) => {
      sockets.add(client);
      client.on('error', () => {});
      client.once('data', () =>
        client.write(`HTTP/1.1 200 Connection Established\r\nX-Pad: ${'a'.repeat(65_496)}\r\n\r\n`),
      );
    }),
  );
  servers.push(proxy);
  await assert.rejects(
    openTunnel({ proxy: new URL(`http://127.0.0.1:${proxy.address().port}`), host: 'a.test', port: 443, timeout: 3_000 }),
    /head too long/,
  );
});

// A SOCKS step whose proxy refuses the connection hands the request on, for `http:` and
// `https:`: the SOCKS client's own errors carry no code a refused connection is told by.
for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  for (const [scheme, target] of [
    ['http:', () => `http://origin.test:${plainPort}/dead-socks`],
    ['https:', () => tlsUrl('/dead-socks')],
  ]) {
    bounded(`${client}: a SOCKS step that refuses the connection hands an ${scheme} request on`, async () => {
      const next = await scriptedProxy(() => 'ok');
      const text = await via(['socks5h://127.0.0.1:1', next.url], {}, target());
      assert.match(text, /saw \/dead-socks$/);
      assert.equal(next.targets.length, 1);
    });
  }
}

// A SOCKS proxy that closes the connection during its handshake, with a FIN or a reset,
// hands the request on, as a refused connection does: none of the request is written yet. A
// proxy that answers the request with a refusal keeps it. `fetch` notices a FIN only at
// `connectTimeout`: undici's SOCKS5 client settles on an error alone.
for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  bounded(`${client}: a SOCKS proxy that closes during its handshake hands the request on`, async () => {
    for (const close of [(socket) => socket.end(), (socket) => socket.resetAndDestroy()]) {
      const proxy = await listen(
        net.createServer((socket) => {
          sockets.add(socket);
          socket.on('error', () => {});
          socket.once('data', () => close(socket));
        }),
      );
      servers.push(proxy);
      const next = await scriptedProxy(() => 'ok');
      const step = `socks5h://127.0.0.1:${proxy.address().port}`;
      const text = await via([step, next.url], { connectTimeout: 1_000 }, `http://origin.test:${plainPort}/socks-closed`);
      assert.equal(text, 'origin saw /socks-closed');
      assert.equal(next.targets.length, 1);
    }
  });

  bounded(`${client}: a SOCKS proxy's refusal stays with its step`, async () => {
    const proxy = await listen(
      net.createServer((socket) => {
        sockets.add(socket);
        socket.on('error', () => {});
        socket.once('data', () => {
          socket.write(Buffer.from([5, 0]));
          socket.once('data', () => socket.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])));
        });
      }),
    );
    servers.push(proxy);
    const next = await scriptedProxy(() => 'ok');
    const step = `socks5h://127.0.0.1:${proxy.address().port}`;
    await assert.rejects(via([step, next.url], {}, `http://origin.test:${plainPort}/socks-refused`), /refused/i);
    assert.equal(next.targets.length, 0);
  });
}

// Each code of a failed connection hands the request on, read wherever the connection raises
// it. The classification reads the code alone; the lookup of `dead.test` is a place to raise
// each one on demand.
const CONNECT_CODES = [
  'ECONNREFUSED',
  'ECONNRESET',
  'ECONNABORTED',
  'EHOSTUNREACH',
  'EHOSTDOWN',
  'ENETUNREACH',
  'ENETDOWN',
  'ENOTFOUND',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'EAI_FAIL',
];
for (const [client, via] of [
  ['http.Agent', viaAgent],
  ['fetch', viaFetch],
]) {
  for (const [scheme, target] of [
    ['http:', () => `http://origin.test:${plainPort}/dead-code`],
    ['https:', () => tlsUrl('/dead-code')],
  ]) {
    bounded(`${client}: each connect error code of a step hands an ${scheme} request on`, async (t) => {
      const lookup = dns.lookup;
      let code;
      t.mock.method(dns, 'lookup', (hostname, options, callback) => {
        if (hostname !== 'dead.test') return lookup(hostname, options, callback);
        const cb = typeof options === 'function' ? options : callback;
        process.nextTick(cb, Object.assign(new Error(`getaddrinfo ${code} ${hostname}`), { code, hostname }));
      });
      for (code of CONNECT_CODES) {
        const next = await scriptedProxy(() => 'ok');
        const text = await via(['http://dead.test:9', next.url], {}, target());
        assert.match(text, /saw \/dead-code$/, code);
        assert.equal(next.targets.length, 1, code);
      }
    });
  }
}
