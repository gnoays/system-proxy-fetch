// An http.Agent for the `http` and `https` modules that sends each request where the
// operating system would. It owns no socket: every request goes to the agent of its route's
// first step, which pools its own connections.
//
// A step agent that fails to open a connection for a step before the last with a code in
// `CONNECT_CODES` hands the request to the next step's agent from its `connect()`: nothing
// of the request is written yet, so a stream body moves on too. A certificate error and a
// proxy's refusal of CONNECT stay with the step, and a failure on a pooled connection fails
// the request. A forwarded `http:` request is rewritten for the proxy and put back when its
// step fails. A SOCKS step before the last is probed first: the SOCKS client's errors carry
// no `code` to tell a refused connection by. A connection to the SOCKS proxy that closes or
// fails during the handshake is given the code of that failure; a refusal the proxy answers
// stays with the step.
//
// `maxSockets` and `maxTotalSockets` are refused: agent-base counts a request against the
// limit while it connects, and a request handed on to another agent gives its place back
// without a socket of this agent's freeing, so nothing starts the requests queued behind
// it and they would wait for ever.

import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { once } from 'node:events';
import { Agent, type AgentConnectOpts } from 'agent-base';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { basicCredentials, withValidEscapes, type ProxyAuth } from './auth.mjs';
import {
  Routes,
  checkRoutesAlone,
  checkTimeout,
  isConnectError,
  isWebSocket,
  requestUrl,
  schemeOf,
  splitRoutesOptions,
  type PasswordState,
  type RoutesOptions,
} from './core.mjs';
import {
  hasProxyAuthorization,
  proxyAuthorizationError,
  restoreRequest,
  rewriteHeader,
  saveRequest,
  untilSocket,
  upgradeHeader,
  type SavedRequest,
} from './request.mjs';
import { dialProxy, openTunnel, proxySocketOptions, secureTunnel, type ProxySocketOptions } from './tunnel.mjs';

export { RouteError, Routes } from './core.mjs';
export type { PasswordState, RoutesOptions } from './core.mjs';
export {
  basicAuth,
  negotiateAuth,
  type BasicAuthRequest,
  type BasicCredentials,
  type NegotiateAuthOptions,
  type KerberosClient,
  type KerberosModule,
  type NegotiateMechanism,
  type ProxyAuth,
  type ProxyAuthContext,
  type ProxyAuthSession,
} from './auth.mjs';
export { ProxyTunnelError } from './tunnel.mjs';

/** The `Routes` options, this package's own, and the rest of `https.Agent`'s, which go to
 * each step's agent. */
export interface SystemProxyAgentOptions extends RoutesOptions, https.AgentOptions {
  /** Replaces the watcher, so a `Routes` option beside it throws `ERR_INVALID_ARG_VALUE`.
   * The agent leaves it open; its owner closes it. */
  routes?: Routes;
  /** Milliseconds each connection to a step before the last may take, its TLS handshake
   * with the destination and a SOCKS step's probe included; past it the request goes to the
   * next step. The last step has no limit of its own, as with Node's own agent: a request's
   * `timeout` emits `'timeout'` while it connects, and destroying the request closes the
   * connection being opened, but for a SOCKS step's, which the SOCKS client closes after
   * 30 s. Above 0 and finite, at most 2147483647; anything else throws
   * `ERR_INVALID_ARG_VALUE`. Default 10000. */
  connectTimeout?: number;
  /** Pools each step's connections; an idle one closes after 5 s, or after the agent's
   * `timeout` where that is shorter. Default true. A `maxSockets` or
   * `maxTotalSockets` other than `Infinity` throws `ERR_INVALID_ARG_VALUE`. */
  keepAlive?: boolean;
  maxSockets?: number;
  maxTotalSockets?: number;
  /** Node's own proxy variables. Anything but `undefined` or `null` throws
   * `ERR_INVALID_ARG_VALUE`: the route reads the environment, through `env`. */
  proxyEnv?: null;
  /** Answers a proxy's `407` to CONNECT, as `negotiateAuth()` does for Kerberos. Without
   * it a 407 fails the request with `ProxyTunnelError`. A plain `http:` request, which an
   * HTTP proxy forwards without CONNECT, carries the proxy URL's `Basic` credentials, and a
   * 407 to it comes back as its response. */
  proxyAuth?: ProxyAuth;
  /** TLS options for the connection to an `https:` proxy alone: a `ca` here trusts the
   * proxy without replacing the destination's trust. Without it, the agent's own TLS options
   * go to the proxy as well as to the destination. */
  proxyTls?: tls.ConnectionOptions;
  /** The SOCKS client's options for its connection to a SOCKS proxy, over the agent's own
   * socket options. */
  socketOptions?: Omit<net.TcpNetConnectOpts, 'host' | 'port'>;
}

type Options = Record<string, unknown> & http.AgentOptions;

const SPEAKS = new Set(['http', 'https', 'socks', 'socks4', 'socks4a', 'socks5', 'socks5h']);
const speaks = (scheme: string) => SPEAKS.has(scheme);
// SOCKS4 carries an IPv4 address or a name: a route to an IPv6 address leaves its `socks4`
// steps out, as steps the client does not speak.
const speaksTo = (host: string) => (net.isIPv6(host) ? (scheme: string) => scheme !== 'socks4' && speaks(scheme) : speaks);

const closedError = () => Object.assign(new Error('the agent is closed'), { code: 'ERR_PROXY_CLOSED' });

// What Node's own agent gives a request destroyed before its socket connects, for a caller
// that retries on it.
const abortedError = () => Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });

const timeoutError = (ms: number) =>
  Object.assign(new Error(`the connection took longer than ${ms} ms`), { code: 'ETIMEDOUT' });

// Fails with `ETIMEDOUT` naming `limit` (the step's whole time) after `ms`, running `cancel`;
// a socket that arrives later is destroyed.
function bounded<T>(connecting: Promise<T>, ms: number, cancel = () => { }, limit = ms): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  let late = false;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      late = true;
      cancel();
      reject(timeoutError(limit));
    }, ms);
  });
  connecting.then(
    (socket) => late && (socket as { destroy?: () => void }).destroy?.(),
    () => { },
  );
  return Promise.race([connecting, timeout]).finally(() => clearTimeout(timer));
}

// `socket` once it is open: connected, and for TLS through its handshake.
function connected<S extends net.Socket>(socket: S): Promise<S> {
  return once(socket, socket instanceof tls.TLSSocket ? 'secureConnect' : 'connect').then(
    () => socket,
    (error) => {
      socket.destroy();
      throw error;
    },
  );
}

function dial(socket: net.Socket, ms: number): Promise<net.Socket> {
  return bounded(connected(socket), ms, () => socket.destroy());
}

// Idle time before a pooled connection closes, as on Node's global agent. Applied by the
// agents themselves, not through `timeout`: `SocksProxyAgent` closes a busy connection on
// `timeout` too.
const IDLE_MS = 5000;

type AgentClass = new (...args: any[]) => http.Agent;

// An agent whose idle connections close after `IDLE_MS`, and whose reused ones carry no
// idle timer while busy.
function pooled<T extends AgentClass>(Base: T) {
  return class extends Base {
    keepSocketAlive(socket: Duplex): boolean {
      // `@types/node` declares `void`; Node's agent returns whether it keeps the socket.
      const keep = super.keepSocketAlive(socket) as unknown as boolean;
      const timeout = (socket as net.Socket).timeout;
      if (keep && (!timeout || timeout > IDLE_MS)) (socket as net.Socket).setTimeout(IDLE_MS);
      return keep;
    }

    // Ends the idle timeout: the socket returns to the agent's `timeout`. A request's own
    // `timeout` is applied after, in Node's `setRequestSocket`.
    reuseSocket(socket: Duplex, req: http.ClientRequest): void {
      super.reuseSocket(socket, req);
      (socket as net.Socket).setTimeout((this as unknown as { options: http.AgentOptions }).options.timeout ?? 0);
    }
  };
}

const PooledHttpAgent = pooled(http.Agent);
const PooledHttpsAgent = pooled(https.Agent);

// Where a request is on its route, for a step agent's `connect()`.
interface Plan {
  index: number;
  saved: SavedRequest;
  connectTimeout: number;
  readonly last: boolean;
  next(): http.Agent;
  probe(): Promise<net.Socket>;
}

const plans = new WeakMap<http.ClientRequest, Plan>();

// The limit on `req`'s connection to its current step, `undefined` on the last. The agent
// that dials uses it too, so the connection it was opening closes at the limit.
function stepTimeout(req: http.ClientRequest): number | undefined {
  const plan = plans.get(req);
  return plan && !plan.last ? plan.connectTimeout : undefined;
}

// Aborts when the request is destroyed before it has a socket, or the agent is destroyed
// first, for the agent connecting it to close the connection it was opening.
const aborts = new WeakMap<http.ClientRequest, AbortSignal>();

// Closes `socket` when `req` is destroyed before it has one. The destroy's `'error'` can
// come after the wait for the connection has stopped listening and before the request
// takes the socket, where nothing else listens for it and it would be thrown.
function closeOnAbort(req: http.ClientRequest, socket: net.Socket): void {
  const signal = aborts.get(req);
  if (!signal) return;
  const close = () => {
    socket.on('error', () => {});
    socket.destroy(signal.reason);
  };
  if (signal.aborted) {
    close();
    return;
  }
  signal.addEventListener('abort', close, { once: true });
  socket.once('close', () => signal.removeEventListener('abort', close));
  req.once('socket', () => signal.removeEventListener('abort', close));
}

// `connecting`, or `signal`'s reason once it aborts; a socket that arrives after that is
// destroyed.
function abortable<T>(connecting: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return connecting;
  let late = false;
  let onAbort = () => { };
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => {
      late = true;
      reject(signal.reason);
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  connecting.then(
    (socket) => late && (socket as { destroy?: () => void }).destroy?.(),
    () => { },
  );
  return Promise.race([connecting, aborted]).finally(() => signal.removeEventListener('abort', onAbort));
}

type StepBase = new (...args: any[]) => Agent & {
  connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<Duplex | http.Agent> | Duplex | http.Agent;
};

// A step agent. `connect()` runs only for a new connection: it hands the request on when
// the connection to a step before the last fails, and gives up when the request is
// destroyed. The SOCKS client keeps the connection it was opening until its own 30 s timer,
// which no option sets without also closing busy connections.
function stepAgent<T extends StepBase>(Base: T) {
  return class extends Base {
    // The agent's `timeout` on a new connection, as Node's agent sets it as it connects. A
    // connection through a proxy is opened without it; a TLS socket takes it from `tls`.
    async connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<Duplex | http.Agent> {
      const taken = await this.#connect(req, opts);
      const timeout = (this as unknown as { options: http.AgentOptions }).options.timeout;
      if (timeout && taken instanceof net.Socket && !taken.timeout) taken.setTimeout(timeout);
      return taken;
    }

    async #connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<Duplex | http.Agent> {
      const plan = plans.get(req);
      const signal = aborts.get(req);
      if (!plan || plan.last) return abortable(Promise.resolve(super.connect(req, opts)), signal);
      const started = Date.now();
      try {
        const socks = this instanceof SocksProxyAgent;
        // The probe and the connection share the step's time.
        if (socks) await abortable(plan.probe(), signal);
        let cancelled = false;
        let socket: Duplex | undefined;
        let connecting = Promise.resolve(super.connect(req, opts));
        if (socks) {
          // The SOCKS agent hands back a TLS socket before its handshake, which is part of
          // the connection too.
          connecting = connecting.then((taken): Duplex | http.Agent | Promise<Duplex> => {
            if (!(taken instanceof tls.TLSSocket)) return taken;
            socket = taken;
            if (cancelled) taken.destroy();
            return connected(taken);
          });
        }
        const cancel = () => {
          cancelled = true;
          socket?.destroy();
        };
        const left = Math.max(0, started + plan.connectTimeout - Date.now());
        return await bounded(abortable(connecting, signal), left, cancel, plan.connectTimeout);
      } catch (error) {
        if (!isConnectError(error) || req.destroyed) throw error;
        restoreRequest(req, plan.saved);
        return plan.next();
      }
    }
  };
}

// A direct step before the last: a plain connection, pooled like any other step's. For
// `https:` the TLS handshake is part of the connection, held to the step's time with it and
// closed when that runs out.
class PlainAgent extends Agent {
  connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<net.Socket> {
    // `path` is the request's path here, and `net.connect` would read it as an IPC path.
    const { path, ...connectOpts } = opts as AgentConnectOpts & { path?: string };
    const socket = opts.secureEndpoint
      ? tls.connect({
        ...(connectOpts as tls.ConnectionOptions),
        servername: opts.servername ?? (net.isIP(opts.host ?? '') ? undefined : opts.host),
      })
      : net.connect(connectOpts as net.NetConnectOpts);
    closeOnAbort(req, socket);
    const timeout = stepTimeout(req);
    return timeout === undefined ? connected(socket) : dial(socket, timeout);
  }
}

const DirectAgent = stepAgent(pooled(PlainAgent));

// What every connection of one agent to a proxy shares: the answer to a 407, the TLS options
// for an `https:` proxy, and the agent's socket options (`localAddress`, `lookup`, ...).
interface TunnelSettings {
  auth: ProxyAuth | undefined;
  proxyTls: tls.ConnectionOptions;
  socket: ProxySocketOptions;
}

// `opts.host` as a proxy is given it. An IPv6 address may come bracketed, as a URL's
// `hostname` gives it (`[::1]`); a proxy is given it without the brackets, while a direct
// connection, like Node's own, looks the bracketed form up as a name. An IPv6 zone id
// (`fe80::1%eth0`) is dropped: no URL parser of the route takes it and a proxy cannot use
// it; a direct connection keeps it.
// The host is checked here because `setHost: false` skips Node's check: a space or control
// character would end the request line or start a header, and a host the route's URL reads
// as another (`internal.corp#@h.test`, `a%41b`) would be routed by one name and connected
// to as another.
function proxiedHost(opts: AgentConnectOpts): string {
  const given = opts.host ?? 'localhost';
  const unbracketed = /^\[(.*)\]$/.exec(given)?.[1];
  const literal = unbracketed !== undefined && net.isIPv6(unbracketed) ? unbracketed : given;
  const host = net.isIPv6(literal) ? literal.replace(/%.*$/, '') : literal;
  if (/[\x00-\x20\x7f]/.test(host)) {
    throw Object.assign(new TypeError(`invalid character in the host ${JSON.stringify(host)}`), {
      code: 'ERR_INVALID_CHAR',
    });
  }
  if (!net.isIPv6(host) && (/[#?/\\@:%[\]]/.test(host) || !URL.canParse(`http://${host}`))) {
    throw Object.assign(new TypeError(`the host ${JSON.stringify(host)} is not a host name or address`), {
      code: 'ERR_INVALID_ARG_VALUE',
    });
  }
  return host;
}

// Where the request goes: `opts.host` and `opts.port`, the address a direct connection and a
// CONNECT tunnel reach. The route and a forwarding proxy's target are read from them too, not
// from the `Host` header, which can name another host or be absent (`setHost: false`).
function destination(opts: AgentConnectOpts, protocol: string): string {
  const host = proxiedHost(opts);
  const fallback = opts.secureEndpoint ? 443 : 80;
  const port = Number(opts.port) || fallback;
  return `${protocol}//${net.isIPv6(host) ? `[${host}]` : host}${port === fallback ? '' : `:${port}`}`;
}

// A plain `http:` request forwarded by an HTTP or HTTPS proxy, as the proxy reads it: an
// absolute path and the proxy URL's credentials.
class ForwardAgent extends Agent {
  readonly #proxy: URL;
  readonly #credentials: string | undefined;
  readonly #tunnel: TunnelSettings;

  constructor(proxy: string, options: Options, tunnel: TunnelSettings, passwordState: PasswordState | null) {
    super(options);
    this.#proxy = new URL(proxy);
    this.#credentials = basicCredentials(this.#proxy, passwordState);
    this.#tunnel = tunnel;
  }

  // A pooled connection takes the request without a `connect()`, so it is rewritten here,
  // its header too where the request has stored it already.
  addRequest(req: http.ClientRequest, opts: AgentConnectOpts): void {
    rewriteHeader(req, () => {
      req.path = requestUrl(destination(opts, 'http:'), req.path);
      if (this.#credentials) req.setHeader('Proxy-Authorization', this.#credentials);
      req.setHeader('Proxy-Connection', this.keepAlive ? 'Keep-Alive' : 'close');
    });
    (http.Agent.prototype as any).addRequest.call(this, req, opts);
  }

  connect(req: http.ClientRequest): Promise<net.Socket> {
    const timeout = stepTimeout(req);
    let socket: net.Socket | undefined;
    const opened = (dialled: net.Socket) => {
      socket = dialled;
      closeOnAbort(req, dialled);
    };
    const dialing = dialProxy(this.#proxy, this.#tunnel.proxyTls, opened, this.#tunnel.socket);
    return timeout === undefined ? dialing : bounded(dialing, timeout, () => socket?.destroy());
  }
}

// An `https:` request, or a `ws:` upgrade, through a CONNECT tunnel; TLS to the
// destination for `https:`.
class TunnelAgent extends Agent {
  readonly #proxy: URL;
  readonly #auth: ProxyAuth | undefined;
  readonly #passwordState: PasswordState | null;
  readonly #tunnel: TunnelSettings;

  constructor(proxy: string, options: Options, tunnel: TunnelSettings, passwordState: PasswordState | null) {
    super(options);
    this.#proxy = new URL(proxy);
    this.#auth = tunnel.auth;
    this.#passwordState = passwordState;
    this.#tunnel = tunnel;
  }

  async connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<net.Socket> {
    const host = proxiedHost(opts);
    const port = Number(opts.port) || (opts.secureEndpoint ? 443 : 80);
    const started = Date.now();
    const timeout = stepTimeout(req);
    const socket = await openTunnel({
      proxy: this.#proxy,
      host,
      port,
      auth: this.#auth,
      passwordState: this.#passwordState,
      proxyTls: this.#tunnel.proxyTls,
      socketOptions: this.#tunnel.socket,
      timeout,
      signal: aborts.get(req),
    });
    // The tunnel is paused; it reads on once `http` has its listeners on the socket.
    const resumeOnSocket = () => req.once('socket', (taken: net.Socket) => setImmediate(() => taken.resume()));
    if (!opts.secureEndpoint) {
      resumeOnSocket();
      return socket;
    }
    // `path` is the request's path here, and would be read as an IPC path. `host` is the name
    // the certificate is checked against when there is no `servername`; without it `tls`
    // checks the host of `socket`, which is the proxy.
    const { path, host: _, port: __, ...options } = opts as AgentConnectOpts & { path?: string };
    const secure = secureTunnel(socket, {
      ...(options as tls.ConnectionOptions),
      host,
      servername: opts.servername ?? (net.isIP(host) ? undefined : host),
    });
    closeOnAbort(req, secure);
    // Before the last step the handshake counts toward the step's time. Running out of time
    // or losing the connection hands the request on; a certificate or protocol error fails
    // it, because the next step (direct, perhaps) would go around the check that failed.
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        once(secure, 'secureConnect'),
        new Promise<never>((_, reject) => {
          if (timeout !== undefined) {
            timer = setTimeout(() => reject(timeoutError(timeout)), Math.max(0, started + timeout - Date.now()));
          }
        }),
      ]);
    } catch (error) {
      secure.destroy();
      throw error;
    } finally {
      clearTimeout(timer);
    }
    resumeOnSocket();
    return secure;
  }
}

// The SOCKS client's errors carry no `code`. One for the connection to the proxy closing,
// failing or timing out during the handshake, before any of the request is written, gets the
// code of that failure, so a step before the last hands the request on as `fetch` does; a
// refusal the proxy answers keeps none and stays with the step.
function socksFailure(error: unknown): never {
  if (error instanceof Error && (error as { code?: unknown }).code === undefined) {
    const code =
      error.message === 'Socket closed'
        ? 'ECONNRESET'
        : error.message === 'Proxy connection timed out'
          ? 'ETIMEDOUT'
          : /^(?:read|write|connect) (E[A-Z]+)\b/.exec(error.message)?.[1];
    if (code) Object.assign(error, { code });
  }
  throw error;
}

const StepForwardAgent = stepAgent(pooled(ForwardAgent));
const StepTunnelAgent = stepAgent(pooled(TunnelAgent));
// `SocksProxyAgent` with no timer of its own: on `timeout` it destroys the connection, busy
// or idle, and the first request it carried. The agent's `timeout` stays in `options`, where
// Node's agent reads it.
// TLS to an `https:` destination starts here, not in `SocksProxyAgent`: its `tls.connect`
// leaves out `host`, so an IP destination with no `servername` would be checked against the
// proxy's host. Like it, this returns the TLS socket before the handshake. A failed
// handshake closes both sockets and leaves `req` to the step agent (before the last step)
// or to the socket's error (on the last). `noDelay` is set here: the SOCKS client does not.
// A `socks4` step resolves the name to an IPv4 address: the SOCKS client sends anything else
// as a SOCKS4a name, and an IPv6 address there reaches no SOCKS4 proxy. A proxy written as an
// IPv6 address is dialled without its brackets, which the SOCKS client keeps.
class SocksStepAgent extends SocksProxyAgent {
  constructor(...args: ConstructorParameters<typeof SocksProxyAgent>) {
    super(...args);
    this.timeout = null;
    this.proxy.host = this.proxy.host?.replace(/^\[(.*)\]$/, '$1');
  }

  override async connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<net.Socket> {
    if (this.shouldLookup && this.proxy.type === 4) {
      const lookup = opts.lookup ?? dns.lookup;
      opts = { ...opts, lookup: (host, options, callback) => lookup(host, { ...options, family: 4 }, callback) };
    }
    if (!opts.secureEndpoint) return (await super.connect(req, opts).catch(socksFailure)).setNoDelay(true);
    const host = proxiedHost(opts);
    const socket = (
      await super.connect(req, { ...opts, secureEndpoint: false } as AgentConnectOpts).catch(socksFailure)
    ).setNoDelay(true);
    // `path` is the request's path here, and would be read as an IPC path.
    const { path, host: _, port: __, ...options } = opts as AgentConnectOpts & { path?: string };
    // Not `secureTunnel`: the `socks` client resumes this socket itself on a later turn,
    // right after it re-emits what arrived past its handshake, and a `resume()` here would
    // let later bytes overtake those.
    let secure: tls.TLSSocket;
    try {
      secure = tls.connect({
        ...(options as tls.ConnectionOptions),
        socket,
        host,
        servername: opts.servername ?? (net.isIP(host) ? undefined : host),
      });
    } catch (error) {
      socket.destroy();
      throw error;
    }
    secure.once('error', () => {
      socket.destroy();
      secure.destroy();
    });
    return secure;
  }
}

const StepSocksProxyAgent = stepAgent(pooled(SocksStepAgent));

export interface SystemProxyAgent extends http.Agent {
  /** The last failed re-read of the settings, while the snapshot before it is in use. */
  readonly watchError: Error | null;
  /** Unset unless assigned: the agent takes `http` and `https` requests alike, and
   * `defaultPort` is the calling module's, 80 or 443. */
  protocol?: string;
}

/**
 * An `http.Agent` for `http.request` / `https.request`. A step before the last that cannot
 * connect hands the request to the next one. It speaks `http`, `https`, `socks4`,
 * `socks4a`, `socks5` and `socks5h` proxies, and tunnels a `ws:` upgrade through an HTTP
 * proxy with CONNECT. A route to an IPv6 address leaves its `socks4` steps out. A request
 * with a `socketPath` goes to that local socket without a route. The `Routes` options go to
 * the watcher; other options go to each step's agent. After a settings change, the next
 * request retires the agents of the older settings, which are destroyed once their requests
 * finish. `destroy()` also stops watching; a `routes` passed in stays open.
 */
export function systemProxyAgent(agentOptions: SystemProxyAgentOptions = {}): SystemProxyAgent {
  const [routesOptions, { routes, connectTimeout: givenTimeout, keepAlive = true, proxyAuth, proxyTls, ...rest }] =
    splitRoutesOptions(agentOptions);
  checkRoutesAlone(routes, routesOptions);
  const connectTimeout = checkTimeout('connectTimeout', givenTimeout ?? 10_000);
  const options: Options = { ...rest, keepAlive };
  for (const name of ['maxSockets', 'maxTotalSockets'] as const) {
    if (options[name] !== undefined && options[name] !== Infinity) {
      throw Object.assign(new RangeError(`${name} is not supported: a request handed to the next step would hold its place`), {
        code: 'ERR_INVALID_ARG_VALUE',
      });
    }
  }
  // Node's agent would send this agent's requests, and its steps' direct connections, to the
  // proxy these variables name; the route is this agent's to choose.
  if ((options as { proxyEnv?: unknown }).proxyEnv != null) {
    throw Object.assign(new TypeError('proxyEnv is not supported: give the variables to env, which the route reads'), {
      code: 'ERR_INVALID_ARG_VALUE',
    });
  }
  const source = routes ?? new Routes(routesOptions);
  const tunnel: TunnelSettings = {
    auth: proxyAuth,
    proxyTls: proxyTls ?? (options as tls.ConnectionOptions),
    socket: proxySocketOptions(options),
  };
  // Node's agent checks the options it takes (`scheduling`, ...) as it is made. A watcher this
  // call started is closed when that throws: the caller gets nothing to close it with.
  try {
    return new SystemProxyAgentImpl(options, source, !routes, connectTimeout, tunnel);
  } catch (error) {
    if (!routes) source.close();
    throw error;
  }
}

// Whether the request being made comes through `node:https`, by the call sites on the stack.
// `agent-base` answers the same question from a formatted stack trace, which Node's
// `ClientRequest` makes it build three times a request and which takes a large part of the
// request's own time. The limit is set here so that an application's lower
// `Error.stackTraceLimit` still reaches the frame.
function calledFromHttps(): boolean {
  const { prepareStackTrace, stackTraceLimit } = Error;
  const holder: { stack?: NodeJS.CallSite[] } = {};
  try {
    Error.prepareStackTrace = callSites;
    Error.stackTraceLimit = 10;
    Error.captureStackTrace(holder, calledFromHttps);
    return holder.stack!.some((site) => site.getFileName() === 'node:https');
  } catch {
    // `Error` is frozen (`--frozen-intrinsics`, a hardened realm): the formatted stack, as
    // `agent-base` reads it.
    return String(new Error().stack).includes('node:https:');
  } finally {
    if (Error.prepareStackTrace !== prepareStackTrace) Error.prepareStackTrace = prepareStackTrace;
    if (Error.stackTraceLimit !== stackTraceLimit) Error.stackTraceLimit = stackTraceLimit;
  }
}

const callSites = (_: Error, sites: NodeJS.CallSite[]) => sites;

class SystemProxyAgentImpl extends Agent implements SystemProxyAgent {
  // Set by the caller after construction; Node's agent sets both while it is constructed,
  // before these exist, and that is ignored as `agent-base` ignores it.
  #protocol: string | undefined;
  #defaultPort: number | undefined;
  #source: Routes;
  #ownsSource: boolean;
  #options: Options;
  #connectTimeout: number;
  #tunnel: TunnelSettings;
  #agents = new Map<string, http.Agent>();
  // Requests on each pooled agent, and the agents of older settings still serving some.
  #leases = new Map<http.Agent, number>();
  #retired = new Set<http.Agent>();
  #generation = 0;
  #closed = false;
  // The requests still connecting, each by the controller that ends it.
  #connecting = new Set<AbortController>();

  constructor(
    options: Options,
    source: Routes,
    ownsSource: boolean,
    connectTimeout: number,
    tunnel: TunnelSettings,
  ) {
    super({ ...options, maxSockets: Infinity, maxTotalSockets: Infinity });
    this.#options = options;
    this.#source = source;
    this.#ownsSource = ownsSource;
    this.#connectTimeout = connectTimeout;
    this.#tunnel = tunnel;
  }

  get watchError(): Error | null {
    return this.#source.error;
  }

  // Node's `ClientRequest` reads these for each request: `protocol` twice, to check the URL's
  // scheme, and `defaultPort` once, to fill in a port the URL leaves out. One agent takes both
  // modules' requests. With no `protocol`, Node checks the scheme against the calling module's
  // own global agent, which is the same answer without a look at the stack; `defaultPort` has
  // no such fallback and reads the calling module from the stack.
  get protocol(): string {
    // `agent-base` declares a string; Node reads a missing value as "the module's own".
    return this.#protocol as string;
  }

  set protocol(value: string) {
    if (#protocol in this) this.#protocol = value;
  }

  get defaultPort(): number {
    if (this.#defaultPort !== undefined) return this.#defaultPort;
    const protocol = this.#protocol ?? (calledFromHttps() ? 'https:' : 'http:');
    return protocol === 'https:' ? 443 : 80;
  }

  set defaultPort(value: number) {
    if (#defaultPort in this) this.#defaultPort = value;
  }

  // Every request goes to a step agent, so no socket of this agent's comes back to pool.
  keepSocketAlive(): boolean {
    return false;
  }

  // Runs as the request is made, before the caller can set a timeout on it.
  addRequest(req: http.ClientRequest, opts: AgentConnectOpts): void {
    // A `signal` that has already aborted destroys the request before it gets here, and the
    // signal is not passed on. No socket lets Node fail it with its own `AbortError`, before
    // the route is read.
    if (req.destroyed) {
      req.onSocket(null as unknown as net.Socket);
      return;
    }
    const aborting = new AbortController();
    aborts.set(req, aborting.signal);
    untilSocket(req, (error) => aborting.abort(error ?? abortedError()));
    // Until it has a socket, `destroy()` of this agent ends it too.
    this.#connecting.add(aborting);
    const settled = () => this.#connecting.delete(aborting);
    req.once('socket', settled);
    req.once('close', settled);
    (Agent.prototype as any).addRequest.call(this, req, opts);
  }

  async connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<http.Agent> {
    if (this.#closed) throw closedError();
    const secure = Boolean(opts.secureEndpoint);
    // A request to a `socketPath` goes to that local socket, as on Node's agent: its URL names
    // `localhost`, which a route could send to a proxy.
    if ((opts as { socketPath?: string }).socketPath) return this.#agentFor('direct', true, secure, false, req);
    if (hasProxyAuthorization(req)) throw proxyAuthorizationError();
    const websocket = isWebSocket(upgradeHeader(req));
    const protocol = secure ? (websocket ? 'wss:' : 'https:') : websocket ? 'ws:' : 'http:';
    const url = requestUrl(destination(opts, protocol), req.path);
    const { steps, generation } = await this.#source.resolve(url, speaksTo(proxiedHost(opts)));
    if (this.#closed) throw closedError();
    if (req.destroyed) throw aborts.get(req)?.reason ?? abortedError();
    this.#rotate(generation);
    // `tunnel` is whether a proxy has to open a CONNECT tunnel, which a plain `ws:` upgrade
    // needs too.
    const tunnel = secure || websocket;
    const plan: Plan = {
      index: 0,
      saved: saveRequest(req),
      connectTimeout: this.#connectTimeout,
      get last() {
        return this.index === steps.length - 1;
      },
      next: () => {
        plan.index += 1;
        return this.#agentFor(steps[plan.index], plan.last, secure, tunnel, req);
      },
      probe: () => this.#probe(steps[plan.index], req),
    };
    plans.set(req, plan);
    return this.#agentFor(steps[0], plan.last, secure, tunnel, req);
  }

  #agentFor(step: string, last: boolean, secure: boolean, tunnel: boolean, req: http.ClientRequest): http.Agent {
    if (this.#closed) throw closedError();
    let agent: http.Agent;
    if (step !== 'direct') {
      agent = this.#child(step, tunnel);
    } else if (last) {
      const make = () => (secure ? new PooledHttpsAgent(this.#options) : new PooledHttpAgent(this.#options));
      agent = this.#pooled(`direct:${secure}`, make);
    } else {
      agent = this.#pooled('direct:step', () => new DirectAgent(this.#options));
    }
    return this.#lease(agent, req);
  }

  // The options of a connection to a SOCKS proxy, the probe's and the SOCKS client's: the
  // agent's socket options, and the SOCKS client's own `socketOptions` over them.
  #socksSocketOptions(): Omit<net.TcpSocketConnectOpts, 'port'> {
    return { ...this.#tunnel.socket, ...(this.#options.socketOptions as object | undefined) };
  }

  // Destroying `req` closes the probe as it closes the connection after it.
  #probe(step: string, req: http.ClientRequest): Promise<net.Socket> {
    const proxy = new URL(step);
    const port = proxy.port ? Number(proxy.port) : 1080;
    const host = proxy.hostname.replace(/^\[(.*)\]$/, '$1');
    const socket = net.connect({ ...this.#socksSocketOptions(), host, port });
    closeOnAbort(req, socket);
    return dial(socket, this.#connectTimeout).finally(() => socket.destroy());
  }

  // A newer snapshot replaces the pools; the agents it replaces are destroyed once their
  // requests finish. A request that read an older snapshot uses the pools in use: an agent
  // depends on its step alone, and turning the pools back would drop newer ones.
  #rotate(generation: number): void {
    if (generation <= this.#generation) return;
    this.#generation = generation;
    for (const agent of this.#agents.values()) {
      if (this.#leases.get(agent)) this.#retired.add(agent);
      else agent.destroy();
    }
    this.#agents.clear();
  }

  #pooled(key: string, make: () => http.Agent): http.Agent {
    let agent = this.#agents.get(key);
    if (!agent) {
      agent = make();
      this.#agents.set(key, agent);
    }
    return agent;
  }

  #child(step: string, tunnel: boolean): http.Agent {
    return this.#pooled(`${tunnel ? 's' : 'h'}:${step}`, () => {
      if (schemeOf(step).startsWith('socks')) {
        // The SOCKS client hands `socketOptions` to its connection to the proxy.
        const socketOptions = this.#socksSocketOptions();
        return new StepSocksProxyAgent(withValidEscapes(step), { ...this.#options, socketOptions });
      }
      const passwordState = this.#source.passwordState?.(step) ?? null;
      if (tunnel) return new StepTunnelAgent(step, this.#options, this.#tunnel, passwordState);
      return new StepForwardAgent(step, this.#options, this.#tunnel, passwordState);
    });
  }

  #lease(agent: http.Agent, req: http.ClientRequest): http.Agent {
    this.#leases.set(agent, (this.#leases.get(agent) ?? 0) + 1);
    req.once('close', () => {
      const left = (this.#leases.get(agent) ?? 1) - 1;
      if (left > 0) {
        this.#leases.set(agent, left);
        return;
      }
      this.#leases.delete(agent);
      if (this.#retired.delete(agent)) agent.destroy();
    });
    return agent;
  }

  destroy(): void {
    this.#closed = true;
    if (this.#ownsSource) this.#source.close();
    for (const aborting of [...this.#connecting]) aborting.abort(closedError());
    this.#connecting.clear();
    for (const agent of [...this.#agents.values(), ...this.#retired]) agent.destroy();
    this.#agents.clear();
    this.#retired.clear();
    super.destroy();
  }
}
