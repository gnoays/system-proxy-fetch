// A dispatcher for `fetch` and undici that sends each request where the operating system
// would.
//
// undici's SOCKS5 agent sends a destination's name to the proxy, never an address it looked
// up, and takes `socks5:` (or `socks:`), so a `socks5h://` step is given to it as `socks5:`
// and a `socks5://` step has the proxy resolve the name too. It does not speak SOCKS4.
//
// An `https:` request or a `ws:` upgrade goes through a CONNECT tunnel of this package's, on an
// undici `Agent` whose `connect` opens it. A plain `http:` request goes to undici's
// `ProxyAgent`, which forwards it without CONNECT.

import net from 'node:net';
import tls from 'node:tls';
import { setMaxListeners } from 'node:events';
import { Agent, Dispatcher, Dispatcher1Wrapper, ProxyAgent, Socks5ProxyAgent, buildConnector } from 'undici';
import { basicCredentials, withValidEscapes, type ProxyAuth } from './auth.mjs';
import type { PasswordState } from './core.mjs';
import {
  CONNECT_CODES,
  ROUTES_OPTIONS,
  Routes,
  checkRoutesAlone,
  checkTimeout,
  isConnectError,
  isWebSocket,
  requestUrl,
  schemeOf,
  splitRoutesOptions,
  type RoutesOptions,
} from './core.mjs';
import { proxyAuthorizationError } from './request.mjs';
import { openTunnel, secureTunnel } from './tunnel.mjs';

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

// TLS options with the keys the constructor refuses held to `undefined`, as it accepts them.
type TlsOptions<Refused extends string> = Omit<tls.ConnectionOptions, Refused> & {
  [Key in Refused]?: undefined;
};

export interface SystemProxyDispatcherOptions extends RoutesOptions {
  /** Replaces the watcher, so a `Routes` option beside it throws `ERR_INVALID_ARG_VALUE`.
   * The dispatcher leaves it open; its owner closes it. */
  routes?: Routes;
  /** Answers a proxy's `407` to CONNECT, as `negotiateAuth()` does for Kerberos. Without
   * it a 407 fails the request with `ProxyTunnelError`. A plain `http:` request, which an
   * HTTP proxy forwards without CONNECT, carries the proxy URL's `Basic` credentials, and a
   * 407 to it fails the request with undici's `InvalidArgumentError`
   * (`UND_ERR_INVALID_ARG`). */
  proxyAuth?: ProxyAuth;
  /** TLS options for the connection to an `https:` proxy. A SOCKS step's connection to its
   * proxy stays plain. `timeout`, `path`, `socketPath` and
   * `socket` throw `ERR_INVALID_ARG_VALUE`. */
  proxyTls?: TlsOptions<'timeout' | 'path' | 'socketPath' | 'socket'>;
  /** TLS options for the connection to the destination through a proxy. A direct step's TLS is Node's default: its `ca` would replace the roots a
   * public destination is judged by, so a CA for every connection goes in
   * `NODE_EXTRA_CA_CERTS`, which adds to them. `timeout`, `path`, `socketPath`, `socket` and
   * `session` throw `ERR_INVALID_ARG_VALUE`. */
  requestTls?: TlsOptions<'timeout' | 'path' | 'socketPath' | 'socket' | 'session'>;
  /** Milliseconds a connection may take, a CONNECT tunnel's exchange with its proxy and
   * the TLS handshake with the destination through it included. Above 0 and finite, at most
   * 2147483647; anything else throws `ERR_INVALID_ARG_VALUE` (undici's own `0` for "no
   * limit" is not taken). Default 10000. A SOCKS step's client holds each part of its
   * connection to this limit on its own (the connection to the proxy, its authentication,
   * its `CONNECT`, the TLS with the destination), so the whole can take longer. */
  connectTimeout?: number;
  // undici `Agent` options, as for undici's `Agent`. They reach the agents of direct and
  // CONNECT steps; a forwarded `http:` request and a SOCKS step take undici's defaults.
  connections?: number | null;
  pipelining?: number;
  headersTimeout?: number;
  bodyTimeout?: number;
  keepAliveTimeout?: number;
  keepAliveMaxTimeout?: number;
  /** A direct step alone negotiates HTTP/2, for undici's own `fetch` and `request`. The
   * `fetch` built into Node passes the older callbacks, which undici keeps to HTTP/1.1. */
  allowH2?: boolean;
}

// Every option the constructor takes. Any other throws `ERR_INVALID_ARG_VALUE`: an undici
// option passed on to every step's agent takes effect on some steps and is dropped on the
// others, and one such as `socketPath` or `factory` sends a step's connection somewhere else.
const AGENT_OPTIONS = [
  'connections',
  'pipelining',
  'headersTimeout',
  'bodyTimeout',
  'keepAliveTimeout',
  'keepAliveMaxTimeout',
  'allowH2',
];
const OPTIONS = new Set([...ROUTES_OPTIONS, 'routes', ...AGENT_OPTIONS, 'proxyAuth', 'proxyTls', 'requestTls', 'connectTimeout']);

const TLS_HINT = 'TLS to a destination through a proxy goes in requestTls, and to an https: proxy in proxyTls';
const HINTS: Record<string, string> = {
  connect: TLS_HINT,
  tls: TLS_HINT,
  headers: 'headers go with each request',
  token: 'credentials go in the proxy URL, or proxyAuth answers a 407',
  auth: 'credentials go in the proxy URL, or proxyAuth answers a 407',
  username: 'credentials go in the proxy URL, or proxyAuth answers a 407',
  password: 'credentials go in the proxy URL, or proxyAuth answers a 407',
  // `requestTls` refuses it too, so the TLS hint would send the caller to a second refusal.
  session: 'a session belongs to one destination',
};
for (const name of [
  'ca', 'cert', 'key', 'pfx', 'passphrase', 'crl', 'rejectUnauthorized', 'minVersion', 'maxVersion', 'ciphers',
  'sigalgs', 'secureOptions', 'secureProtocol', 'checkServerIdentity', 'ALPNProtocols', 'honorCipherOrder',
  'servername',
]) {
  HINTS[name] = TLS_HINT;
}

// TLS options that would take a step's connection from the dispatcher. Spread into undici's
// connectors and `tls.connect`, `timeout` replaces `connectTimeout` (`0` lifts the limit),
// and `path`, `socketPath` and `socket` send the connection somewhere else. A `session` in
// `requestTls` would be offered to every destination.
const TLS_REFUSED: Record<string, Record<string, string>> = {
  proxyTls: {
    timeout: 'the limit is connectTimeout',
    path: 'the connection goes to the proxy',
    socketPath: 'the connection goes to the proxy',
    socket: 'the connection goes to the proxy',
  },
  requestTls: {
    timeout: 'the limit is connectTimeout',
    path: 'the connection goes through the proxy',
    socketPath: 'the connection goes through the proxy',
    socket: 'the connection goes through the proxy',
    session: 'a session belongs to one destination',
  },
};

const invalid = (message: string) =>
  Object.assign(new TypeError(message), { code: 'ERR_INVALID_ARG_VALUE' });

// undici takes headers as an object, as a flat array of names and values, or as any other
// iterable of name-value pairs.
const isIterableHeaders = (headers: unknown): headers is Iterable<[string, unknown]> =>
  typeof headers === 'object' && headers !== null && !Array.isArray(headers) && Symbol.iterator in headers;

// The name is enough, whatever its value, as for undici's ProxyAgent.
const hasProxyAuthorization = (headers: Dispatcher.DispatchOptions['headers']): boolean => {
  const names = Array.isArray(headers) ? headers.filter((_, i) => i % 2 === 0) : Object.keys(headers ?? {});
  return names.some((name) => String(name).toLowerCase() === 'proxy-authorization');
};

// Throws `ERR_INVALID_ARG_VALUE` for the first option set that is not in `OPTIONS`, or TLS
// option in `TLS_REFUSED`. An option set to `undefined` is taken as absent. The tables are read
// by own key, so a name such as `constructor` finds nothing on `Object.prototype`.
function checkOptions(options: object): void {
  for (const [name, value] of Object.entries(options)) {
    if (value === undefined || OPTIONS.has(name)) continue;
    const hint = Object.hasOwn(HINTS, name) ? HINTS[name] : undefined;
    throw invalid(`SystemProxyDispatcher does not take the ${name} option${hint ? `: ${hint}` : ''}`);
  }
  for (const [option, refused] of Object.entries(TLS_REFUSED)) {
    const tlsOptions = (options as Record<string, unknown>)[option];
    if (typeof tlsOptions !== 'object' || tlsOptions === null) continue;
    for (const [name, value] of Object.entries(tlsOptions)) {
      if (value === undefined || !Object.hasOwn(refused, name)) continue;
      throw invalid(`SystemProxyDispatcher does not take ${option}.${name}: ${refused[name]}`);
    }
  }
}

const SPEAKS = new Set(['http', 'https', 'socks5', 'socks5h']);
const speaks = (scheme: string) => SPEAKS.has(scheme);
// undici's SOCKS5 agent sends an IPv6 destination as the name `[::1]`, which no proxy
// resolves: a route to an IPv6 address leaves its SOCKS steps out, as steps the client
// does not speak.
const speaksTo = (hostname: string) =>
  hostname.startsWith('[') ? (scheme: string) => !scheme.startsWith('socks') && speaks(scheme) : speaks;
// undici's SOCKS5 agent dials a proxy written as an IPv6 address with its brackets, as a name.
const unbracketed =
  (connect: buildConnector.connector): buildConnector.connector =>
  (options, callback) => {
    const host = options.hostname.replace(/^\[(.*)\]$/, '$1');
    connect({ ...options, hostname: host, host }, callback);
  };

// `CONNECT_CODES` and undici's own codes for the same failures. They hand the request on only
// before undici calls `onRequestStart`, which it does as it starts to write the request: until
// then no byte of the request, body included, has left.
const UNDICI_CONNECT_CODES = new Set([
  ...CONNECT_CODES,
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
  'UND_ERR_PRX_CONN',
]);

interface TunnelSettings {
  auth: ProxyAuth | undefined;
  proxyTls: tls.ConnectionOptions | undefined;
  requestTls: tls.ConnectionOptions | undefined;
  timeout: number;
  /** Aborts on the dispatcher's `destroy()`, closing the tunnels being opened. */
  signal: AbortSignal;
}

// An undici `connect` that reaches the destination through `proxy`'s CONNECT, with TLS to
// the destination for `https:`.
function tunnelConnector(
  proxy: URL,
  passwordState: PasswordState | null,
  { auth, proxyTls, requestTls, timeout, signal }: TunnelSettings,
): buildConnector.connector {
  // undici puts no timer of its own on a `connect` function, so `timeout` covers the whole
  // connection here: the tunnel and, for `https:`, the TLS handshake through it. `signal`
  // ends both.
  return (options, callback) => {
    const host = options.hostname.replace(/^\[|\]$/g, '');
    const secure = options.protocol === 'https:';
    const port = Number(options.port) || (secure ? 443 : 80);
    const deadline = Date.now() + timeout;
    openTunnel({ proxy, host, port, auth, passwordState, proxyTls, timeout, signal }).then(
      (socket) => {
        if (!secure) {
          callback(null, socket);
          return;
        }
        // undici passes an IP destination's `servername` as ''. `host` is the name the
        // certificate is checked against when there is no `servername`; without it `tls`
        // checks the host of `socket`, which is the proxy.
        const servername = requestTls?.servername ?? (options.servername || (net.isIP(host) ? undefined : host));
        let session: tls.TLSSocket;
        try {
          session = secureTunnel(socket, { ALPNProtocols: ['http/1.1'], ...requestTls, host, servername });
        } catch (error) {
          callback(error as Error, null);
          return;
        }
        let settled = false;
        const onAbort = () => fail(signal.reason);
        const fail = (error: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          signal.removeEventListener('abort', onAbort);
          session.destroy();
          callback(error, null);
        };
        const timer = setTimeout(
          () => fail(Object.assign(new Error(`the connection took longer than ${timeout} ms`), { code: 'ETIMEDOUT' })),
          Math.max(0, deadline - Date.now()),
        );
        if (signal.aborted) onAbort();
        else signal.addEventListener('abort', onAbort, { once: true });
        session.once('error', fail);
        session.once('secureConnect', () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          signal.removeEventListener('abort', onAbort);
          session.off('error', fail);
          callback(null, session);
        });
      },
      (error) => callback(error, null),
    );
  };
}

// `ProxyAgent`'s proxy and credentials for `step`. The URL goes without its credentials and
// `basicCredentials` builds `token` from them: `ProxyAgent` would send `Basic` for a user name
// with no password, and decodes the credentials with `decodeURIComponent`, which throws on a
// malformed escape.
function forwardOptions(step: string, passwordState: PasswordState | null): { uri: string; token?: string } {
  const uri = new URL(step);
  const token = basicCredentials(uri, passwordState);
  uri.username = '';
  uri.password = '';
  return token === undefined ? { uri: uri.href } : { uri: uri.href, token };
}

const closedError = () =>
  Object.assign(new Error('the dispatcher is closed'), { code: 'ERR_PROXY_CLOSED' });

// `handler` (the newer callbacks), except that a connection failure before the request
// starts to be written goes to `retry` when there is a step left. `settle` runs once, when
// the request is over for this dispatcher; `started` gets the controller that aborts it.
function attempt(
  handler: any,
  retry: (() => void) | null,
  settle: () => void,
  started: (controller: Dispatcher.DispatchController) => void,
): Dispatcher.DispatchHandler {
  let began = false;
  return {
    onRequestStart: (controller: Dispatcher.DispatchController, ...args: any[]) => {
      began = true;
      started(controller);
      return handler.onRequestStart?.(controller, ...args);
    },
    // The hooks undici calls only where the handler has them: `fetch` takes the response's
    // start time from `onResponseStarted`.
    onRequestSent: () => handler.onRequestSent?.(),
    onBodySent: (chunk: unknown) => handler.onBodySent?.(chunk),
    onResponseStarted: () => handler.onResponseStarted?.(),
    onRequestUpgrade: (...args: any[]) => {
      settle();
      return handler.onRequestUpgrade?.(...args);
    },
    onResponseStart: (...args: any[]) => handler.onResponseStart?.(...args),
    onResponseData: (...args: any[]) => handler.onResponseData?.(...args),
    onResponseEnd: (...args: any[]) => {
      settle();
      return handler.onResponseEnd?.(...args);
    },
    onResponseError: (controller: any, error: Error) => {
      if (!began && retry && isConnectError(error, UNDICI_CONNECT_CODES)) return retry();
      settle();
      return handler.onResponseError?.(controller, error);
    },
  } as Dispatcher.DispatchHandler;
}

export type CloseCallback = (error: Error | null, data: null) => void;

function callBack(promise: Promise<void>, callback?: CloseCallback): Promise<void> | undefined {
  if (typeof callback !== 'function') return promise;
  promise.then(
    () => callback(null, null),
    (error) => callback(error, null),
  );
  return undefined;
}

/**
 * Routes each request by the OS proxy settings layered with `*_proxy`. Pass it as
 * `fetch(url, { dispatcher })` or to `setGlobalDispatcher`. It speaks `http`, `https`,
 * `socks5` and `socks5h` proxies; a SOCKS step sends a destination's name to the proxy, and
 * a route to an IPv6 address leaves its SOCKS steps out. A `407` to CONNECT fails the
 * request unless `proxyAuth` answers it. The `Routes` options go to the watcher; an option it
 * does not list throws `ERR_INVALID_ARG_VALUE`. After a change, the next request retires the
 * agents of the older settings, which close once their requests finish. `close()` refuses
 * later requests and settles once the requests already taken have finished; `destroy()` ends them. Both also
 * take undici's callback forms. A `routes` passed in stays open. A `fetch`'s `signal` reaches
 * a request once undici starts it, on an open connection: an abort before that rejects the
 * `fetch` at once and leaves the connection being opened, a CONNECT tunnel and its
 * `proxyAuth` included, to finish or to reach `connectTimeout`. Composed under undici's
 * `interceptors.dns`, it sees the IP address in place of the host name, and so do PAC and
 * `no_proxy`.
 */
export class SystemProxyDispatcher extends Dispatcher {
  #routes: Routes;
  #ownsRoutes: boolean;
  #options: Record<string, unknown>;
  #tunnel: TunnelSettings;
  #agents = new Map<string, Dispatcher>();
  #retired = new Set<Dispatcher>();
  #generation = 0;
  #legacy: Dispatcher | null = null;
  #closed = false;
  #destroyed = false;
  #inflight = 0;
  // The requests under way that undici has started to write, for `destroy()` to end: an
  // agent of older settings has handed its connections to `close()`, and its `destroy()`
  // no longer reaches them.
  #started = new Set<Dispatcher.DispatchController>();
  #aborting = new AbortController();
  #idle: (() => void) | null = null;
  #closing: Promise<void> | null = null;

  constructor(options: SystemProxyDispatcherOptions = {}) {
    super();
    checkOptions(options);
    const [routesOptions, { routes, proxyAuth, proxyTls, requestTls, connectTimeout, ...agentOptions }] =
      splitRoutesOptions(options);
    // Checked before `Routes` starts watching the system: a constructor that throws leaves the
    // caller nothing to close it with.
    checkRoutesAlone(routes, routesOptions);
    const timeout = checkTimeout('connectTimeout', connectTimeout ?? 10_000);
    this.#ownsRoutes = !routes;
    this.#routes = routes ?? new Routes(routesOptions);
    this.#tunnel = { auth: proxyAuth, proxyTls, requestTls, timeout, signal: this.#aborting.signal };
    this.#options = { ...agentOptions, connectTimeout: this.#tunnel.timeout };
    // Every tunnel being opened listens on it.
    setMaxListeners(0, this.#aborting.signal);
    // undici's `compose()` returns a Proxy that hands out every method but `dispatch` unbound,
    // and a private field read through the Proxy throws.
    this.close = this.close.bind(this) as this['close'];
    this.destroy = this.destroy.bind(this) as this['destroy'];
  }

  /** The last failed re-read of the settings, while the snapshot before it is in use. */
  get watchError(): Error | null {
    return this.#routes.error;
  }

  // A newer snapshot replaces the pools; the agents it replaces close once their requests
  // finish. A request that read an older snapshot uses the pools in use: an agent depends on
  // its step alone, and turning the pools back would close newer ones.
  #agent(step: string, generation: number, tunnel: boolean): Dispatcher {
    if (generation > this.#generation) {
      for (const agent of this.#agents.values()) this.#retire(agent);
      this.#agents.clear();
      this.#generation = generation;
    }
    const http = step !== 'direct' && !schemeOf(step).startsWith('socks5');
    const key = http ? `${tunnel ? 'tunnel' : 'forward'}:${step}` : step;
    let agent = this.#agents.get(key);
    if (!agent) {
      if (step === 'direct') {
        agent = new Agent(this.#options);
      } else if (!http) {
        // `Socks5ProxyAgent` opens TLS to its proxy wherever `proxyTls` is set, which a SOCKS
        // proxy does not speak; `proxyTls` here is for an `https:` proxy alone.
        agent = new Socks5ProxyAgent(withValidEscapes(step).replace(/^socks5h:/i, 'socks5:'), {
          requestTls: this.#tunnel.requestTls,
          connectTimeout: this.#tunnel.timeout,
          connect: unbracketed(buildConnector({ timeout: this.#tunnel.timeout })),
        });
      } else if (tunnel) {
        const passwordState = this.#routes.passwordState?.(step) ?? null;
        agent = new Agent({ ...this.#options, connect: tunnelConnector(new URL(step), passwordState, this.#tunnel) });
      } else {
        const passwordState = this.#routes.passwordState?.(step) ?? null;
        agent = new ProxyAgent({
          ...this.#options,
          proxyTls: this.#tunnel.proxyTls,
          ...forwardOptions(step, passwordState),
        } as ProxyAgent.Options);
      }
      this.#agents.set(key, agent);
    }
    return agent;
  }

  #retire(agent: Dispatcher): void {
    this.#retired.add(agent);
    agent
      .close()
      .catch(() => { })
      .finally(() => this.#retired.delete(agent));
  }

  dispatch(opts: Dispatcher.DispatchOptions, handler: any): boolean {
    // The `fetch` built into Node passes the older callbacks; undici's wrapper turns them
    // into the newer ones and calls back into this method. A legacy handler may have any
    // subset of the older callbacks, so it is told apart by lacking the newer ones.
    if (!handler.onResponseStart && !handler.onRequestStart) {
      this.#legacy ??= new Dispatcher1Wrapper(this);
      return this.#legacy.dispatch(opts, handler);
    }
    if (this.#closed) {
      handler.onResponseError?.(null, closedError());
      return true;
    }
    let url: string;
    let hostname: string;
    try {
      // A WebSocket's origin is `http:` or `https:`; the route is read for `ws:` or `wss:`,
      // as for the http.Agent.
      const origin = new URL(String(opts.origin));
      if (isWebSocket(opts.upgrade)) origin.protocol = origin.protocol === 'https:' ? 'wss:' : 'ws:';
      url = requestUrl(origin.origin, opts.path);
      hostname = origin.hostname;
      // Every step is handed the same headers, so an iterator is read into an array once.
      if (isIterableHeaders(opts.headers)) opts = { ...opts, headers: [...opts.headers].flat() as string[] };
      if (hasProxyAuthorization(opts.headers)) throw proxyAuthorizationError();
    } catch (error) {
      handler.onResponseError?.(null, error as Error);
      return true;
    }
    this.#inflight += 1;
    let settled = false;
    let controller: Dispatcher.DispatchController | null = null;
    const settle = () => {
      if (settled) return;
      settled = true;
      if (controller) this.#started.delete(controller);
      this.#inflight -= 1;
      if (this.#inflight === 0) this.#idle?.();
    };
    const started = (taken: Dispatcher.DispatchController) => {
      controller = taken;
      if (!settled) this.#started.add(taken);
    };
    const fail = (error: Error) => {
      settle();
      handler.onResponseError?.(null, error);
    };
    this.#routes.resolve(url, speaksTo(hostname)).then(
      ({ steps, generation }) => this.#attempt(steps, 0, opts, handler, generation, settle, started, fail),
      fail,
    );
    return true;
  }

  #attempt(
    steps: string[],
    index: number,
    opts: Dispatcher.DispatchOptions,
    handler: any,
    generation: number,
    settle: () => void,
    started: (controller: Dispatcher.DispatchController) => void,
    fail: (error: Error) => void,
  ): void {
    if (this.#destroyed) {
      fail(this.#aborting.signal.reason);
      return;
    }
    const retry =
      index === steps.length - 1
        ? null
        : () => this.#attempt(steps, index + 1, opts, handler, generation, settle, started, fail);
    try {
      // A plain `ws:` upgrade takes a tunnel too: a forwarding proxy need not pass it on.
      const tunnel = new URL(String(opts.origin)).protocol !== 'http:' || isWebSocket(opts.upgrade);
      this.#agent(steps[index], generation, tunnel).dispatch(opts, attempt(handler, retry, settle, started));
    } catch (error) {
      fail(error as Error);
    }
  }

  close(): Promise<void>;
  close(callback: CloseCallback): void;
  close(callback?: CloseCallback): Promise<void> | void {
    this.#closing ??= this.#shutdown();
    return callBack(this.#closing, callback);
  }

  async #shutdown(): Promise<void> {
    this.#closed = true;
    if (this.#ownsRoutes) this.#routes.close();
    if (this.#inflight > 0) await new Promise<void>((resolve) => (this.#idle = resolve));
    // A `destroy()` since has ended the agents, and the close is done with them.
    if (this.#destroyed) return;
    await Promise.all([...this.#agents.values(), ...this.#retired].map((agent) => agent.close()));
    this.#agents.clear();
  }

  destroy(): Promise<void>;
  destroy(error: Error | null): Promise<void>;
  destroy(callback: CloseCallback): void;
  destroy(error: Error | null, callback: CloseCallback): void;
  destroy(error?: Error | null | CloseCallback, callback?: CloseCallback): Promise<void> | void {
    if (typeof error === 'function') {
      callback = error;
      error = null;
    }
    this.#closed = true;
    this.#destroyed = true;
    if (this.#ownsRoutes) this.#routes.close();
    const agents = [...this.#agents.values(), ...this.#retired];
    this.#agents.clear();
    const reason = error ?? closedError();
    this.#aborting.abort(reason);
    for (const controller of [...this.#started]) controller.abort(reason);
    this.#started.clear();
    // A request still queued in a pool ends with the same reason as one under way.
    const done = Promise.all(agents.map((agent) => agent.destroy(reason))).then(() => { });
    return callBack(done, callback);
  }
}
