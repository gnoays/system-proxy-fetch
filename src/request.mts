// The parts of Node's `ClientRequest` that are not public API: the stored header (`_header`,
// `_headerSent`) and the queued writes (`outputData`, `outputSize`). A request can reach an
// agent with its header stored and queued, or have it stored while the agent holds it, so an
// agent that rewrites the request for a proxy, or puts it back for the next step, edits them.
// A stored header is edited as text, never rendered again: a request made with its headers
// as an array keeps them in the stored header alone. Every use of them is in this module.

import type { ClientRequest, OutgoingHttpHeader } from 'node:http';

interface Internals {
  _header: string | null;
  _headerSent: boolean;
  outputData?: { data: string | Buffer }[];
  outputSize: number;
}

const internals = (req: ClientRequest) => req as unknown as Internals;

/**
 * Until `req` has a socket: calls `destroyed`, with the error it is destroyed with if any,
 * when it is destroyed, and emits its `'timeout'` when its timeout (the `timeout` option, or
 * `setTimeout()`) passes. Node does neither
 * before a socket comes, and an agent that connects through a proxy hands one over only
 * once the proxy has answered; Node's own agent hands over the socket as it starts to
 * connect. Call it before the caller can call `setTimeout()`, from `addRequest()`.
 */
export function untilSocket(req: ClientRequest, destroyed: (error: Error | undefined) => void): void {
  const { destroy, setTimeout: setRequestTimeout } = req;
  let timer: NodeJS.Timeout | undefined;
  const arm = (ms: number | undefined) => {
    clearTimeout(timer);
    timer = ms ? setTimeout(() => req.emit('timeout'), ms) : undefined;
  };
  let finished = false;
  // A request that fails without a socket (the agent could not connect) closes without
  // `destroy()`; its timer ends then too, so no `'timeout'` follows its `'close'`. A method
  // the caller has wrapped since stays wrapped, and calls through to the original.
  const done = () => {
    finished = true;
    clearTimeout(timer);
    req.off('socket', done);
    req.off('close', done);
    if (req.destroy === watchedDestroy) req.destroy = destroy;
    if (req.setTimeout === watchedSetTimeout) req.setTimeout = setRequestTimeout;
  };
  const watchedDestroy = function (this: ClientRequest, ...args: Parameters<ClientRequest['destroy']>) {
    if (!finished) {
      done();
      destroyed(args[0]);
    }
    return destroy.apply(this, args);
  };
  const watchedSetTimeout = function (this: ClientRequest, ms: number, callback?: () => void) {
    setRequestTimeout.call(this, ms, callback);
    if (!finished) arm(ms);
    return this;
  };
  req.destroy = watchedDestroy;
  req.setTimeout = watchedSetTimeout as ClientRequest['setTimeout'];
  req.once('socket', done);
  req.once('close', done);
  arm((req as ClientRequest & { timeout?: number }).timeout);
}

/** `req`'s `Upgrade` value. A request made with its headers as an array has them in the stored
 * header alone, where `getHeader()` does not look. */
export function upgradeHeader(req: ClientRequest): OutgoingHttpHeader | undefined {
  const value = req.getHeader('upgrade');
  if (value !== undefined) return value;
  const head = internals(req)._header;
  return head ? /\r\nupgrade:[ \t]*([^\r]*)/i.exec(head)?.[1] : undefined;
}

export const PROXY_HEADERS = ['Proxy-Authorization', 'Proxy-Connection'] as const;

/** The error for a request that carries its own `Proxy-Authorization`. The route decides which
 * hop a request reaches, so such a value could go to the origin; a proxy's credentials go in
 * its URL or come from `proxyAuth`. */
export const proxyAuthorizationError = () =>
  Object.assign(new TypeError("a proxy's credentials go in its URL or come from proxyAuth, not in a Proxy-Authorization header"), {
    code: 'ERR_INVALID_ARG_VALUE',
  });

/** Whether `req` carries a `Proxy-Authorization`, set by name or in a headers array. */
export function hasProxyAuthorization(req: ClientRequest): boolean {
  return req.hasHeader('proxy-authorization') || /\r\nproxy-authorization:/i.test(internals(req)._header ?? '');
}

/** What a proxy agent changes on a request, kept to put back. The caller's other headers are
 * left as they are when it is put back, ones set since included. */
export interface SavedRequest {
  path: string;
  headers: Map<string, OutgoingHttpHeader | undefined>;
  header: string | null;
}

export function saveRequest(req: ClientRequest): SavedRequest {
  const raw = new Map(req.getRawHeaderNames().map((name) => [name.toLowerCase(), name]));
  return {
    path: req.path,
    headers: new Map(PROXY_HEADERS.map((name) => [raw.get(name.toLowerCase()) ?? name, req.getHeader(name)])),
    header: internals(req)._header,
  };
}

/**
 * Puts back what `saved` holds. A header stored since it was saved (the caller ended the
 * request while the agent had it rewritten) carries the rewrite, the proxy's credentials
 * among them; its rewrite is undone, the saved values of the proxy headers in place of the
 * rewrite's.
 */
export function restoreRequest(req: ClientRequest, saved: SavedRequest): void {
  const inner = internals(req);
  const head = inner._header;
  req.path = saved.path;
  inner._header = null;
  for (const [name, value] of saved.headers) {
    if (value === undefined) req.removeHeader(name);
    else if (req.getHeader(name) !== value) req.setHeader(name, value);
  }
  if (head === null) return;
  requeue(inner, head, saved.header ?? editHead(head, saved.path, saved.headers));
}

/**
 * Changes the request through `edit`, which sets its path and the proxy headers. A header
 * already stored is edited to match, in place and in the queued write that carries it; one
 * not stored yet is left to Node, so that the caller can still set headers and `end(body)`
 * still sends a `Content-Length`.
 */
export function rewriteHeader(req: ClientRequest, edit: () => void): void {
  const inner = internals(req);
  const head = inner._header;
  if (head === null) {
    edit();
    return;
  }
  inner._header = null;
  edit();
  const values = new Map<string, OutgoingHttpHeader | undefined>();
  for (const name of PROXY_HEADERS) {
    const value = req.getHeader(name);
    if (value !== undefined) values.set(name, value);
  }
  requeue(inner, head, editHead(head, req.path, values));
}

// `head`, a stored header, with `path` as its request target and the lines of each name in
// `values` replaced by its value, or dropped where it is `undefined`. Other lines stay as
// they are, in their order and spelling.
function editHead(head: string, path: string, values: Map<string, OutgoingHttpHeader | undefined>): string {
  const [line, ...fields] = head.slice(0, -4).split('\r\n');
  const names = new Set([...values.keys()].map((name) => name.toLowerCase()));
  const kept = fields.filter((field) => !names.has(field.slice(0, field.indexOf(':')).trim().toLowerCase()));
  for (const [name, value] of values) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) kept.push(`${name}: ${item}`);
  }
  // A function, so that a `$&` or `$1` in the path is not read as a replacement pattern.
  return [line.replace(/^(\S+) \S+/, (_, method: string) => `${method} ${path}`), ...kept].join('\r\n') + '\r\n\r\n';
}

// Stores `to` as the header in place of `from`, in the queued write that carries `from`
// too. A header marked sent and not found queued would go out as `from`, so that throws.
function requeue(inner: Internals, from: string, to: string): void {
  inner._header = to;
  const first = inner.outputData?.[0];
  if (first && typeof first.data === 'string' && first.data.startsWith(from)) {
    first.data = to + first.data.slice(from.length);
    inner.outputSize += to.length - from.length;
  } else if (inner._headerSent) {
    throw new Error('the request header is queued where the agent cannot rewrite it');
  }
}
