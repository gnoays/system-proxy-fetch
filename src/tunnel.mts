// A CONNECT tunnel through an HTTP or HTTPS proxy, shared by the agent and the dispatcher.
//
// A tunnel is handed over only once the proxy answers 2xx. Any other answer fails the
// tunnel and closes its connection, so the client's request, credentials included, never
// reaches a proxy that refused it; nor is the proxy's own answer passed off as the
// destination's.

import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { basicCredentials, type ProxyAuth } from './auth.mjs';
import type { PasswordState } from './core.mjs';

// Why a 407 went unanswered, where the settings say where the password is.
const UNREAD: Partial<Record<PasswordState, string>> = {
  InKeychain: 'the password is in the macOS keychain, which is not read',
  NotRead: "GNOME's stored password is not read",
};

/**
 * A proxy answered CONNECT with something other than 2xx. Never handed to the next step.
 * `passwordState` is what the settings say about the proxy's password, `null` where they
 * name no user; a `407` the settings left the password for says so in the message, and,
 * where no `proxyAuth` was there (`answerable` false), points to it.
 */
export class ProxyTunnelError extends Error {
  readonly code = 'ERR_PROXY_TUNNEL';
  readonly statusCode: number;
  readonly headers: Record<string, string[]>;
  readonly passwordState: PasswordState | null;

  constructor(
    proxy: URL,
    statusCode: number,
    headers: Record<string, string[]>,
    passwordState: PasswordState | null = null,
    answerable = false,
  ) {
    const unread = statusCode === 407 && passwordState ? UNREAD[passwordState] : undefined;
    const note = unread && (answerable ? unread : `${unread}; answer with proxyAuth`);
    super(`the proxy ${proxy.protocol}//${proxy.host} answered CONNECT with ${statusCode}${note ? `: ${note}` : ''}`);
    this.name = 'ProxyTunnelError';
    this.statusCode = statusCode;
    this.headers = headers;
    this.passwordState = passwordState;
  }
}

export interface TunnelOptions {
  /** An `http:` or `https:` proxy. Its user name and password go as `Basic` where
   * `basicCredentials` builds one: a password, or an empty one `passwordState` gives as
   * `Present`. A user name with a `:` in it throws. */
  proxy: URL;
  /** The destination, a host name or an IP address without brackets. */
  host: string;
  port: number;
  auth?: ProxyAuth;
  /** What the settings say about the proxy's password, for `auth` and for the error. */
  passwordState?: PasswordState | null;
  /** For the TLS connection to an `https:` proxy. */
  proxyTls?: tls.ConnectionOptions;
  /** For the connection to the proxy, of either scheme. */
  socketOptions?: ProxySocketOptions;
  /** Milliseconds for the whole exchange, connections and answers included. Past it the
   * tunnel fails with `ETIMEDOUT`. */
  timeout?: number;
  /** Ends the exchange, its connection closed, with the signal's reason. */
  signal?: AbortSignal;
}

const ROUNDS = 3;

const MAX_HEAD = 64 * 1024;

interface Answer {
  statusCode: number;
  headers: Record<string, string[]>;
  /** The proxy keeps the connection for another CONNECT: the whole answer was read and
   * neither side asked to close. */
  reusable: boolean;
}

const resetError = () =>
  Object.assign(new Error('the proxy closed the connection before it answered CONNECT'), { code: 'ECONNRESET' });

export function proxyAddress(proxy: URL): { host: string; port: number } {
  const host = proxy.hostname.replace(/^\[|\]$/g, '');
  const port = proxy.port ? Number(proxy.port) : proxy.protocol === 'https:' ? 443 : 80;
  return { host, port };
}

/** Where a connection to a proxy is made from, and how the proxy's name resolves. */
export type ProxySocketOptions = Pick<
  net.TcpSocketConnectOpts,
  'localAddress' | 'family' | 'lookup' | 'autoSelectFamily' | 'autoSelectFamilyAttemptTimeout'
>;

const PROXY_SOCKET_OPTIONS = [
  'localAddress',
  'family',
  'lookup',
  'autoSelectFamily',
  'autoSelectFamilyAttemptTimeout',
] as const;

export function proxySocketOptions(options: Record<string, unknown>): ProxySocketOptions {
  const picked: Record<string, unknown> = {};
  for (const name of PROXY_SOCKET_OPTIONS) if (options[name] !== undefined) picked[name] = options[name];
  return picked as ProxySocketOptions;
}

/** A connection to `proxy`, settled once it is open (for `https:`, once TLS is up).
 * `opened` sees the socket as soon as it exists, for a caller that may destroy it. A
 * socket option in `proxyTls` wins over the one in `socketOptions`. */
export async function dialProxy(
  proxy: URL,
  proxyTls?: tls.ConnectionOptions,
  opened: (socket: net.Socket) => void = () => {},
  socketOptions: ProxySocketOptions = {},
): Promise<net.Socket> {
  const { host, port } = proxyAddress(proxy);
  const secure = proxy.protocol === 'https:';
  const socket = secure
    ? tls.connect({
        ALPNProtocols: ['http/1.1'],
        ...socketOptions,
        ...proxyTls,
        host,
        port,
        servername: proxyTls?.servername ?? (net.isIP(host) ? undefined : host),
      })
    : net.connect({ ...socketOptions, host, port });
  opened(socket);
  try {
    await once(socket, secure ? 'secureConnect' : 'connect');
  } catch (error) {
    socket.destroy();
    throw error;
  }
  socket.setNoDelay(true);
  return socket;
}

function parseHead(text: string): Pick<Answer, 'statusCode' | 'headers'> & { version: string } {
  const [status, ...lines] = text.split('\r\n');
  const match = /^HTTP\/(\d\.\d) (\d{3})(?: |$)/.exec(status);
  if (!match) throw new Error(`the proxy answered CONNECT with no HTTP status line: ${JSON.stringify(status.slice(0, 80))}`);
  // No prototype: a header named `constructor` or `__proto__` is a header like any other.
  const headers: Record<string, string[]> = Object.create(null);
  let last: string[] | null = null;
  for (const line of lines) {
    // A line that starts with whitespace continues the field above it (obs-fold), which a
    // recipient reads as one space (RFC 9112 §5.2).
    if (/^[ \t]/.test(line) && last) {
      last[last.length - 1] = `${last[last.length - 1]} ${line.trim()}`.trim();
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Error(`the proxy answered CONNECT with a malformed header: ${JSON.stringify(line.slice(0, 80))}`);
    const name = line.slice(0, colon).trim().toLowerCase();
    last = headers[name] ??= [];
    last.push(line.slice(colon + 1).trim());
  }
  return { version: match[1], statusCode: Number(match[2]), headers };
}

// The challenges of `Proxy-Authenticate` values, one each. A value can list several, comma
// separated (RFC 9110 §11.6.1), and a comma also separates one challenge's parameters: a
// part starts a challenge where it opens with a scheme followed by a token68, a parameter or
// nothing, and continues the one before where it is itself a parameter (`name=`).
function challengesOf(values: string[]): string[] {
  const challenges: string[] = [];
  for (const value of values) {
    for (const part of value.match(/(?:[^",]|"(?:[^"\\]|\\.)*"?)+/g) ?? []) {
      const text = part.trim();
      if (!text) continue;
      const opens = /^[!#$%&'*+.^_`|~0-9a-z-]+(?:\s+[^=\s]|\s*$)/i.test(text);
      if (opens || challenges.length === 0) challenges.push(text);
      else challenges[challenges.length - 1] += `, ${text}`;
    }
  }
  return challenges;
}

const MAX_LINE = 4096;

// A reader of a chunked body (RFC 9112 §7.1) as it arrives. Each call takes the next bytes
// and returns where in them the body ends, `null` while it goes on, or `-1` where the bytes
// are not chunked framing. It keeps no chunk data and reads each byte once.
export function chunkedReader(): (bytes: Buffer) => number | null {
  // `size`: a chunk-size line; `data`: `left` bytes of a chunk; `crlf`: the line break after
  // them; `trailer`: trailer fields, up to the empty line that ends the body.
  let state: 'size' | 'data' | 'crlf' | 'trailer' = 'size';
  let line = '';
  let left = 0;
  return (bytes) => {
    let pos = 0;
    while (pos < bytes.length) {
      if (state === 'data') {
        const taken = Math.min(left, bytes.length - pos);
        pos += taken;
        left -= taken;
        if (left === 0) state = 'crlf';
        continue;
      }
      const eol = bytes.indexOf(0x0a, pos);
      const end = eol === -1 ? bytes.length : eol + 1;
      line += bytes.toString('latin1', pos, end);
      pos = end;
      if (line.length > MAX_LINE + 2) return -1;
      // A chunk's data ends at a line break and nothing else.
      if (state === 'crlf' && !'\r\n'.startsWith(line)) return -1;
      if (eol === -1) break;
      if (!line.endsWith('\r\n')) return -1;
      const text = line.slice(0, -2);
      line = '';
      if (state === 'crlf') {
        if (text !== '') return -1;
        state = 'size';
      } else if (state === 'trailer') {
        if (text === '') return pos;
      } else {
        const size = /^([0-9a-f]{1,8})[ \t]*(?:;.*)?$/i.exec(text);
        if (!size) return -1;
        left = parseInt(size[1], 16);
        state = left === 0 ? 'trailer' : 'data';
      }
    }
    return null;
  };
}

// The longest 407 body read to keep its connection; past it the connection is dropped.
const MAX_BODY = 1024 * 1024;

// Writes `request` and reads the answer's head. Where `answerable` (a session will answer
// another round), it also reads a framed 407 body, so the next CONNECT can reuse the
// connection, as NTLM and a multi-leg Negotiate need. The socket is left paused, with any
// bytes past the answer put back.
function exchange(socket: net.Socket, request: string, answerable: boolean): Promise<Answer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let searched = 0;
    let head: (ReturnType<typeof parseHead> & { length?: number; chunked?: boolean }) | null = null;
    let interim = 0;
    // The body is read as it arrives and not kept: `left` counts down a `Content-Length`,
    // `readChunked` follows chunked framing, and `read` counts the bytes against MAX_BODY.
    let left = 0;
    let readChunked: ReturnType<typeof chunkedReader> | null = null;
    let read = 0;
    const cleanup = () => {
      socket.pause();
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('close', onEnd);
      socket.off('error', onError);
    };
    const fail = (error: Error) => {
      cleanup();
      reject(error);
    };
    // `framed`: the body was read to the end its framing gives, so the connection is clear for
    // the next request.
    const finish = (rest: Buffer, ended: boolean, framed: boolean) => {
      cleanup();
      if (rest.length > 0) socket.unshift(rest);
      const { version, statusCode, headers } = head!;
      // A proxy can say it closes the connection in `Proxy-Connection` alone.
      const connection = [...(headers['connection'] ?? []), ...(headers['proxy-connection'] ?? [])].join(',').toLowerCase();
      const keep = version === '1.1' ? !/\bclose\b/.test(connection) : /\bkeep-alive\b/.test(connection);
      resolve({ statusCode, headers, reusable: !ended && keep && framed });
    };
    const onData = (chunk: Buffer) => {
      if (head) return readBody(chunk);
      buffer = Buffer.concat([buffer, chunk]);
      while (!head) {
        const end = buffer.indexOf('\r\n\r\n', searched);
        // A head over the limit fails whether or not its end has arrived in the same read.
        if (end === -1 ? buffer.length > MAX_HEAD : end > MAX_HEAD) {
          fail(new Error('the proxy answered CONNECT with a head too long to read'));
          return;
        }
        if (end === -1) {
          // The end can straddle this read and the next.
          searched = Math.max(0, buffer.length - 3);
          return;
        }
        try {
          head = parseHead(buffer.subarray(0, end).toString('latin1'));
        } catch (error) {
          fail(error as Error);
          return;
        }
        buffer = buffer.subarray(end + 4);
        searched = 0;
        // An interim answer (1xx but 101, RFC 9110 §15.2) has no body and comes before the
        // final one. The interim answers together are held to MAX_HEAD, as one head is.
        if (head.statusCode < 200 && head.statusCode !== 101) {
          head = null;
          interim += end + 4;
          if (interim > MAX_HEAD) {
            fail(new Error('the proxy answered CONNECT with interim answers too long to read'));
            return;
          }
          continue;
        }
        const lengths = head.headers['content-length'];
        const codings = (head.headers['transfer-encoding'] ?? []).join(',').split(',');
        if (codings.length > 1 || codings[0] !== '') {
          // Chunked only where it is the last coding; any other body runs to the close.
          head.chunked = codings[codings.length - 1].trim().toLowerCase() === 'chunked';
        } else if (lengths?.length === 1 && /^\d+$/.test(lengths[0])) {
          head.length = Number(lengths[0]);
        }
      }
      const past = buffer;
      buffer = Buffer.alloc(0);
      // A 2xx answer to CONNECT has no body: what follows it is the tunnel's.
      if (head.statusCode >= 200 && head.statusCode < 300) return finish(past, false, true);
      // Only a 407 that a session will answer is read on. Any other refusal ends the exchange
      // at its head, without waiting on a body that may be slow, large or never sent.
      if (head.statusCode !== 407 || !answerable) return finish(Buffer.alloc(0), false, false);
      if (head.chunked) readChunked = chunkedReader();
      else if (head.length === undefined || head.length > MAX_BODY) return finish(Buffer.alloc(0), false, false);
      else left = head.length;
      readBody(past);
    };
    // Reads the next bytes of a 407's body; past its end, they are the next answer's.
    const readBody = (bytes: Buffer) => {
      if (readChunked) {
        const end = readChunked(bytes);
        read += end ?? bytes.length;
        if (end === -1 || read > MAX_BODY) return finish(Buffer.alloc(0), false, false);
        if (end !== null) finish(bytes.subarray(end), false, true);
        return;
      }
      if (bytes.length < left) {
        left -= bytes.length;
        return;
      }
      finish(bytes.subarray(left), false, true);
    };
    // A connection that closes after the head ends the answer; one that closes before it
    // never answered.
    const onEnd = () => (head ? finish(Buffer.alloc(0), true, false) : fail(resetError()));
    const onError = (error: Error) => fail(error);
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('close', onEnd);
    socket.on('error', onError);
    socket.resume();
    socket.write(request);
  });
}

function checkHeaderValue(value: string): string {
  if (/[\r\n]/.test(value)) throw new TypeError('a Proxy-Authorization value has a line break in it');
  return value;
}

/**
 * A connection to `host:port` through `proxy`'s CONNECT, answering `407`s through `auth`,
 * up to three. The socket is paused; whoever reads it next resumes it. `timeout` covers
 * the waits on `auth` as well as the proxy; one still running when it passes is left to
 * finish, and its answer is dropped. `signal` ends it the same way.
 */
export async function openTunnel({
  proxy,
  host,
  port,
  auth,
  passwordState = null,
  proxyTls,
  socketOptions,
  timeout,
  signal,
}: TunnelOptions): Promise<net.Socket> {
  signal?.throwIfAborted();
  let socket: net.Socket | null = null;
  let expired: Error | null = null;
  // Settles, by rejecting, only when `timeout` passes or `signal` aborts; `within` races a
  // wait that holds no socket (`auth`'s answers, which can be a prompt or a KDC) against it.
  let expire: (error: Error) => void = () => {};
  const deadline = new Promise<never>((_, reject) => (expire = reject));
  deadline.catch(() => {});
  const end = (error: Error) => {
    expired ??= error;
    socket?.destroy(expired);
    expire(expired);
  };
  const timer =
    timeout === undefined
      ? undefined
      : setTimeout(
          () => end(Object.assign(new Error(`the tunnel took longer than ${timeout} ms`), { code: 'ETIMEDOUT' })),
          timeout,
        );
  const onAbort = () => end(signal!.reason);
  signal?.addEventListener('abort', onAbort, { once: true });
  const settled = () => {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  };
  const within = <T,>(waiting: Promise<T>): Promise<T> => Promise.race([waiting, deadline]);
  // `within`, while `connection` waits between exchanges: an error on it then (the timeout's
  // destroy, a reset) surfaces on the next CONNECT or as the timeout, not as an unhandled
  // error.
  const holding = async <T,>(connection: net.Socket, waiting: Promise<T>): Promise<T> => {
    const ignore = () => {};
    connection.on('error', ignore);
    try {
      return await within(waiting);
    } finally {
      connection.off('error', ignore);
    }
  };
  const dial = async () => {
    if (expired) throw expired;
    return dialProxy(proxy, proxyTls, (opened) => (socket = opened), socketOptions);
  };
  try {
    const target = `${net.isIPv6(host) ? `[${host}]` : host}:${port}`;
    const session = auth?.start(proxy, target, { passwordState });
    // With no first answer from `auth`, the URL's `Basic` is built before dialling: a user name
    // it refuses throws whether or not the proxy is up, where a refused connection would hand
    // the request to the next step.
    const basic = session?.initial ? undefined : basicCredentials(proxy, passwordState);
    let current = await dial();
    // Whether `current` has carried no exchange yet.
    let fresh = true;
    let credentials = session?.initial
      ? ((await holding(current, session.initial())) ?? basicCredentials(proxy, passwordState))
      : basic;
    for (let round = 0; ; round += 1) {
      if (current.destroyed) {
        current = await dial();
        fresh = true;
      }
      const lines = [`CONNECT ${target} HTTP/1.1`, `Host: ${target}`];
      if (credentials !== undefined) lines.push(`Proxy-Authorization: ${checkHeaderValue(credentials)}`);
      const request = `${lines.join('\r\n')}\r\n\r\n`;
      const answerable = Boolean(session) && round < ROUNDS;
      let answer: Answer;
      try {
        answer = await exchange(current, request, answerable);
      } catch (error) {
        // A kept connection that closes before it answers had closed before it read this
        // CONNECT, as a stale keep-alive connection does (RFC 9112 §9.3.1): the CONNECT goes
        // again, once, on a new connection, rather than counting as a proxy that is down.
        const code = (error as { code?: unknown }).code;
        if (fresh || expired || (code !== 'ECONNRESET' && code !== 'EPIPE')) throw error;
        current.destroy();
        current = await dial();
        answer = await exchange(current, request, answerable);
      }
      fresh = false;
      if (answer.statusCode >= 200 && answer.statusCode < 300) {
        // A timeout or an abort can land between the answer and this line, and closes `current`.
        if (expired) throw expired;
        settled();
        return current;
      }
      if (answer.statusCode === 407 && session && round < ROUNDS) {
        if (!answer.reusable) current.destroy();
        // `null` from a JavaScript caller gives up too, as `initial()`'s does.
        credentials =
          (await holding(current, session.respond(challengesOf(answer.headers['proxy-authenticate'] ?? []), answer.reusable))) ??
          undefined;
        if (expired) throw expired;
        if (credentials !== undefined) continue;
      }
      throw new ProxyTunnelError(proxy, answer.statusCode, answer.headers, passwordState, Boolean(session));
    }
  } catch (error) {
    settled();
    (socket as net.Socket | null)?.destroy();
    throw error;
  }
}

/** TLS to the destination over `socket`, a tunnel from `openTunnel`. Options `tls` refuses
 * (`minVersion: 'foo'`) throw, and close the tunnel. */
export function secureTunnel(socket: net.Socket, options: tls.ConnectionOptions): tls.TLSSocket {
  let secure: tls.TLSSocket;
  try {
    secure = tls.connect({ ...options, socket });
  } catch (error) {
    socket.destroy();
    throw error;
  }
  // The tunnel comes paused; TLS reads it from here. Bun does not read a paused socket it
  // wraps, and its handshake never ends.
  socket.resume();
  return secure;
}
