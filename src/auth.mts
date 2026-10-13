// How a client answers a proxy's `407` to CONNECT.

import type { PasswordState } from './core.mjs';
import {
  negotiateClient,
  negotiateStep,
  proxySpn,
  type KerberosClient,
  type KerberosModule,
  type NegotiateMechanism,
} from './negotiate.mjs';

export type { PasswordState } from './core.mjs';
export type { KerberosClient, KerberosModule } from './negotiate.mjs';

export type { NegotiateMechanism } from './negotiate.mjs';

/**
 * Answers a proxy's `407` to CONNECT. `start` runs once for each tunnel opened through a
 * proxy, and never for a direct step or for a plain `http:` request forwarded by an HTTP
 * proxy, which takes the `Basic` credentials of the proxy URL alone. `target` is the
 * CONNECT request target, `host:port` with an IPv6 host in brackets, as Digest's `uri`
 * needs it. A proxy URL with a user name and no password is passed with the user name,
 * for a session that finds the password elsewhere; `context.passwordState` says where the
 * settings left it.
 */
export interface ProxyAuth {
  start(proxy: URL, target: string, context: ProxyAuthContext): ProxyAuthSession;
}

/** What the settings say about the proxy `start` is called for. */
export interface ProxyAuthContext {
  /** Why the proxy URL has no password, or `Present` when it has one; `null` where the
   * settings give no user name, or the step came from a PAC script. `InKeychain`: macOS
   * keeps the password in the keychain. `NotRead`: GNOME holds one in dconf that
   * `proxy-watch` does not read. Neither is fetched by this package. */
  passwordState: PasswordState | null;
}

/** One tunnel's exchange with its proxy. */
export interface ProxyAuthSession {
  /** The `Proxy-Authorization` the first CONNECT carries, in place of the `Basic`
   * credentials of the proxy URL. `undefined` keeps those. */
  initial?(): Promise<string | undefined>;
  /**
   * The `Proxy-Authorization` for the next CONNECT, given the challenges of a `407`, one
   * element each, a header that lists several split into them; `undefined` gives up, and
   * the request fails with the 407. `sameConnection` is false when the next CONNECT goes on
   * a new connection: the proxy closed this one, or its 407 could not be read to the end (no
   * length, a body over 1 MiB, or chunked framing that does not parse) and the client closed
   * it. A scheme bound to its connection, as NTLM is, starts over there or gives up. A proxy
   * can also close the connection while `respond` runs; the answer then goes on a new one,
   * where a scheme bound to the old one gets a fresh challenge and gives up. Called at most
   * three times for one tunnel.
   */
  respond(challenges: string[], sameConnection: boolean): Promise<string | undefined>;
}

/**
 * A URL's user name or password, percent-decoded. A run of escapes that does not decode
 * (`%zz`, or bytes that are not UTF-8) stays as written: the settings hand over what a user
 * typed into `http_proxy`, and a malformed escape there should cost that escape, not the
 * request.
 */
export function decodeUserinfo(text: string): string {
  return text.replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run;
    }
  });
}

/**
 * `step` with its user name and password escaped anew from what `decodeUserinfo` reads, for
 * a library that decodes them with `decodeURIComponent` (the SOCKS agents), so a malformed
 * escape reaches it as the characters it stands for instead of throwing there.
 */
export function withValidEscapes(step: string): string {
  const url = new URL(step);
  if (!url.username && !url.password) return step;
  url.username = encodeURIComponent(decodeUserinfo(url.username));
  url.password = encodeURIComponent(decodeUserinfo(url.password));
  return url.href;
}

/**
 * The `Basic` credentials of `proxy`'s URL, if it has a password. A user name alone sends
 * nothing: on macOS the settings carry the user name and the keychain the password, and a
 * `Basic` with an empty password on every request is a failed login each time, which a
 * directory can count towards locking the account. An empty password the settings give as
 * one (`http://alice:@proxy`, `passwordState` `Present`) goes as written: a URL cannot
 * keep it apart from no password, and the settings can. A user name with a `:` in it (`%3A`
 * in the URL) throws, as for `basicAuth`: the proxy would read the rest as the password.
 */
export function basicCredentials(proxy: URL, passwordState: PasswordState | null = null): string | undefined {
  if (!proxy.password && !(passwordState === 'Present' && proxy.username)) return undefined;
  const user = decodeUserinfo(proxy.username);
  if (user.includes(':')) throw colonError();
  return `Basic ${Buffer.from(`${user}:${decodeUserinfo(proxy.password)}`).toString('base64')}`;
}

const colonError = () => new TypeError('a Basic user name cannot contain ":"');

/** What `basicAuth` asks its lookup for when a proxy answers CONNECT with `407 Basic`. */
export interface BasicAuthRequest {
  /** The proxy, its user name included. */
  proxy: URL;
  /** The CONNECT target, `host:port`. */
  target: string;
  /** The proxy URL's user name, decoded; `null` when it has none. */
  username: string | null;
  /** Where the settings left the password, as for `ProxyAuthContext`. */
  passwordState: PasswordState | null;
  /** The challenge's `realm`, `null` when it names none. */
  realm: string | null;
}

/** A password for the proxy URL's user name, or a user name and password. */
export type BasicCredentials = string | { username: string; password: string };

/** One of the challenge strings `respond` gets, parsed (RFC 9110 §11.2). */
export interface Challenge {
  /** The scheme, lower-cased. */
  scheme: string;
  /** The token68 after the scheme, if the challenge carries one in place of parameters. */
  token68?: string;
  /** The parameters by lower-cased name, quoted values unquoted; the first of a repeated name. */
  params: Map<string, string>;
}

// A token68 stands alone up to the challenge's end or a comma. `realm=x` is not one: the
// `=` of a token68 only pads its end.
const TOKEN68 = /^([A-Za-z0-9._~+/-]+=*)\s*(?:,|$)/;
// A name starts at the start or after a separator. Tried from every position, a long run with
// no `=` is rescanned from each character, quadratic in a header of up to 64 KiB.
const PARAM = /(?:^|[\s,])([^\s=,]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))/g;

/** `text`, one challenge, read into its scheme and its token68 or parameters. */
export function parseChallenge(text: string): Challenge {
  const [, scheme = '', rest = ''] = /^([^\s,]*)\s*([\s\S]*)$/.exec(text.trim()) ?? [];
  const params = new Map<string, string>();
  const token68 = TOKEN68.exec(rest)?.[1];
  if (token68 !== undefined) return { scheme: scheme.toLowerCase(), token68, params };
  for (const [, name, quoted, plain] of rest.matchAll(PARAM)) {
    const key = name.toLowerCase();
    if (!params.has(key)) params.set(key, quoted === undefined ? plain : quoted.replace(/\\(.)/g, '$1'));
  }
  return { scheme: scheme.toLowerCase(), params };
}

const findChallenge = (challenges: string[], scheme: string): Challenge | undefined =>
  challenges.map(parseChallenge).find((challenge) => challenge.scheme === scheme);

/**
 * Answers `407 Basic` with what `lookup` returns, as a keychain or a prompt would supply
 * it. `lookup` runs only when a proxy asks for Basic, once for each tunnel, so a store that
 * asks the user for consent asks only then. `undefined` gives up, and the request fails
 * with the 407. A 407 after the answer is not answered again: the proxy refused those
 * credentials, and sending them again would count as another failed login. A proxy URL
 * with a password sends its own `Basic` first, and `lookup` answers the 407 to that: a
 * `lookup` that returns the same pair sends it a second time. A user name with a `:` in it
 * throws, as Basic cannot carry one (RFC 7617).
 */
export function basicAuth(
  lookup: (request: BasicAuthRequest) => BasicCredentials | undefined | Promise<BasicCredentials | undefined>,
): ProxyAuth {
  return {
    start(proxy, target, { passwordState }) {
      let answered = false;
      return {
        async respond(challenges) {
          const challenge = findChallenge(challenges, 'basic');
          if (answered || challenge === undefined) return undefined;
          answered = true;
          const username = proxy.username ? decodeUserinfo(proxy.username) : null;
          const found = await lookup({
            proxy,
            target,
            username,
            passwordState,
            realm: challenge.params.get('realm') ?? null,
          });
          if (found === undefined) return undefined;
          const user = typeof found === 'string' ? username : found.username;
          const password = typeof found === 'string' ? found : found.password;
          if (user === null) {
            throw new TypeError('basicAuth: the proxy URL names no user; return { username, password }');
          }
          if (user.includes(':')) throw new TypeError('basicAuth: a Basic user name cannot contain ":"');
          return `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
        },
      };
    },
  };
}

export interface NegotiateAuthOptions {
  /** `'spnego'` (the default) lets Windows fall back to NTLM inside SPNEGO where Kerberos
   * cannot be used; that takes a second round trip on the same connection, which a proxy
   * that closes it after its 407 does not allow.
   * `'kerberos'` sends a Kerberos token alone, so that no NTLM ever leaves; a proxy that
   * cannot take Kerberos then fails the request. */
  mechanism?: NegotiateMechanism;
  /** The `kerberos` package, for a bundle that cannot load an optional dependency by
   * name. Default: `import('kerberos')` when a proxy first asks. */
  kerberos?: KerberosModule;
}

/**
 * Answers a `407 Negotiate` through the optional `kerberos` package, as `HTTP/<proxy host>`
 * on Windows and `HTTP@<proxy host>` elsewhere. Each tunnel has one security context, and
 * a `407` that carries the proxy's token is answered by the next step of it, on the same
 * connection only: Kerberos finishes in one round trip, NTLM inside SPNEGO in two. A bare
 * `Negotiate` after a token was sent means the proxy refused it, and is not answered.
 */
export function negotiateAuth({ mechanism = 'spnego', kerberos }: NegotiateAuthOptions = {}): ProxyAuth {
  if (mechanism !== 'spnego' && mechanism !== 'kerberos') {
    throw Object.assign(new TypeError(`mechanism is 'spnego' or 'kerberos', not ${JSON.stringify(mechanism)}`), {
      code: 'ERR_INVALID_ARG_VALUE',
    });
  }
  return {
    start(proxy) {
      const spn = proxySpn(proxy.hostname.replace(/^\[|\]$/g, ''));
      let client: KerberosClient | null = null;
      return {
        async respond(challenges, sameConnection) {
          const challenge = findChallenge(challenges, 'negotiate');
          if (challenge === undefined) return undefined;
          // A `Negotiate` with parameters and no token68 carries no token.
          const token = challenge.token68 ?? '';
          let answer: string;
          if (client === null) {
            // A token before any of ours belongs to no context of this tunnel's.
            if (token) return undefined;
            client = await negotiateClient(spn, mechanism, kerberos);
            answer = await negotiateStep(spn, client, '');
          } else {
            // The context lives on the connection that carried it.
            if (!token || !sameConnection || client.contextComplete) return undefined;
            answer = await negotiateStep(spn, client, token);
          }
          return answer === 'Negotiate ' ? undefined : answer;
        },
      };
    },
  };
}
