// What every adapter shares: the snapshot to route by, its generation, and the steps one
// request tries. A route is never widened to direct: a PAC configuration no engine ran,
// and a route whose every proxy the client cannot speak, are errors.

import native from 'proxy-watch';
import type { PacPolicy, Route, Snapshot, Watcher } from 'proxy-watch';
import { decodeUserinfo } from './auth.mjs';
import { PAC_TIMEOUT, fetchPac } from './pacfetch.mjs';

export type { PacPolicy, Route, Snapshot } from 'proxy-watch';

export interface RoutesOptions {
  /** Who runs a PAC configuration, as for `Snapshot.route`: `'auto'` (the default) runs the
   * OS's engine where it has one, else QuickJS; `'none'` runs none. A script the
   * configuration names by URL and the OS's engine does not run is fetched for QuickJS
   * (`'auto'` or `'quickjs'`), direct, once per change to the settings; a fetch that fails
   * is tried again by the next request, and a script that fails to run is fetched again
   * 5 s after it was fetched. */
  pac?: 'none' | 'native' | 'quickjs' | 'auto';
  /** Watch the settings (the default), or read them once. */
  watch?: boolean;
  /** As for `proxy-watch`'s `read()`. */
  env?: Record<string, string | undefined>;
  precedence?: 'before-system' | 'after-system' | 'ignore';
  /** Also re-read the settings on this interval, as for `proxy-watch`'s `watch()`; unused
   * with `watch: false`. Without it, a Flatpak or Snap sandbox keeps the first settings it
   * reads, and a Linux session without a D-Bus session bus fails to start the watch. */
  pollIntervalMs?: number;
  /** As for `Snapshot.route`: a PAC body run in place of the configuration's. */
  script?: string;
  /** As for `Snapshot.route`: let the OS discover a script by WPAD. */
  wpad?: boolean;
  /** As for `Snapshot.route`: what QuickJS runs a script under. Its defaults answer as if
   * off every network, so a script that chooses a proxy by network goes direct. */
  policy?: PacPolicy;
}

// Typed so that a key `RoutesOptions` gains and this misses fails to compile.
const ROUTES_KEYS: { [K in keyof RoutesOptions]-?: true } = {
  pac: true,
  watch: true,
  env: true,
  precedence: true,
  pollIntervalMs: true,
  script: true,
  wpad: true,
  policy: true,
};

export const ROUTES_OPTIONS = Object.keys(ROUTES_KEYS) as (keyof RoutesOptions)[];

/** The `RoutesOptions` of `options`, and its own options besides them, as destructuring
 * them with a rest element would split it. */
export function splitRoutesOptions<T extends RoutesOptions>(options: T): [RoutesOptions, Omit<T, keyof RoutesOptions>] {
  const picked: Record<string, unknown> = {};
  const others: Record<string, unknown> = { ...(options as object) };
  for (const key of ROUTES_OPTIONS) {
    picked[key] = options[key];
    delete others[key];
  }
  return [picked as RoutesOptions, others as Omit<T, keyof RoutesOptions>];
}

/** Throws `ERR_INVALID_ARG_VALUE` for a `Routes` option set beside `routes`: the watcher it
 * would go to is the one `routes` replaces. */
export function checkRoutesAlone(routes: unknown, routesOptions: RoutesOptions): void {
  if (routes == null) return;
  const name = Object.entries(routesOptions).find(([, value]) => value !== undefined)?.[0];
  if (name !== undefined) {
    throw Object.assign(new TypeError(`${name} is an option of the watcher, which routes replaces; give it to that Routes`), {
      code: 'ERR_INVALID_ARG_VALUE',
    });
  }
}

/**
 * What a proxy's missing password means, as the settings say: `Absent`, none was given;
 * `NotRead`, GNOME holds one that `proxy-watch` does not read; `InKeychain`, macOS keeps
 * it in the keychain, which `proxy-watch` does not open. `Present` when the URL has it.
 */
export type PasswordState = 'Present' | 'Absent' | 'NotRead' | 'InKeychain';

/** One proxy entry of `Snapshot.toJSON()`, the part {@link passwordStates} reads. */
export interface EntryJson {
  kind: string;
  host?: string;
  port?: number;
  username?: string | null;
  passwordState?: string | null;
}
/** The part of `Snapshot.toJSON()` {@link passwordStates} reads. */
export interface SnapshotJson {
  mode?: { kind: string; proxies?: Record<string, EntryJson> };
}

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443 };

// A proxy by host, port and user name, the same for a route step and a settings entry.
const credentialKey = (host: string, port: number, username: string) =>
  `${host.replace(/^\[|\]$/g, '')}:${port}|${username}`;

function stepKey(step: string): string | null {
  if (step === 'direct') return null;
  const url = new URL(step);
  if (!url.username) return null;
  const scheme = schemeOf(step);
  const port = url.port ? Number(url.port) : (DEFAULT_PORTS[scheme] ?? 1080);
  return credentialKey(url.hostname, port, decodeUserinfo(url.username));
}

/** The `passwordState` of each proxy a snapshot's manual settings name with a user name,
 * keyed as `stepKey` keys a route step. Steps a PAC script names carry no user name. */
export function passwordStates(json: SnapshotJson | undefined): Map<string, PasswordState> {
  const states = new Map<string, PasswordState>();
  if (json?.mode?.kind !== 'manual') return states;
  for (const entry of Object.values(json.mode.proxies ?? {})) {
    if (entry.kind !== 'use' || !entry.username || !entry.host || entry.port === undefined) continue;
    states.set(credentialKey(entry.host, entry.port, entry.username), entry.passwordState as PasswordState);
  }
  return states;
}

/** Which proxy schemes a client speaks, by lower-cased scheme. */
export type Speaks = (scheme: string) => boolean;

/** The route names nothing this client can take, or is a PAC script and no PAC engine ran
 * it. Never answered by going direct. */
export class RouteError extends Error {
  readonly code = 'ERR_PROXY_ROUTE';

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RouteError';
  }
}

export const isWebSocket = (upgrade: unknown): boolean =>
  /(?:^|,)\s*websocket\s*(?:,|$)/i.test(String(upgrade ?? ''));

/**
 * The URL of a request for `path` to `origin` (`scheme://host[:port]`), joined as written.
 * Read as a URL reference instead, `//other.example/x` names another host and dot-segments
 * and backslashes are rewritten, so the route and a forwarding proxy's target would follow a
 * host the request does not go to. `*` (`OPTIONS *`) is the origin itself.
 */
export function requestUrl(origin: string, path: string): string {
  if (path === '*') return origin;
  return origin + (path.startsWith('/') ? path : `/${path}`);
}

// The longest delay `setTimeout` takes; anything above it, or not a positive finite number,
// fires at once, which would hand every step but the last on before it could answer.
const MAX_TIMER_MS = 2 ** 31 - 1;

/** `value` if it is a usable `connectTimeout`, else an `ERR_INVALID_ARG_VALUE` RangeError. */
export function checkTimeout(name: string, value: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > MAX_TIMER_MS) {
    throw Object.assign(new RangeError(`${name} must be a number of milliseconds above 0 and at most ${MAX_TIMER_MS}`), {
      code: 'ERR_INVALID_ARG_VALUE',
    });
  }
  return value;
}

// Failures of a step's connection, the proxy's CONNECT included, after which the next step
// can take the request. A 407, any other refusal of CONNECT, and a certificate the client
// rejects are not among them.
export const CONNECT_CODES: ReadonlySet<string> = new Set([
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
]);

/** Whether `error` carries one of `codes`, itself or as its `cause`. An `AggregateError`, from
 * connecting to each address of a name in turn, counts when any of its attempts does. */
export const isConnectError = (error: any, codes: ReadonlySet<string> = CONNECT_CODES): boolean =>
  codes.has(error?.code) ||
  codes.has(error?.cause?.code) ||
  (Array.isArray(error?.errors) && error.errors.some((item: unknown) => isConnectError(item, codes)));

export const schemeOf = (step: string): string => step.split('://', 1)[0].toLowerCase();

/** The steps of `route` this client can take, in order. Throws `RouteError` for a PAC
 * configuration no engine ran, and for a route none of whose steps the client speaks. */
export function usableSteps(route: Route, speaks: Speaks): string[] {
  if (route.kind !== 'steps') {
    throw new RouteError(`the configuration is ${route.kind} and no PAC engine ran it`);
  }
  const usable = route.steps.filter((step) => step === 'direct' || speaks(schemeOf(step)));
  if (usable.length === 0) {
    const schemes = [...new Set(route.steps.map(schemeOf))].sort().join(', ');
    throw new RouteError(`this client speaks none of the proxies the route names: ${schemes}`);
  }
  return usable;
}

// How many times a request reads its route again when the settings change while a PAC
// engine answers it. Past that it keeps the last answer, or its failure.
const REREADS = 2;

// How long a fetched script that failed to run is kept before a request fetches it again;
// Firefox's first retry of a PAC script it could not load is 5 s too.
const PAC_RETRY_MS = 5_000;

// A PAC script fetched for `url` under one generation of the settings.
interface FetchedScript {
  generation: number;
  url: string;
  fetchedAt: number;
  // Set when the script failed to run.
  unusable: boolean;
  body: Promise<string>;
}

/**
 * The snapshot to route by, kept current by a `proxy-watch` watcher, and its generation,
 * which moves on each change. A failed re-read keeps the snapshot before it in use and is
 * kept in `error` until the next change; a watch that stops on its own leaves its last
 * error there for good.
 */
export class Routes {
  pac: NonNullable<RoutesOptions['pac']>;
  generation = 0;
  error: Error | null = null;
  #snapshot: Snapshot;
  #watcher: Watcher | null = null;
  #routeOptions;
  #states: { generation: number; states: Map<string, PasswordState> } | null = null;
  #script: FetchedScript | null = null;
  #closed = new AbortController();

  constructor({
    pac = 'auto',
    watch = true,
    env,
    precedence,
    pollIntervalMs,
    script,
    wpad,
    policy,
  }: RoutesOptions = {}) {
    this.pac = pac;
    this.#routeOptions = { pac, script, wpad, policy };
    // Requests pass these to `Snapshot.route` only once the settings turn to PAC, so a bad
    // value would fail every request from then on. They are checked here, against a snapshot
    // `all_proxy` alone answers (`before-system` puts it first). A missing engine still
    // shows only when PAC runs.
    if (pac !== 'auto' || script !== undefined || wpad !== undefined || policy !== undefined) {
      native
        .readSync({ env: { all_proxy: 'http://options.invalid' }, precedence: 'before-system' })
        .route('http://options.invalid/', this.#routeOptions);
    }
    const options = { env, precedence };
    if (watch) {
      this.#watcher = native.watchSync(
        (err, snapshot) => {
          if (err) {
            this.error = err;
            return;
          }
          this.#snapshot = snapshot!;
          this.error = null;
          this.generation += 1;
        },
        { ...options, pollIntervalMs },
      );
      this.#snapshot = this.#watcher.current();
    } else {
      this.#snapshot = native.readSync(options);
    }
  }

  /** The snapshot to route by and its generation, read together. */
  current(): { snapshot: Snapshot; generation: number } {
    return { snapshot: this.#snapshot, generation: this.generation };
  }

  /**
   * `snapshot`'s route for `url`, off the event loop when a PAC engine runs. A route with
   * no PAC mode in it is answered on this thread: `routeAsync` queues on the libuv pool,
   * behind DNS lookups and fs work, and holds a pool thread that they wait behind.
   */
  async route(snapshot: Pick<Snapshot, 'route' | 'routeAsync'>, url: string): Promise<Route> {
    const route = snapshot.route(url);
    if (this.pac === 'none' || route.kind === 'steps') return route;
    const answer = await snapshot.routeAsync(url, this.#routeOptions);
    if (answer.kind !== 'pac' || this.pac === 'native' || this.#routeOptions.script !== undefined) return answer;
    const fetched = this.#fetchScript(answer.pacUrl);
    const script = await fetched.body;
    try {
      return await snapshot.routeAsync(url, { ...this.#routeOptions, script });
    } catch (error) {
      // What the server sent may be no script (a captive portal's page, for one), which no
      // later request could run either; it is fetched again, as a failed fetch is.
      fetched.unusable = true;
      throw error;
    }
  }

  // The script at `url`, fetched once per generation. A failed fetch is tried again by the
  // next request; a script that failed to run, by the first request `PAC_RETRY_MS` after
  // it was fetched, so a server that keeps sending a bad one is asked at most that often.
  #fetchScript(url: string): FetchedScript {
    const generation = this.generation;
    const kept = this.#script;
    if (
      kept?.generation === generation &&
      kept.url === url &&
      !(kept.unusable && Date.now() - kept.fetchedAt >= PAC_RETRY_MS)
    ) {
      return kept;
    }
    const signal = AbortSignal.any([this.#closed.signal, AbortSignal.timeout(PAC_TIMEOUT)]);
    const entry: FetchedScript = {
      generation,
      url,
      fetchedAt: Date.now(),
      unusable: false,
      body: fetchPac(url, signal).catch((error) => {
        if (this.#script === entry) this.#script = null;
        const shown = new URL(url);
        if (shown.password) shown.password = '***';
        throw new RouteError(`the PAC script at ${shown} could not be fetched`, { cause: error });
      }),
    };
    this.#script = entry;
    return entry;
  }

  /** The steps of `url`'s route this client can take, in order. */
  async steps(snapshot: Snapshot, url: string, speaks: Speaks): Promise<string[]> {
    return usableSteps(await this.route(snapshot, url), speaks);
  }

  /**
   * The steps of `url`'s route by the newest snapshot, and that snapshot's generation. A
   * change while the route is computed reads it again, up to `REREADS` times, whether the
   * older snapshot's route came out or failed.
   */
  async resolve(url: string, speaks: Speaks): Promise<{ steps: string[]; generation: number }> {
    for (let reread = 0; ; reread += 1) {
      const { snapshot, generation } = this.current();
      let steps: string[];
      try {
        steps = await this.steps(snapshot, url, speaks);
      } catch (error) {
        if (reread < REREADS && this.generation !== generation) continue;
        throw error;
      }
      if (reread === REREADS || this.generation === generation) return { steps, generation };
    }
  }

  /**
   * The `passwordState` the current settings give `step`'s proxy, or `null` where they
   * give none: `direct`, a step with no user name, or one a PAC script named.
   */
  passwordState(step: string): PasswordState | null {
    const key = stepKey(step);
    if (key === null) return null;
    if (this.#states?.generation !== this.generation) {
      this.#states = { generation: this.generation, states: passwordStates(this.#snapshot.toJSON()) };
    }
    return this.#states.states.get(key) ?? null;
  }

  close(): void {
    this.#closed.abort();
    this.#watcher?.close();
  }
}
