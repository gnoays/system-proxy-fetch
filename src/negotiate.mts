// Negotiate (Kerberos, or NTLM inside SPNEGO) tokens for a proxy, through the optional
// `kerberos` package.

/** The part of the `kerberos` package used here. It is an optional peer dependency with
 * no type declarations of its own; `negotiateAuth` also takes it passed in. */
export interface KerberosModule {
  GSS_MECH_OID_KRB5: number;
  GSS_MECH_OID_SPNEGO: number;
  initializeClient(service: string, options: { mechOID: number }): Promise<KerberosClient>;
}

/** One security context. `step` takes the proxy's token (empty for the first) and gives
 * the next one to send. */
export interface KerberosClient {
  step(challenge: string): Promise<string>;
  contextComplete?: boolean;
}

// A specifier the type checker does not resolve, so that a missing `kerberos` is a run-time
// error rather than a build error.
const KERBEROS: string = 'kerberos';

/** What a Negotiate token carries: SPNEGO, which Windows can fill with NTLM where Kerberos
 * cannot be used, or a Kerberos token alone. */
export type NegotiateMechanism = 'spnego' | 'kerberos';

/** A proxy's service principal for Negotiate: SSPI takes `HTTP/host`, GSSAPI the host-based
 * form `HTTP@host`. */
export const proxySpn = (host: string): string =>
  process.platform === 'win32' ? `HTTP/${host}` : `HTTP@${host}`;

/** A security context for `spn`, from `kerberos` or else the installed package. Every
 * failure names `spn`, the part a misconfiguration is usually in. */
export async function negotiateClient(
  spn: string,
  mechanism: NegotiateMechanism,
  kerberos?: KerberosModule,
): Promise<KerberosClient> {
  if (!kerberos) {
    try {
      const loaded = await import(KERBEROS);
      kerberos = (loaded.default ?? loaded) as KerberosModule;
    } catch {
      throw new Error(`Negotiate as ${spn} needs the kerberos package (npm install kerberos)`);
    }
  }
  const mechOID = mechanism === 'kerberos' ? kerberos.GSS_MECH_OID_KRB5 : kerberos.GSS_MECH_OID_SPNEGO;
  try {
    return await kerberos.initializeClient(spn, { mechOID });
  } catch (error) {
    throw negotiateError(spn, error);
  }
}

/** `client`'s next token for the proxy's `token`, as a `Proxy-Authorization` value. */
export async function negotiateStep(spn: string, client: KerberosClient, token: string): Promise<string> {
  try {
    return `Negotiate ${await client.step(token)}`;
  } catch (error) {
    throw negotiateError(spn, error);
  }
}

const negotiateError = (spn: string, error: unknown) =>
  new Error(`Negotiate as ${spn} failed: ${(error as Error).message}`, { cause: error });
