// What SSPI puts in a Negotiate token on a Windows machine joined to no domain, through the
// optional `kerberos` package. With no KDC to reach, SPNEGO falls back to NTLM inside the
// token; `mechanism: 'kerberos'` must let no NTLM out. The SPNEGO case is the control: it
// shows that this machine would send NTLM, so that the Kerberos case means something.
//
// Windows only, and only where `kerberos` is installed. SYSTEM_PROXY_FETCH_SSPI=1 makes a
// missing `kerberos` a failure rather than a skip, for the CI job that installs it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { negotiateAuth } from '../dist/auth.mjs';

const KERBEROS = 'kerberos';
const required = process.env.SYSTEM_PROXY_FETCH_SSPI === '1';
let skip = false;
if (process.platform !== 'win32') {
  skip = 'SSPI is Windows only';
} else {
  try {
    await import(KERBEROS);
  } catch (error) {
    if (required) throw new Error('SYSTEM_PROXY_FETCH_SSPI=1 but the kerberos package does not load', { cause: error });
    skip = 'the kerberos package is not installed';
  }
}

const NTLMSSP = Buffer.from('NTLMSSP\0', 'latin1');
const PROXY = new URL('http://proxy.invalid:3128');

// The first token for `mechanism`, `{ none: true }` where the session gives up without one,
// or the error that stood in for it.
async function firstToken(mechanism) {
  const session = negotiateAuth({ mechanism }).start(PROXY);
  let value;
  try {
    value = await session.respond(['Negotiate'], true);
  } catch (error) {
    return { error };
  }
  return value === undefined ? { none: true } : { token: Buffer.from(value.replace(/^Negotiate\s+/, ''), 'base64') };
}

const describe = ({ token, error }) =>
  token ? `token ${token.subarray(0, 48).toString('hex')}` : error ? `error ${error.message}` : 'no token';

// An error SSPI raised, which `negotiateAuth` names with the principal; any other is a fault
// of its own and proves nothing about what SSPI sends.
const SSPI_ERROR = /^Negotiate as HTTP\/proxy\.invalid failed: /;

test('SSPI: SPNEGO on a machine with no domain carries NTLM', { skip }, async () => {
  const result = await firstToken('spnego');
  assert.ok(result.token?.includes(NTLMSSP), `expected NTLM inside SPNEGO, got ${describe(result)}`);
});

test("SSPI: mechanism 'kerberos' lets no NTLM out", { skip }, async () => {
  const result = await firstToken('kerberos');
  if (result.error) assert.match(result.error.message, SSPI_ERROR);
  assert.ok(!result.token?.includes(NTLMSSP), `NTLM left under 'kerberos': ${describe(result)}`);
  console.log(`'kerberos' on a machine with no domain: ${describe(result)}`);
});
