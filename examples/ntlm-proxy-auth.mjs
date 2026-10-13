// NTLM for a proxy's 407 to CONNECT, plugged into system-proxy-fetch through `proxyAuth`. An
// example, not part of the package: the NTLM messages come from `@node-ntlm/core`, and the
// choice of that library, and of keeping a password in the process, is the caller's.
//
//   import { SystemProxyDispatcher } from 'system-proxy-fetch';
//   import { ntlmAuth } from './ntlm-proxy-auth.mjs';
//   const dispatcher = new SystemProxyDispatcher({
//     proxyAuth: ntlmAuth({ username: 'alice', password: process.env.PROXY_PASSWORD, domain: 'CORP' }),
//   });
//
// NTLM authenticates the connection, so its three messages go on one: the Type 1 answers
// the first 407, the proxy's Type 2 comes back in the next 407 on the same connection, and
// the Type 3 answers that. A proxy that closes the connection between them cannot be
// answered, and the request fails with the 407.
//
// Only NTLMv2 is sent. `@node-ntlm/core` falls back to NTLMv1 (with the LM response) when
// the Type 2 lacks extended session security, and to the NTLMv1 session response when it
// lacks target information; such a Type 2 is refused here instead. The library draws its
// client challenge from `Math.random()`, not a cryptographic source.

import { createType1Message, createType3Message, parseType2Message } from '@node-ntlm/core';

const EXTENDED_SESSION_SECURITY = 0x00080000;

/**
 * A `proxyAuth` answering `407 NTLM` as `username` in `domain`. Pass `workstation` to name
 * the machine to the proxy; it is empty by default.
 */
export function ntlmAuth({ username, password, domain = '', workstation = '' }) {
  return {
    start() {
      let sent = 'nothing';
      return {
        async respond(challenges, sameConnection) {
          const ntlm = challenges.map((value) => /^NTLM(?:\s+(\S+))?\s*$/i.exec(value)).find(Boolean);
          if (!ntlm) return undefined;
          if (!ntlm[1]) {
            // A bare `NTLM` starts the exchange. After a Type 3 it means the proxy refused it.
            if (sent === 'type3') return undefined;
            sent = 'type1';
            return createType1Message({ domain, workstation });
          }
          if (sent !== 'type1' || !sameConnection) return undefined;
          const type2 = parseType2Message(`NTLM ${ntlm[1]}`);
          if (!(type2.negotiateFlags & EXTENDED_SESSION_SECURITY) || !type2.targetInfo) return undefined;
          sent = 'type3';
          return createType3Message(type2, { username, password, domain, workstation });
        },
      };
    },
  };
}
