// Fetching the PAC script a configuration names by URL, for an engine that runs a script's
// body and does not download it. The fetch goes direct: the proxy is what the script decides,
// and a request through this package's own dispatcher would wait on the script it fetches.

import { createReadStream } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { fileURLToPath } from 'node:url';

/** The longest script fetched, in bytes: what `Snapshot.route` takes as `script`. */
export const PAC_LIMIT = 1 << 20;
/** How long one fetch takes at most, redirects included. */
export const PAC_TIMEOUT = 10_000;
const REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * The script at `url`: an `http:` or `https:` URL fetched direct, with no agent (so no
 * `NODE_USE_ENV_PROXY` either), or a `file:` URL read. Up to `REDIRECTS` redirects are
 * followed, none to a `file:` URL. The body is asked for uncoded. Rejects for any other
 * scheme, a status other than 2xx, a body with a `Content-Encoding` other than `identity`, a
 * body over `PAC_LIMIT`, and when `signal` aborts.
 */
export async function fetchPac(url: string, signal: AbortSignal): Promise<string> {
  let target = new URL(url);
  for (let redirects = 0; ; redirects += 1) {
    if (target.protocol === 'file:' && redirects === 0) {
      return collect(createReadStream(fileURLToPath(target), { end: PAC_LIMIT, signal }));
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      throw new Error(`a PAC script at ${target.protocol} is not fetched${redirects ? ' after a redirect' : ''}`);
    }
    const answer = await get(target, signal);
    if (typeof answer === 'string') return answer;
    if (redirects === REDIRECTS) throw new Error(`the PAC script is more than ${REDIRECTS} redirects away`);
    target = new URL(answer.location, target);
  }
}

function get(url: URL, signal: AbortSignal): Promise<string | { location: string }> {
  return new Promise((resolve, reject) => {
    const options = { agent: false, signal, headers: { 'accept-encoding': 'identity' } };
    const request = (url.protocol === 'https:' ? https : http).get(url, options, (response) => {
      const status = response.statusCode ?? 0;
      const location = response.headers.location;
      const encoding = response.headers['content-encoding']?.trim().toLowerCase() || 'identity';
      if (REDIRECT_STATUSES.has(status) && location) {
        response.resume();
        resolve({ location });
      } else if (status < 200 || status > 299) {
        response.resume();
        reject(new Error(`the PAC server answered ${status}`));
      } else if (encoding !== 'identity') {
        response.resume();
        reject(new Error(`the PAC server sent the script as ${encoding}`));
      } else {
        collect(response).then(resolve, reject);
      }
    });
    request.on('error', reject);
  });
}

async function collect(stream: AsyncIterable<Buffer>): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > PAC_LIMIT) throw new Error(`the PAC script is longer than ${PAC_LIMIT} bytes`);
    chunks.push(chunk);
  }
  // Decoding turns each byte that is not UTF-8 into U+FFFD, three bytes, and the limit is
  // on the UTF-8 the engine is handed.
  const script = Buffer.concat(chunks).toString('utf8');
  if (Buffer.byteLength(script) > PAC_LIMIT) {
    throw new Error(`the PAC script is longer than ${PAC_LIMIT} bytes once read as UTF-8`);
  }
  return script;
}
