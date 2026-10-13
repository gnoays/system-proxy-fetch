import { createSign, generateKeyPairSync } from 'node:crypto';

function derLen(n) {
  if (n < 128) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, n >> 8, n & 0xff]);
}

function der(tag, body) {
  return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
}

// A subjectAltName extension naming the IPv4 addresses `ips`.
function ipAltNames(ips) {
  const names = ips.map((ip) => der(0x87, Buffer.from(ip.split('.').map(Number))));
  const extension = der(
    0x30,
    Buffer.concat([der(0x06, Buffer.from([0x55, 0x1d, 0x11])), der(0x04, der(0x30, Buffer.concat(names)))]),
  );
  return der(0xa3, der(0x30, extension));
}

// A self-signed certificate for `cn`, valid for a day, that no default trust store accepts.
// `ips` puts IPv4 addresses in its subjectAltName, the only names an IP destination is
// checked against.
export function selfSigned(cn, { ips } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const name = der(
    0x30,
    der(0x31, der(0x30, Buffer.concat([der(0x06, Buffer.from([0x55, 0x04, 0x03])), der(0x0c, Buffer.from(cn))]))),
  );
  const utc = (date) => {
    const pad = (n) => String(n).padStart(2, '0');
    const stamp = `${String(date.getUTCFullYear()).slice(2)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
    return der(0x17, Buffer.from(stamp));
  };
  const now = new Date();
  const algo = der(0x30, der(0x06, Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])));
  const tbs = der(
    0x30,
    Buffer.concat([
      // An extension needs a version 3 certificate.
      ...(ips ? [der(0xa0, der(0x02, Buffer.from([0x02])))] : []),
      der(0x02, Buffer.from([0x01])),
      algo,
      name,
      der(0x30, Buffer.concat([utc(now), utc(new Date(now.getTime() + 86400e3))])),
      name,
      spki,
      ...(ips ? [ipAltNames(ips)] : []),
    ]),
  );
  const signer = createSign('SHA256');
  signer.update(tbs);
  const sig = signer.sign(privateKey);
  const cert = der(0x30, Buffer.concat([tbs, algo, der(0x03, Buffer.concat([Buffer.from([0x00]), sig]))]));
  const pem =
    '-----BEGIN CERTIFICATE-----\n' +
    cert.toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END CERTIFICATE-----\n';
  return { key: privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: pem };
}
