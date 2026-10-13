# system-proxy-fetch

`fetch` and `http.Agent` that go through the proxy the operating system is set to use, with
no configuration: Windows, macOS, GNOME and KDE settings and PAC scripts, layered with
`*_proxy`. Built on [proxy-watch](https://www.npmjs.com/package/proxy-watch). Node 22.19 or later.

```sh
npm install system-proxy-fetch
```

## fetch

```js
import { SystemProxyDispatcher } from 'system-proxy-fetch';

const dispatcher = new SystemProxyDispatcher();
await fetch('https://example.com/', { dispatcher });
```

`setGlobalDispatcher(dispatcher)` from undici applies it to every `fetch`.

## http.Agent

```js
import https from 'node:https';
import { systemProxyAgent } from 'system-proxy-fetch/agent';

const agent = systemProxyAgent();
https.get('https://example.com/', { agent });
```

Also for node-fetch (`{ agent }`) and axios (`{ httpAgent: agent, httpsAgent: agent, proxy: false }`).

## Notes

- A change to the settings applies from the next request. Other options are in the type
  definitions.
- In a Flatpak or Snap sandbox, set `pollIntervalMs` to follow changes.
- The dispatcher watches the settings until `close()` or `destroy()`, the agent until
  `destroy()`.
- A request the settings give no usable route fails with `RouteError`; it does not go direct.
- The `pac` option picks the PAC engine. By default it is the OS's on Windows and macOS,
  and QuickJS on Linux, which fetches the script and answers as if off every network
  unless `policy` says where the machine is. WPAD
  ("Automatically detect settings") needs `wpad: true`, and runs on Windows and macOS only.
- A proxy password the OS keeps elsewhere (the macOS keychain), or Kerberos
  (`negotiateAuth()`), goes through the `proxyAuth` option. For a plain `http:` request,
  put the credentials in the proxy URL.
- proxy-watch is a native addon: mark it external when bundling.

## License

MIT OR Apache-2.0.
