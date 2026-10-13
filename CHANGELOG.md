# Changelog

Notable changes to `system-proxy-fetch`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). A release's tag is
`vX.Y.Z`, and its notes are its section here.

## [Unreleased]

## [0.1.0] - 2026-10-13

### Added

- `SystemProxyDispatcher` for `fetch` (undici) and `systemProxyAgent()` for `http.Agent`
  clients, which send each request where the operating system's proxy settings would:
  Windows, macOS, GNOME and KDE settings and PAC scripts, layered with `*_proxy`, through
  [proxy-watch](https://www.npmjs.com/package/proxy-watch).
- Proxy authentication through `proxyAuth`, with `basicAuth()` and `negotiateAuth()`
  (Kerberos, with the optional `kerberos` package) built in.
