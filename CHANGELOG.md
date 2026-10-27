# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
the versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

| Part | Raised when |
|---|---|
| **MAJOR** | an existing setup stops working — a removed or renamed setting, a changed endpoint or answer |
| **MINOR** | something is added without requiring a change to an existing setup |
| **PATCH** | a fix or a dependency update without a change in behaviour |

**A release is a git tag `X.Y.Z`.** CI builds `X.Y.Z`, `X.Y`, `X` and moves `latest`; the `release` job fails
without an entry below for the tag.

## [1.1.0] - 2026-10-27

### Added

- `mail.link`: the code mail also carries a sign-in button. It signs in only the browser that asked for the code, by
  a token of its own - not the code, so a wrong token costs no attempt. The mail then names the host; off by default.
  With it the cookie of a pending code is `SameSite=Lax`, so a click in webmail carries it

## [1.0.0] - 2026-10-27

The first public release.

### Added

- Sign-in by a one-time code by email: eight digits, kept only as HMAC, bound to the requesting browser and the host,
  valid for `mail.code_ttl` and `mail.code_attempts` entries. An address without access gets the same answer and no
  mail; a group takes single addresses or whole domains (`@example.com`)
- Sign-in through OpenID Connect providers with state, nonce and PKCE; the address must be verified by the provider;
  `groups_claim` lets the provider's groups decide; logout at the provider by a server-side call or in the browser
- Access by groups per host, checked on every request against the configuration; an entry `*` for every other host
- `/_gatekeeper/auth` for nginx `auth_request` and `/_gatekeeper/forward_auth` for Traefik `forwardAuth`
- Pages and code mail in German, English, Russian and Georgian with a strict Content Security Policy and no script;
  signing out by a form with a CSRF token
- `branding`: name, owner and link, mark (an SVG checked against an allowlist), mail logo, colours and texts per
  language; without it a neutral look
- `altcha`: a proof of work of the ALTCHA service before the address field of the code by email
- `mail.bounces`: no code mail to an address whose code mail bounced, for `suppress` (48 hours)
- Rate limits per client address (IPv6 per /64, a whole /48 at most 16 times), per entered address and for all mails
  of the instance, of which addresses of a domain entry use at most half
- Optional counting of the sign-in page and its steps in Umami, respecting Do Not Track and GPC per host
- `gatekeeper check` validates a configuration and its files; `gatekeeper healthcheck` for the image
- Images for `linux/amd64` and `linux/arm64` on Docker Hub and in the GitLab registry
