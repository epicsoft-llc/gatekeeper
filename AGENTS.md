# AGENTS.md — gatekeeper

Guidance for coding agents working in this repository. User documentation lives in [`README.md`](README.md).

A Docker image: a Go service that guards websites behind nginx `auth_request` or Traefik `forwardAuth`. Visitors sign
in with a one-time code by email or with an OpenID Connect provider; groups in the configuration decide who enters which
host.

## Coordinates

| | |
|---|---|
| **Repository** | `gitlab.com/epicsoft-networks/gatekeeper`, branch `develop` → `main`; mirrored to `github.com/epicsoft-llc/gatekeeper` by a GitLab push mirror |
| **Image** | `epicsoft/gatekeeper` on Docker Hub and `registry.gitlab.com/epicsoft-networks/gatekeeper`, `linux/amd64` and `linux/arm64` |
| **Version** | the git tag `X.Y.Z`, built in through `-ldflags -X main.version` |
| **Runtime** | Go 1.27 (`golang:1.27.3-alpine` to build, `scratch` to run); locally pinned in `.vfox.toml` |
| **Dependencies** | `github.com/coreos/go-oidc/v3` (with `go-jose`) and `golang.org/x/oauth2` — nothing else |

## Rules

- **Public repository.** No secrets and no internal names - servers, deployments, vaults, mailboxes - in any file;
  examples use `example.com`, `example.org` and `example.net`.
- **Everything in English** — code, comments, README, CHANGELOG, log lines, error messages, commit messages.
- **Commit messages: one line**, Conventional Commits prefix (`feat:`, `fix:`, `ci:`, `docs:`, `refactor:`), no trailers.
- **No comment by default.** One line where a decision would otherwise be "corrected"; no header boxes, no derivations.
- **Only a human suppresses warnings.** No `//nolint`, `//lint:ignore` or similar — fix the cause or report it.
- **No new dependency without a reason that outweighs it.** The standard library covers HTTP, SMTP, TLS, crypto and
  templates here.
- **Page and mail templates live in the repository**; name, mark, logo, colours and texts come from `branding` in the
  configuration - without it the neutral look of `internal/brand`.
- **Keep this file current** after every architectural change, new setting, CI change or new rule.

## Commands

```bash
go test ./...                      # all tests in-process, a few seconds; no Docker, no network
go test -race ./...                # needs cgo - run it in Linux (CI) or in the golang image
go test -run '^$' -fuzz FuzzSafeReturn ./internal/server/      # also FuzzNormalizeAddress (config), FuzzMark (brand),
                                                                # FuzzParse (bounce), FuzzOpen (seal)
docker build -t gatekeeper:dev .
```

## Architecture

```
cmd/gatekeeper/     main: serve | check | healthcheck | version; two listeners (public and health), shutdown
internal/config/    JSON configuration: defaults, every check in one place, NormalizeAddress, group lookup
internal/brand/     the SVG allowlist of the mark (ParseMark, written out anew), the mail logo check, the colours;
                    mark.svg and logo.png - the neutral default with shield-lock of Bootstrap Icons (MIT)
internal/bounce/    bounces: Tracker (a token per code mail in the envelope sender, suppressions), Parse (RFC 3464),
                    a minimal IMAP client over TLS, Poller; testdata/ with a real Postfix bounce. No file under
                    another licence: the public samples of sisimai/set-of-emails (BSD 2-Clause) stay out
internal/seal/      AES-256-GCM boxes with HKDF keys per purpose - all cookies go through it
internal/limit/     fixed-window rate limiter with a bounded number of keys; a full one pushes out an arbitrary key
internal/i18n/      texts.json (de, en, ru, ka), Catalog with the overrides of a texts_file, language negotiation, minutes
internal/mail/      code mail (text + HTML + inline logo), SMTP client, background queue (skips suppressed addresses);
                    templates/
internal/server/    HTTP: request.go (host, client, return path), cookies.go (session, pending, flow, CSRF),
                    codes.go (pending codes), handlers.go (auth, pages, email and code flow, sign-out),
                    oidc.go (providers), altcha.go (the ALTCHA step and its ticket), pages.go + templates/ (layout,
                    pages, style.css as a template of the colours), umami.go
examples/           config.json and texts.json - loaded by a test, so they never drift from the code
scripts/            publish.sh (build, smoke test, push) and smoke.sh, run by the image jobs
docs/               screenshots/ of the README - take them anew when the pages change
```

### Invariants — keep them when changing code

- **Fail closed.** An unknown host, an unopenable cookie, an expired flow, any provider or mail error: never access.
- **Access is decided on every request** by `permitted`: the session's method must still be offered by the host, and
  then either its address is in an allowed group (code by email, providers without `groups_claim`) or one of the
  provider groups kept in the session is in the host's `allow` (providers with `groups_claim`). A session alone
  never grants access.
- **Every cookie goes through `seal`** with its own purpose and `purpose|host` as additional data, so a value opens
  only for the host it was issued for. Cookie names carry the `__Host-` prefix.
- **Codes are kept only as HMAC**, bound to the pending cookie (browser) and the host, void after use, expiry or
  `code_attempts`. A new code for the same address and host voids the old one - for an address without access too.
  A full store gives up its oldest entry instead of refusing everybody.
- **An address without access is indistinguishable**: same redirect, same pending cookie, same code page, same limits
  (the per-address limit counts every entered address), and its older pending code is voided the same way - otherwise
  a second request and the first cookie would tell the two apart (found in the review of 2026-10-25). The only difference is that no mail goes out — and that
  happens in the background queue, so the answer takes the same time. Its address never reaches the log.
- **Mail goes to the address as configured** (`config.NormalizeAddress` output; for a domain entry its exact domain
  and a local part from `localPattern`, no `%` or `!` routes), never to the raw input, and never
  names the host - a mail in the wrong inbox must not reveal the protected site. `mail.Build`
  refuses line breaks in header values. The SMTP client never falls back to plain text and sends credentials only
  over TLS.
- **Providers:** state, nonce and PKCE are checked; the ID token only through go-oidc's verifier; `email_verified`
  must be true; userinfo must belong to the same subject. Groups only with `groups_claim`, read from the verified
  ID token or that userinfo; the session keeps only groups some host allows.
- **Return paths go through `safeReturn`** — only a path on the same host. Redirect targets are relative.
- **Forwarded headers only from `trusted_proxies`**, and only as the nearest proxy wrote them: the last entry of the
  last line. A configured `Host` with another `X-Forwarded-Host` is refused. The client address for rate limits is
  IPv4 or the IPv6 /64; a whole IPv6 /48 gets 16 times `per_client`.
- **Addresses and hosts are ASCII before they are lowered** - `strings.ToLower` folds `İ` and the Kelvin sign.
- **A full limiter or store never refuses everybody:** limiters and the code store push out an entry; only the store
  of spent ALTCHA tickets refuses while full, since a ticket it forgot could be used again.
- **Pages carry no script and no style attribute.** The only style is the `<style>` element with `style.css`, allowed
  by its hash in the CSP. An SVG takes presentation attributes (`fill="…"`), never `style="…"`. The one exception is
  the ALTCHA step with `altcha` set: exactly the widget script and exactly the challenge URL of the service,
  `worker-src blob:`, the widget's `<style>` by a nonce per response - never `'unsafe-inline'`; every other page and
  the address field after the step stay without script. A page with the sign-out button of a `logout: browser`
  session admits the provider's end-session origin in `form-action` - the browser checks the redirect against it.
- **The mark is written out anew** from what `brand.ParseMark` allowed - never passed through. Its ids carry a prefix
  per copy; a pointer is only `url(#id)` to an element of the mark. Colours only as `#rrggbb`; a texts_file only for
  existing keys with the placeholders of the original.
- **A solved ALTCHA opens the address field once:** the service checks and spends the solution; the ticket cookie is
  sealed, bound to client and host, valid for `ticketLifetime` and spent with the code request (`ticketStore`).
  Service unreachable or refusing: no code by email, the providers keep working.
- **Only real bounces count:** every code mail goes out with the envelope sender `<local>+b-<token>@<domain>`; a
  delivery status notification counts only for a known token, the address that token went to and a failure. A
  suppressed address gets the same answer and no mail. The IMAP client speaks TLS only and logs no address of a
  bounce it ignores.
- **Signing out is a POST with the CSRF token**; a GET only shows the button.
- **Logs never contain codes, tokens, cookies or client addresses** - an error of `net/http` names its URL, so a URL
  with a token in it is logged without the URL.
- **Umami event names stay as they are** (`gate-email`, `gate-<provider>`, `gate-email-callback`,
  `gate-<provider>-callback`, `gate-language`) - reports count on them.
- **A new text** needs all four languages in `texts.json` — a test compares keys and placeholders.
- **A new setting** goes into `config.go` (field, default, check), `examples/config.json` and the README table.

## CI/CD

Pipeline: `.gitlab-ci.yml`

| Job | Trigger | Action |
|---|---|---|
| `test` | every pipeline, also the weekly schedule | `gofmt`, `go vet`, `go test -race`, `staticcheck`, `govulncheck` in `golang:1.27.3` |
| `develop` | branch `develop` | image `:develop`, GitLab registry only |
| `latest` | branch `main` | image `:latest` |
| `release` | tag `X.Y.Z` | fails without a `CHANGELOG.md` entry for the tag; images `X.Y.Z`, `X.Y`, `X`, `latest` |
| `uploadReadme` | branch `main` | `README.md` as the description on Docker Hub, its relative image paths as GitLab URLs - fails above 25,000 bytes |
| `github-release` | tag `X.Y.Z` | the GitHub release from the `CHANGELOG.md` entry, once the push mirror has brought the tag |

The image jobs run `scripts/publish.sh`: an amd64 build into the runner's Docker, `scripts/smoke.sh` starts it with a
throwaway configuration (health, version, uid, `check`, CA bundle, the status codes of the endpoints), and only then
buildx builds `linux/amd64` and `linux/arm64` and pushes to the GitLab registry and Docker Hub. Go cross-compiles, so
arm64 needs no emulation. Locally:
`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/src" -w /src -e SMOKE_HOST=host.docker.internal docker:latest sh scripts/smoke.sh <image> <version>`.

The **weekly schedule** (pipeline schedule on `main`, Monday 06:00 Asia/Tbilisi) runs only `test`: a new entry in the
Go vulnerability database fails it without any commit. A red scheduled pipeline means: update and release.

The jobs log in with the job token and the group variables `DOCKER_HUB_USER` and `DOCKER_HUB_TOKEN`, over stdin.

**Not in CI, deliberately:** OWASP Dependency-Check maps Go modules poorly; `govulncheck` reads the Go vulnerability
database, covers the standard library and reports only code paths in use. `gosec` was evaluated with 2.30.0
(again on 2026-10-27 with branding, ALTCHA and bounces): its unhandled-error findings are fixed, the rest are false
positives (G203 on the CSS of the checked colours, the favicon and the mark written anew from the allowlist, G304 on
files named in the configuration, G710 on redirects that pass `safeReturn` or come from provider metadata, G124 on the
SameSite parameter). Running it in CI would need exclusions, and only a human sets those.

## Updates

- Go: `.vfox.toml`, `Dockerfile` and `.gitlab-ci.yml` together.
- Modules: `go get -u ./... && go mod tidy`, then the full test run; `govulncheck` in CI reports known
  vulnerabilities in the code paths actually used.
- `staticcheck` and `govulncheck` are pinned in `.gitlab-ci.yml`.

## Release checklist

- `CHANGELOG.md`: `## [X.Y.Z] - <date>` — the `release` job looks for exactly that heading
- Tag **without `v`**: `X.Y.Z`
