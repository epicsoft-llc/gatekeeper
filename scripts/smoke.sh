#!/bin/sh
# Starts the built image with a throwaway configuration before anything is pushed: smoke.sh <image> <version>
set -eu

image="$1"
version="$2"
host="${SMOKE_HOST:-docker}"
work=$(mktemp -d)
trap 'docker rm -f gatekeeper-smoke >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

head -c 48 /dev/urandom | base64 | tr -d '\n' > "$work/secret"
cat > "$work/config.json" <<'EOF'
{
  "secret_file": "/etc/gatekeeper/secret",
  "trusted_proxies": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"],
  "providers": [{"id": "zitadel", "name": "Zitadel", "issuer": "https://id.example.invalid", "client_id": "smoke"}],
  "groups": {"all": ["admin@example.com"]},
  "hosts": {"smoke.example.com": {"login": ["zitadel"], "allow": ["all"]}}
}
EOF
chmod 0755 "$work"
chmod 0644 "$work/secret" "$work/config.json"

fail() {
  echo "smoke test: $1"
  docker logs gatekeeper-smoke 2>&1 | tail -20
  exit 1
}

docker rm -f gatekeeper-smoke >/dev/null 2>&1 || true
docker create --name gatekeeper-smoke -p 18080:8080 "$image" >/dev/null
docker cp "$work/." gatekeeper-smoke:/etc/gatekeeper
docker start gatekeeper-smoke >/dev/null

tries=0
until docker exec gatekeeper-smoke /gatekeeper healthcheck >/dev/null 2>&1; do
  tries=$((tries + 1))
  [ "$tries" -lt 30 ] || fail "no health within 15 seconds"
  sleep 0.5
done

[ "$(docker exec gatekeeper-smoke /gatekeeper version)" = "$version" ] || fail "version is not $version"
[ "$(docker inspect -f '{{.Config.User}}' gatekeeper-smoke)" = "65532:65532" ] || fail "the image does not run as 65532"
docker exec gatekeeper-smoke /gatekeeper check >/dev/null || fail "check refuses the configuration"
docker cp gatekeeper-smoke:/etc/ssl/certs/ca-certificates.crt "$work/ca.crt" && [ -s "$work/ca.crt" ] || fail "no CA certificates"

status() {
  wget -S -q -O /dev/null --header "X-Forwarded-Host: $1" "http://$host:18080$2" 2>&1 | awk '$1 ~ /^HTTP\// { code = $2 } END { print code }'
}
[ "$(status smoke.example.com /_gatekeeper/auth)" = 401 ] || fail "auth without session is not 401"
[ "$(status other.example.com /_gatekeeper/auth)" = 403 ] || fail "auth for an unknown host is not 403"
[ "$(status smoke.example.com /_gatekeeper/sign_in)" = 401 ] || fail "the sign-in page does not render"
[ "$(status smoke.example.com /_gatekeeper/start/zitadel)" = 503 ] || fail "an unreachable provider is not 503"

echo "smoke test passed: $image"
