package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func startAt(t *testing.T, b *browser, rd string) *url.URL {
	t.Helper()
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, rd)
	start := b.get(prefix + "/start/zitadel?" + url.Values{"rd": {rd}, "lang": {"en"}}.Encode())
	if !strings.Contains(page.body, "Sign in with Zitadel") {
		t.Fatal("no provider button")
	}
	location := start.location(t)
	if got := location.Query().Get("redirect_uri"); got != "https://"+b.host+prefix+"/callback/zitadel" {
		t.Fatalf("redirect_uri %q", got)
	}
	return location
}

func (b *browser) callback(code, state string) *response {
	return b.get(prefix + "/callback/zitadel?" + url.Values{"code": {code}, "state": {state}}.Encode())
}

var verifiedAdmin = map[string]any{"email": "Admin@Example.com", "email_verified": true, "gatekeeper:roles": []string{"all"}}

func TestProviderFlow(t *testing.T) {
	h := newHarness(t)
	b := h.browser("admin.example.com")
	location := startAt(t, b, "/dashboard/")
	if location.Query().Get("ui_locales") != "en" || !strings.Contains(location.Query().Get("scope"), "email") {
		t.Errorf("authorization request %s", location)
	}
	code, state := h.idp.authorize(t, location, verifiedAdmin)
	done := b.callback(code, state)
	if got := done.location(t).String(); got != "/dashboard/" {
		t.Fatalf("after the callback: %s", got)
	}
	auth := b.request(http.MethodGet, prefix+"/auth", nil, "/")
	if auth.StatusCode != http.StatusAccepted || auth.Header.Get("X-Gatekeeper-User") != "admin@example.com" {
		t.Fatalf("auth: %d %q", auth.StatusCode, auth.Header.Get("X-Gatekeeper-User"))
	}
	if again := b.callback(code, state); again.StatusCode != http.StatusBadRequest {
		t.Errorf("the callback worked twice: %d", again.StatusCode)
	}

	out := b.signOut()
	if out.location(t).String() != "/" {
		t.Errorf("after sign-out: %s", out.location(t))
	}
	if hints := h.idp.logoutHints(); len(hints) != 1 || strings.Count(hints[0], ".") != 2 {
		t.Errorf("backend logout: %v", hints)
	}
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("still signed in: %d", r.StatusCode)
	}
}

func TestProviderBrowserLogout(t *testing.T) {
	h := newHarness(t, `"logout": "backend"`, `"logout": "browser"`)
	b := h.browser("admin.example.com")
	code, state := h.idp.authorize(t, startAt(t, b, "/"), verifiedAdmin)
	b.callback(code, state)
	target := b.signOut().location(t)
	q := target.Query()
	if !strings.HasPrefix(target.String(), h.idp.server.URL+"/logout?") || q.Get("post_logout_redirect_uri") != "https://admin.example.com/" || q.Get("client_id") != "gatekeeper" || q.Get("id_token_hint") == "" {
		t.Errorf("browser logout to %s", target)
	}
}

func TestProviderRefusals(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		tamper func(map[string]any)
		state  func(string) string
		status int
		text   string
	}{
		{"unverified address", map[string]any{"email": "admin@example.com", "email_verified": false}, nil, nil, http.StatusForbidden, "not verified"},
		{"verified as text", map[string]any{"email": "admin@example.com", "email_verified": "false"}, nil, nil, http.StatusForbidden, "not verified"},
		{"no access", map[string]any{"email": "reader@example.org", "email_verified": true}, nil, nil, http.StatusForbidden, "The account reader@example.org has no access"},
		{"wrong state", verifiedAdmin, nil, func(s string) string { return s + "x" }, http.StatusBadRequest, "failed or was cancelled"},
		{"nonce", verifiedAdmin, func(c map[string]any) { c["nonce"] = "other" }, nil, http.StatusBadGateway, "failed or was cancelled"},
		{"audience", verifiedAdmin, func(c map[string]any) { c["aud"] = "someone-else" }, nil, http.StatusBadGateway, "failed or was cancelled"},
		{"issuer", verifiedAdmin, func(c map[string]any) { c["iss"] = "https://evil.example.net" }, nil, http.StatusBadGateway, "failed or was cancelled"},
		{"expired", verifiedAdmin, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, nil, http.StatusBadGateway, "failed or was cancelled"},
		{"bad address", map[string]any{"email": "admin", "email_verified": true}, nil, nil, http.StatusBadGateway, "failed or was cancelled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.idp.tamper = c.tamper
			b := h.browser("admin.example.com")
			code, state := h.idp.authorize(t, startAt(t, b, "/"), c.claims)
			if c.state != nil {
				state = c.state(state)
			}
			b.callback(code, state).expect(t, c.status, c.text)
			if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
				t.Errorf("a refused sign-in left a session: %d", r.StatusCode)
			}
		})
	}
}

func TestProviderUserinfo(t *testing.T) {
	h := newHarness(t)
	h.idp.userinfo = map[string]any{"sub": "user-1", "email": "admin@example.com", "email_verified": true, "gatekeeper:roles": []string{"all"}}
	b := h.browser("admin.example.com")
	code, state := h.idp.authorize(t, startAt(t, b, "/"), nil)
	if r := b.callback(code, state); r.location(t).String() != "/" {
		t.Fatalf("callback %d %s", r.StatusCode, r.body)
	}

	h.idp.userinfo = map[string]any{"sub": "user-2", "email": "admin@example.com", "email_verified": true, "gatekeeper:roles": []string{"all"}}
	other := h.browser("admin.example.com")
	code, state = h.idp.authorize(t, startAt(t, other, "/"), nil)
	other.callback(code, state).expect(t, http.StatusBadGateway)
	if !strings.Contains(h.log(), "userinfo belongs to another subject") {
		t.Errorf("log: %s", h.log())
	}
}

func TestProviderCallbackNeedsItsFlow(t *testing.T) {
	h := newHarness(t)
	b := h.browser("admin.example.com")
	b.callback("code", "state").expect(t, http.StatusBadRequest, "failed or was cancelled")

	starter := h.browser("admin.example.com")
	code, state := h.idp.authorize(t, startAt(t, starter, "/"), verifiedAdmin)
	b.callback(code, state).expect(t, http.StatusBadRequest)

	h.clock = h.clock.Add(flowLifetime)
	starter.callback(code, state).expect(t, http.StatusBadRequest)
}

func TestProviderCancelled(t *testing.T) {
	h := newHarness(t)
	b := h.browser("admin.example.com")
	_, state := h.idp.authorize(t, startAt(t, b, "/"), verifiedAdmin)
	b.get(prefix+"/callback/zitadel?"+url.Values{"error": {"access_denied"}, "state": {state}}.Encode()).expect(t, http.StatusBadRequest, "failed or was cancelled")
}

func TestProviderNotOfferedOnThisHost(t *testing.T) {
	h := newHarness(t, `["email", "zitadel"]`, `["email"]`)
	b := h.browser("report.example.com")
	if r := b.get(prefix + "/start/zitadel?rd=%2F"); r.StatusCode != http.StatusNotFound {
		t.Errorf("start: %d", r.StatusCode)
	}
	if r := b.get(prefix + "/start/github?rd=%2F"); r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown provider: %d", r.StatusCode)
	}
}

func TestProviderUnavailable(t *testing.T) {
	h := newHarness(t)
	h.idp.server.Close()
	b := h.browser("report.example.com")
	b.get(prefix+"/start/zitadel?rd=%2F&lang=de").expect(t, http.StatusServiceUnavailable, "Zitadel ist gerade nicht erreichbar")
	if r := b.signInByEmail("reader@example.org", "/"); r.location(t).String() != "/" {
		t.Error("the code by email stopped working with the provider down")
	}
}

func TestProviderGroupsDecide(t *testing.T) {
	h := newHarness(t)
	signIn := func(host string, claims map[string]any) *browser {
		b := h.browser(host)
		code, state := h.idp.authorize(t, startAt(t, b, "/"), claims)
		b.callback(code, state)
		return b
	}
	auth := func(b *browser) int { return b.request(http.MethodGet, prefix+"/auth", nil, "/").StatusCode }

	hostRole := signIn("report.example.com", map[string]any{"email": "someone@example.org", "email_verified": true, "gatekeeper:roles": []string{"report.example.com"}})
	if auth(hostRole) != http.StatusAccepted {
		t.Error("the role named like the host does not open it")
	}
	elsewhere := h.browser("admin.example.com")
	code, state := h.idp.authorize(t, startAt(t, elsewhere, "/"), map[string]any{"email": "someone@example.org", "email_verified": true, "gatekeeper:roles": []string{"report.example.com"}})
	elsewhere.callback(code, state).expect(t, http.StatusForbidden, "has no access")

	native := signIn("admin.example.com", map[string]any{"email": "admin@example.com", "email_verified": true, "gatekeeper:roles": map[string]any{"all": map[string]string{"1": "example"}}})
	if auth(native) != http.StatusAccepted {
		t.Error("roles as an object keyed by name are not read")
	}

	listed := h.browser("report.example.com")
	code, state = h.idp.authorize(t, startAt(t, listed, "/"), map[string]any{"email": "reader@example.org", "email_verified": true})
	listed.callback(code, state).expect(t, http.StatusForbidden, "has no access")

	trimmed := signIn("admin.example.com", map[string]any{"email": "admin@example.com", "email_verified": true, "gatekeeper:roles": []string{"all", "unrelated", "all"}})
	sess, ok := h.srv.readSession(cookieRequest(trimmed), &request{host: "admin.example.com", site: h.cfg.Hosts["admin.example.com"]})
	if !ok || len(sess.Groups) != 1 || sess.Groups[0] != "all" {
		t.Errorf("session groups %+v", sess)
	}

	h.load(`"admin.example.com": {"login": ["zitadel"], "allow": ["all"]}`, `"admin.example.com": {"login": ["zitadel"], "allow": ["staff"]}`)
	if auth(native) != http.StatusForbidden {
		t.Error("a group taken from the host still opened it")
	}
}

func TestBrowserLogoutPassesTheFormAction(t *testing.T) {
	h := newHarness(t, `"logout": "backend"`, `"logout": "browser"`)
	b := h.browser("admin.example.com")
	code, state := h.idp.authorize(t, startAt(t, b, "/"), verifiedAdmin)
	b.callback(code, state)
	page := b.get(prefix + "/sign_out")
	if policy := page.Header.Get("Content-Security-Policy"); !strings.Contains(policy, "form-action 'self' "+h.idp.server.URL+";") {
		t.Errorf("the redirect to the provider is not admitted: %s", policy)
	}
	h.load(`"logout": "backend"`, `"logout": "browser"`, `"admin.example.com": {"login": ["zitadel"], "allow": ["all"]}`, `"admin.example.com": {"login": ["zitadel"], "allow": ["staff"]}`)
	denied := b.at("/")
	if policy := denied.Header.Get("Content-Security-Policy"); denied.StatusCode != http.StatusForbidden || !strings.Contains(policy, "form-action 'self' "+h.idp.server.URL+";") {
		t.Errorf("denied page %d: %s", denied.StatusCode, policy)
	}

	email := newHarness(t).browser("report.example.com")
	email.signInByEmail("reader@example.org", "/")
	if policy := email.get(prefix + "/sign_out").Header.Get("Content-Security-Policy"); !strings.Contains(policy, "form-action 'self';") {
		t.Errorf("a session without browser logout widened form-action: %s", policy)
	}
}

func TestBackendLogoutKeepsTheTokenOutOfTheLog(t *testing.T) {
	h := newHarness(t)
	b := h.browser("admin.example.com")
	code, state := h.idp.authorize(t, startAt(t, b, "/"), verifiedAdmin)
	b.callback(code, state)
	page := b.get(prefix + "/sign_out")
	h.idp.server.CloseClientConnections()
	h.idp.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacked, _, _ := w.(http.Hijacker).Hijack()
		_ = hijacked.Close()
	})
	b.post(prefix+"/sign_out", url.Values{"csrf": {csrfOf(t, page.body)}, "lang": {"en"}})
	log := h.log()
	if !strings.Contains(log, "provider logout failed") || strings.Contains(log, "id_token_hint") || strings.Contains(log, "eyJ") {
		t.Errorf("log: %s", log)
	}
}

func TestDiscoveryOutlivesTheVisitor(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.srv.providers["zitadel"].get(ctx); err != nil {
		t.Errorf("a visitor who went away stopped the discovery: %v", err)
	}
}

func TestAddressAndVerificationFromOneDocument(t *testing.T) {
	h := newHarness(t)
	h.idp.userinfo = map[string]any{"sub": "user-1", "email": "reader@example.org", "email_verified": true, "gatekeeper:roles": []string{"all"}}
	b := h.browser("admin.example.com")
	code, state := h.idp.authorize(t, startAt(t, b, "/"), map[string]any{"email": "admin@example.com", "gatekeeper:roles": []string{"all"}})
	b.callback(code, state)
	if user := b.request(http.MethodGet, prefix+"/auth", nil, "/").Header.Get("X-Gatekeeper-User"); user != "reader@example.org" {
		t.Errorf("signed in as %q, not as the address userinfo verified", user)
	}
}
