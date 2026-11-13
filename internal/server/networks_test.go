package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const reportAllow = `"allow": ["report.example.com", "all"]}`

func TestIPAllowLetsInWithoutSigningIn(t *testing.T) {
	h := newHarness(t, reportAllow, `"allow": ["report.example.com", "all"], "ip_allow": ["203.0.113.0/24", "2001:db8:7::/48"]}`)
	b := h.browser("report.example.com")
	auth := b.request(http.MethodGet, prefix+"/auth", nil, "/")
	if auth.StatusCode != http.StatusAccepted || auth.Header.Get("X-Gatekeeper-User") != "" {
		t.Errorf("auth: %d %q", auth.StatusCode, auth.Header.Get("X-Gatekeeper-User"))
	}
	if r := b.request(http.MethodGet, prefix+"/forward_auth", nil, "/"); r.StatusCode != http.StatusOK {
		t.Errorf("forward_auth: %d", r.StatusCode)
	}
	v6 := h.browser("report.example.com")
	v6.ip = "2001:db8:7:1::5"
	if r := v6.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusAccepted {
		t.Errorf("IPv6 network: %d", r.StatusCode)
	}
	outside := h.browser("report.example.com")
	outside.ip = "198.51.100.1"
	if r := outside.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("outside the list: %d", r.StatusCode)
	}
	if r := h.browser("admin.example.com").request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("the list of another host: %d", r.StatusCode)
	}

	// Signed in on an allowed network, the proxy still learns who it is.
	b.signInByEmail("reader@example.org", "/")
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.Header.Get("X-Gatekeeper-User") != "reader@example.org" {
		t.Errorf("signed in: %d %q", r.StatusCode, r.Header.Get("X-Gatekeeper-User"))
	}
}

func TestIPListsNeedTheClientAddress(t *testing.T) {
	h := newHarness(t, reportAllow, `"allow": ["report.example.com", "all"], "ip_allow": ["127.0.0.0/8"]}`)
	b := h.browser("report.example.com")
	b.ip = ""
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("a proxy that named no client was let in as itself: %d", r.StatusCode)
	}
}

func TestIPDenyKeepsOutOfEverything(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	b.signInByEmail("reader@example.org", "/")
	asker := h.browser("report.example.com")
	form := asker.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	sent := h.mailer.count()
	h.load(`"default_language": "en",`, `"default_language": "en", "ip_deny": ["203.0.113.0/24"],`)

	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusForbidden {
		t.Errorf("auth with a session: %d", r.StatusCode)
	}
	page := b.at("/x")
	page.expect(t, http.StatusForbidden, "No access", "This area cannot be reached from your internet address.")
	if strings.Contains(page.body, "<form") {
		t.Error("the page offers a form")
	}
	b.at("/x?lang=de").expect(t, http.StatusForbidden, "Von Ihrer Internetadresse aus")
	b.request(http.MethodGet, prefix+"/forward_auth", nil, "/").expect(t, http.StatusForbidden, "cannot be reached")
	b.get(prefix+"/sign_in").expect(t, http.StatusForbidden, "cannot be reached")
	asker.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, form.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}}).
		expect(t, http.StatusForbidden, "cannot be reached")
	if h.mailer.count() != sent {
		t.Error("a code mail went out")
	}
	if r := h.browser("admin.example.com").request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusForbidden {
		t.Errorf("the top level applies to every host: %d", r.StatusCode)
	}
	outside := h.browser("report.example.com")
	outside.ip = "198.51.100.1"
	if r := outside.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("outside the list: %d", r.StatusCode)
	}
	if strings.Contains(h.log(), "203.0.113.7") {
		t.Errorf("the log names the client: %s", h.log())
	}
}

func TestIPDenyWinsOverIPAllow(t *testing.T) {
	h := newHarness(t, reportAllow, `"allow": ["report.example.com", "all"], "ip_allow": ["203.0.113.0/24"], "ip_deny": ["203.0.113.7"]}`)
	if r := h.browser("report.example.com").request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusForbidden {
		t.Errorf("status %d", r.StatusCode)
	}
}
