package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeAltcha answers /verify like the ALTCHA service: a solution of solution(n) passes once.
type fakeAltcha struct {
	server *httptest.Server
	mu     sync.Mutex
	spent  map[string]bool
	sites  []string
	status int
}

func solution(n int) string {
	return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, `{"challenge":{"n":%d},"solution":{}}`, n))
}

func newFakeAltcha(t *testing.T) *fakeAltcha {
	t.Helper()
	f := &fakeAltcha{spent: map[string]bool{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Altcha, Site string }
		if r.Method != http.MethodPost || r.URL.Path != "/verify" || r.Header.Get("Origin") != "" || json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, `{"ok":false,"error":"route_unknown"}`, http.StatusNotFound)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sites = append(f.sites, body.Site)
		w.Header().Set("Content-Type", "application/json")
		decoded, _ := base64.StdEncoding.DecodeString(body.Altcha)
		switch {
		case f.status != 0:
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, `{"ok":false,"error":"rate_ip"}`)
		case !strings.HasPrefix(string(decoded), `{"challenge":`):
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"ok":false,"error":"altcha_solution"}`)
		case f.spent[body.Altcha]:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"ok":false,"error":"altcha_replay"}`)
		default:
			f.spent[body.Altcha] = true
			_, _ = fmt.Fprintf(w, `{"ok":true,"verified":true,"site":%q}`, body.Site)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAltcha) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sites...)
}

func newAltchaHarness(t *testing.T) (*harness, *fakeAltcha) {
	t.Helper()
	f := newFakeAltcha(t)
	h := newHarness(t, "UMAMI", `,
  "altcha": {"url": "`+f.server.URL+`/", "site": "gatekeeper"}`)
	return h, f
}

func cookieValue(b *browser, name string) string {
	for _, c := range b.jar.Cookies(&url.URL{Scheme: "https", Host: b.host, Path: "/"}) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func between(s, start, end string) string {
	_, rest, _ := strings.Cut(s, start)
	value, _, _ := strings.Cut(rest, end)
	return value
}

func TestAltchaComesBeforeTheAddressField(t *testing.T) {
	h, f := newAltchaHarness(t)
	b := h.browser("report.example.com")
	page := b.at("/reports/")
	page.expect(t, http.StatusUnauthorized, `<altcha-widget challenge="`+f.server.URL+`/challenge" language="en" auto="onsubmit"></altcha-widget>`,
		`<script type="module" src="`+f.server.URL+`/widget.js"></script>`, `action="/_gatekeeper/altcha"`, "<noscript>", "Sign in with Zitadel")
	if strings.Contains(page.body, `name="email"`) {
		t.Error("the address field shows before the check")
	}
	nonce := between(page.body, `<meta name="csp-nonce" content="`, `"`)
	policy := page.Header.Get("Content-Security-Policy")
	for _, want := range []string{"script-src " + f.server.URL + "/widget.js;", "connect-src " + f.server.URL + "/challenge;", "worker-src blob:;", "'nonce-" + nonce + "'", "'sha256-" + h.srv.look.cssHash + "'", "form-action 'self'"} {
		if nonce == "" || !strings.Contains(policy, want) {
			t.Errorf("the policy lacks %q: %s", want, policy)
		}
	}
	if strings.Contains(policy, "unsafe") {
		t.Errorf("policy %s", policy)
	}
	if other := b.at("/reports/"); between(other.body, `<meta name="csp-nonce" content="`, `"`) == nonce {
		t.Error("two pages share a nonce")
	}
	ka := b.at("/reports/?lang=ka")
	ka.expect(t, http.StatusUnauthorized, `<script type="module" src="`+f.server.URL+`/widget.i18n.js"></script>`, `language="ka"`)

	csrf := csrfOf(t, page.body)
	form := func(more ...string) url.Values {
		values := url.Values{"csrf": {csrf}, "rd": {"/reports/"}, "lang": {"en"}}
		for i := 0; i+1 < len(more); i += 2 {
			values.Set(more[i], more[i+1])
		}
		return values
	}
	b.post(prefix+"/email", form("email", "reader@example.org")).expect(t, http.StatusForbidden, "The page has expired", "<altcha-widget")
	b.post(prefix+"/altcha", form("altcha", base64.StdEncoding.EncodeToString([]byte("guessed")))).expect(t, http.StatusForbidden, "The check failed", "<altcha-widget")
	before := len(f.calls())
	for _, garbage := range []string{"", "<script>", strings.Repeat("A", maxSolution+4)} {
		b.post(prefix+"/altcha", form("altcha", garbage)).expect(t, http.StatusForbidden, "The check failed")
	}
	if len(f.calls()) != before {
		t.Error("a malformed solution reached the service")
	}
	if h.mailer.count() != 0 {
		t.Fatal("a mail went out without a check")
	}

	checked := b.post(prefix+"/altcha", form("altcha", solution(1), "lang", "de"))
	field := b.get(checked.location(t).String())
	field.expect(t, http.StatusUnauthorized, `name="email"`, "Code per E-Mail")
	if strings.Contains(field.body, "<script") || strings.Contains(field.body, "<altcha-widget") || field.Header.Get("Content-Security-Policy") != h.srv.look.csp {
		t.Error("the address field comes with the widget or its policy")
	}
	ticket := cookieValue(b, ticketCookie)
	sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, field.body)}, "rd": {"/reports/"}, "lang": {"de"}, "email": {"reader@example.org"}})
	if sent.location(t).Path != prefix+"/code" || h.mailer.count() != 1 {
		t.Fatalf("no code after the check: %s, %d mails", sent.location(t), h.mailer.count())
	}

	if again := b.at("/"); !strings.Contains(again.body, "<altcha-widget") {
		t.Error("the ticket opened the address field twice")
	}
	b.jar.SetCookies(&url.URL{Scheme: "https", Host: b.host, Path: "/"}, []*http.Cookie{{Name: ticketCookie, Value: ticket, Path: "/"}})
	if !strings.Contains(b.at("/").body, "<altcha-widget") {
		t.Error("a spent ticket opened the address field")
	}
	b.post(prefix+"/email", form("email", "stranger@example.org")).expect(t, http.StatusForbidden, "The page has expired")
	b.post(prefix+"/altcha", form("altcha", solution(1))).expect(t, http.StatusForbidden, "The check failed")
	if h.mailer.count() != 1 || !strings.Contains(h.log(), "reason=altcha_replay") {
		t.Errorf("%d mails, log %s", h.mailer.count(), h.log())
	}
	for _, site := range f.calls() {
		if site != "gatekeeper" {
			t.Errorf("verified for site %q", site)
		}
	}
}

func TestAltchaTicketIsBound(t *testing.T) {
	h, _ := newAltchaHarness(t)
	b := h.browser("report.example.com")
	page := b.at("/")
	b.post(prefix+"/altcha", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "altcha": {solution(2)}})
	if !strings.Contains(b.at("/").body, `name="email"`) {
		t.Fatal("no address field after the check")
	}

	moved := h.browser("report.example.com")
	moved.ip = "198.51.100.9"
	moved.jar.SetCookies(&url.URL{Scheme: "https", Host: moved.host, Path: "/"}, []*http.Cookie{{Name: ticketCookie, Value: cookieValue(b, ticketCookie), Path: "/"}})
	if !strings.Contains(moved.at("/").body, "<altcha-widget") {
		t.Error("the ticket worked from another client address")
	}

	h.clock = h.clock.Add(ticketLifetime)
	if !strings.Contains(b.at("/").body, "<altcha-widget") {
		t.Error("an expired ticket opened the address field")
	}
}

func TestAltchaFailsClosed(t *testing.T) {
	h, f := newAltchaHarness(t)
	b := h.browser("report.example.com")
	page := b.at("/")
	form := url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "altcha": {solution(3)}}

	f.status = http.StatusTooManyRequests
	b.post(prefix+"/altcha", form).expect(t, http.StatusServiceUnavailable, "Code by email is not available right now", "Sign in with Zitadel")
	f.server.Close()
	b.post(prefix+"/altcha", form).expect(t, http.StatusServiceUnavailable, "Code by email is not available right now", "<altcha-widget")
	if strings.Contains(b.at("/").body, `name="email"`) || !strings.Contains(h.log(), "altcha unavailable") {
		t.Error("an unreachable service opened the address field")
	}
	if r := b.get(prefix + "/start/zitadel?rd=%2F"); r.StatusCode != http.StatusFound {
		t.Errorf("the provider stopped working: %d", r.StatusCode)
	}
}

func TestAltchaChecksAreLimited(t *testing.T) {
	h, _ := newAltchaHarness(t)
	b := h.browser("report.example.com")
	page := b.at("/")
	for i := 0; i < 10; i++ {
		b.post(prefix+"/altcha", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "altcha": {"Z3Vlc3M="}}).expect(t, http.StatusForbidden)
	}
	b.post(prefix+"/altcha", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "altcha": {solution(4)}}).expect(t, http.StatusTooManyRequests, "Too many attempts")
}

func TestAltchaLeavesTheOtherPagesWithoutScript(t *testing.T) {
	h, _ := newAltchaHarness(t)
	b := h.browser("report.example.com")
	page := b.at("/")
	b.post(prefix+"/altcha", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "altcha": {solution(5)}})
	field := b.at("/")
	sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, field.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}})
	pages := []*response{field, b.get(sent.location(t).String()), b.get(prefix + "/callback/zitadel?code=x&state=y")}
	b.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, field.body)}, "rd": {"/"}, "lang": {"en"}, "code": {h.mailer.last(t).Code}})
	pages = append(pages, b.get(prefix+"/sign_out"))
	h.load(`"report.example.com": ["reader@example.org"]`, `"report.example.com": []`, "UMAMI", `,
  "altcha": {"url": "https://altcha.example.com", "site": "gatekeeper"}`)
	pages = append(pages, b.at("/x"))
	for i, p := range pages {
		if strings.Contains(p.body, "<script") || (p.Header.Get("Content-Security-Policy") != "" && p.Header.Get("Content-Security-Policy") != h.srv.look.csp) {
			t.Errorf("page %d carries a script or another policy: %s", i, p.Header.Get("Content-Security-Policy"))
		}
	}
}

func TestAltchaEndpointNeedsTheSetting(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	page := b.at("/")
	if r := b.post(prefix+"/altcha", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "altcha": {solution(6)}}); r.StatusCode != http.StatusNotFound {
		t.Errorf("status %d", r.StatusCode)
	}
}
