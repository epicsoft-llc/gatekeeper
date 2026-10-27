package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthWithoutSession(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d", r.StatusCode)
	}
	unknown := h.browser("other.example.com")
	if r := unknown.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusForbidden {
		t.Errorf("unknown host: status %d", r.StatusCode)
	}
	if r := unknown.get(prefix + "/sign_in"); r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown host sign-in: status %d", r.StatusCode)
	}
}

func TestEmailFlow(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")

	page := b.at("/reports/latest/?tab=1&lang=de")
	page.expect(t, http.StatusUnauthorized, `<html lang="de">`, "Anmelden", "report.example.com", `name="email"`, "Mit Zitadel anmelden",
		`value="/reports/latest/?tab=1"`, `href="/reports/latest/?tab=1&amp;lang=en"`)
	if page.Header.Get("Content-Security-Policy") != h.srv.look.csp || page.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", page.Header)
	}

	sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/reports/latest/?tab=1"}, "lang": {"de"}, "email": {" Reader@Example.org "}})
	codeURL := sent.location(t)
	if codeURL.Path != prefix+"/code" || codeURL.Query().Get("rd") != "/reports/latest/?tab=1" || codeURL.Query().Get("lang") != "de" {
		t.Fatalf("redirect %s", codeURL)
	}
	mailed := h.mailer.last(t)
	if mailed.To != "reader@example.org" || mailed.Host != "report.example.com" || mailed.Lang != "de" || len(mailed.Code) != 8 || mailed.TTL != 15*time.Minute {
		t.Fatalf("mail %+v", mailed)
	}
	if strings.Contains(h.log(), mailed.Code) {
		t.Error("the code reached the log")
	}

	codePage := b.get(codeURL.String())
	codePage.expect(t, http.StatusOK, "Code eingeben", "15 Minuten", `autocomplete="one-time-code"`)

	wrong := b.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, codePage.body)}, "rd": {"/reports/latest/?tab=1"}, "lang": {"de"}, "code": {"00000000"}})
	if wrong.location(t).Query().Get("e") != "code" {
		t.Fatalf("wrong code: %s", wrong.location(t))
	}

	right := b.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, codePage.body)}, "rd": {"/reports/latest/?tab=1"}, "lang": {"de"}, "code": {mailed.Code[:4] + " " + mailed.Code[4:]}})
	if got := right.location(t).String(); got != "/reports/latest/?tab=1" {
		t.Fatalf("after the code: %s", got)
	}
	auth := b.request(http.MethodGet, prefix+"/auth", nil, "/reports/latest/")
	if auth.StatusCode != http.StatusAccepted || auth.Header.Get("X-Gatekeeper-User") != "reader@example.org" {
		t.Fatalf("auth after sign-in: %d %q", auth.StatusCode, auth.Header.Get("X-Gatekeeper-User"))
	}
	if !strings.Contains(h.log(), `msg="signed in" host=report.example.com method=email user=reader@example.org`) {
		t.Errorf("log: %s", h.log())
	}
	again := b.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, codePage.body)}, "rd": {"/"}, "lang": {"de"}, "code": {mailed.Code}})
	if again.location(t).Query().Get("e") != "expired" {
		t.Error("a used code worked twice")
	}
}

func TestAddressWithoutAccessLooksTheSame(t *testing.T) {
	h := newHarness(t)
	known, stranger := h.browser("report.example.com"), h.browser("report.example.com")
	stranger.ip = "203.0.113.8"
	var redirects []string
	for _, c := range []struct {
		b       *browser
		address string
	}{{known, "reader@example.org"}, {stranger, "stranger@example.org"}} {
		page := c.b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
		sent := c.b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {c.address}})
		redirects = append(redirects, sent.location(t).String())
		if _, ok := c.b.h.srv.readPending(cookieRequest(c.b), &request{host: "report.example.com"}); !ok {
			t.Errorf("%s got no pending code", c.address)
		}
	}
	if redirects[0] != redirects[1] {
		t.Errorf("answers differ: %v", redirects)
	}
	if h.mailer.count() != 1 || h.mailer.last(t).To != "reader@example.org" {
		t.Errorf("mails: %d", h.mailer.count())
	}
	if strings.Contains(h.log(), "stranger") {
		t.Error("an address without access reached the log")
	}
	codePage := stranger.get(prefix + "/code?rd=%2F&lang=en")
	for i := 0; i < 4; i++ {
		r := stranger.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, codePage.body)}, "rd": {"/"}, "lang": {"en"}, "code": {h.mailer.last(t).Code}})
		if r.location(t).Query().Get("e") != "code" {
			t.Fatalf("attempt %d: %s", i+1, r.location(t))
		}
	}
	last := stranger.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, codePage.body)}, "rd": {"/"}, "lang": {"en"}, "code": {"12345678"}})
	if last.location(t).Query().Get("e") != "expired" {
		t.Errorf("fifth attempt: %s", last.location(t))
	}
}

func cookieRequest(b *browser) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range b.jar.Cookies(&url.URL{Scheme: "https", Host: b.host, Path: "/"}) {
		r.AddCookie(c)
	}
	return r
}

func requestCode(t *testing.T, b *browser, address string) (*response, string) {
	t.Helper()
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {address}})
	codePage := b.get(sent.location(t).String())
	return codePage, csrfOf(t, codePage.body)
}

func TestCodeAttemptsAreLimited(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	_, csrf := requestCode(t, b, "reader@example.org")
	code := h.mailer.last(t).Code
	for i := 0; i < 5; i++ {
		b.post(prefix+"/code", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "code": {"99999999"}})
	}
	r := b.post(prefix+"/code", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "code": {code}})
	if r.location(t).Query().Get("e") != "expired" {
		t.Errorf("the right code still worked after five wrong ones: %s", r.location(t))
	}
	if !strings.Contains(h.log(), "code attempts used up") {
		t.Error("used up attempts are not logged")
	}
}

func TestCodeExpires(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	_, csrf := requestCode(t, b, "reader@example.org")
	h.clock = h.clock.Add(15 * time.Minute)
	r := b.post(prefix+"/code", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "code": {h.mailer.last(t).Code}})
	if r.location(t).Query().Get("e") != "expired" {
		t.Errorf("an expired code worked: %s", r.location(t))
	}
}

func TestNewCodeReplacesOld(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	_, _ = requestCode(t, b, "reader@example.org")
	first := h.mailer.last(t).Code
	other := h.browser("report.example.com")
	_, _ = requestCode(t, other, "reader@example.org")
	_, csrf := requestCode(t, b, "reader@example.org")
	if r := b.post(prefix+"/code", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "code": {first}}); r.location(t).Query().Get("e") == "" {
		t.Error("an old code still worked")
	}
}

func TestCodeOnlyInTheBrowserThatAskedForIt(t *testing.T) {
	h := newHarness(t)
	asking, other := h.browser("report.example.com"), h.browser("report.example.com")
	_, _ = requestCode(t, asking, "reader@example.org")
	page := other.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	r := other.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "code": {h.mailer.last(t).Code}})
	if r.location(t).Query().Get("e") != "expired" {
		t.Errorf("the code worked in another browser: %s", r.location(t))
	}
}

func TestEmailLink(t *testing.T) {
	h := newHarness(t, `"from_name": "Example"`, `"from_name": "Example", "link": true`)
	b := h.browser("report.example.com")
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/reports/")
	sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/reports/"}, "lang": {"en"}, "email": {"reader@example.org"}})
	for _, c := range sent.Cookies() {
		if c.Name == pendingCookie && c.SameSite != http.SameSiteLaxMode {
			t.Errorf("pending cookie SameSite %v - a click in webmail would arrive without it", c.SameSite)
		}
	}
	mailed := h.mailer.last(t)
	link, err := url.Parse(mailed.Link)
	if err != nil || link.Scheme != "https" || link.Host != "report.example.com" || link.Path != prefix+"/code" || link.Query().Get("rd") != "/reports/" || len(link.Query().Get("t")) != 26 {
		t.Fatalf("link %q", mailed.Link)
	}
	if strings.Contains(h.log(), link.Query().Get("t")) {
		t.Error("the token of the link reached the log")
	}

	other := h.browser("report.example.com")
	if got := other.get(link.RequestURI()).location(t); got.Path != prefix+"/sign_in" || got.Query().Get("e") != "link" {
		t.Errorf("the link in another browser: %s", got)
	}
	other.get(prefix+"/sign_in?rd=%2F&lang=en&e=link").expect(t, http.StatusUnauthorized, "only in the browser where the code was requested")

	wrong := *link
	query := wrong.Query()
	query.Set("t", "AAAAAAAAAAAAAAAAAAAAAAAAAA")
	wrong.RawQuery = query.Encode()
	for i := 0; i < 6; i++ {
		if got := b.get(wrong.RequestURI()).location(t); got.Path != prefix+"/code" || got.Query().Get("e") != "link" {
			t.Fatalf("wrong token %d: %s", i+1, got)
		}
	}

	if got := b.get(link.RequestURI()).location(t).String(); got != "/reports/" {
		t.Fatalf("after the link: %s - wrong tokens must cost no attempt", got)
	}
	auth := b.request(http.MethodGet, prefix+"/auth", nil, "/reports/")
	if auth.StatusCode != http.StatusAccepted || auth.Header.Get("X-Gatekeeper-User") != "reader@example.org" {
		t.Fatalf("auth after the link: %d %q", auth.StatusCode, auth.Header.Get("X-Gatekeeper-User"))
	}
	if !strings.Contains(h.log(), `msg="signed in" host=report.example.com method=email user=reader@example.org by=link`) {
		t.Errorf("log: %s", h.log())
	}
	if got := b.get(link.RequestURI()).location(t); got.Query().Get("e") != "link" {
		t.Errorf("a used link: %s", got)
	}
}

func TestNoLinkByDefault(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}})
	for _, c := range sent.Cookies() {
		if c.Name == pendingCookie && c.SameSite != http.SameSiteStrictMode {
			t.Errorf("pending cookie SameSite %v without the link", c.SameSite)
		}
	}
	if h.mailer.last(t).Link != "" {
		t.Error("a link without mail.link")
	}
	b.get(prefix+"/code?rd=%2F&lang=en&t=AAAAAAAAAAAAAAAAAAAAAAAAAA").expect(t, http.StatusOK, `name="code"`)
}

func TestForms(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	csrf := csrfOf(t, page.body)

	b.post(prefix+"/email", url.Values{"rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}}).expect(t, http.StatusForbidden, "The page has expired")
	b.post(prefix+"/email", url.Values{"csrf": {csrf + "x"}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}}).expect(t, http.StatusForbidden)
	b.post(prefix+"/email", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "email": {"not an address"}}).expect(t, http.StatusBadRequest, "valid email address")
	if h.mailer.count() != 0 {
		t.Error("a refused form sent a mail")
	}

	b.header.Set("Sec-Fetch-Site", "cross-site")
	if r := b.post(prefix+"/email", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}}); r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site post: status %d", r.StatusCode)
	}
	b.header.Del("Sec-Fetch-Site")

	other := h.browser("admin.example.com")
	if r := other.post(prefix+"/email", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "email": {"admin@example.com"}}); r.StatusCode != http.StatusNotFound {
		t.Errorf("email on a host without it: status %d", r.StatusCode)
	}
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	csrf := csrfOf(t, page.body)
	for i := 0; i < 10; i++ {
		b.post(prefix+"/email", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "email": {"someone" + string(rune('a'+i)) + "@example.org"}})
	}
	b.post(prefix+"/email", url.Values{"csrf": {csrf}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}}).expect(t, http.StatusTooManyRequests, "Too many attempts")

	for i := 0; i < 6; i++ {
		c := h.browser("report.example.com")
		c.ip = "198.51.100." + string(rune('1'+i))
		p := c.request(http.MethodGet, prefix+"/sign_in", nil, "/")
		r := c.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, p.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"other@example.org"}})
		if i < 5 && r.StatusCode != http.StatusSeeOther {
			t.Fatalf("request %d: status %d", i+1, r.StatusCode)
		}
		if i == 5 && r.StatusCode != http.StatusTooManyRequests {
			t.Errorf("sixth request for one address: status %d", r.StatusCode)
		}
	}
	if strings.Contains(h.log(), "198.51.100") || strings.Contains(h.log(), "203.0.113") {
		t.Error("a client address reached the log")
	}
}

func TestIPv6ClientsShareTheirNetwork(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 11; i++ {
		b := h.browser("report.example.com")
		b.ip = fmt.Sprintf("2001:db8:1:2::%x", i+1)
		p := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
		r := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, p.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"x" + string(rune('a'+i)) + "@example.org"}})
		if i == 10 && r.StatusCode != http.StatusTooManyRequests {
			t.Errorf("eleventh request from one /64: status %d", r.StatusCode)
		}
	}
}

func TestSessionIsBoundToItsHostAndTheConfiguration(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	b.signInByEmail("reader@example.org", "/")
	cookie := cookieRequest(b).Header.Get("Cookie")

	elsewhere := httptest.NewRequest(http.MethodGet, prefix+"/auth", nil)
	elsewhere.RemoteAddr = "127.0.0.1:1"
	elsewhere.Header.Set("X-Forwarded-Host", "admin.example.com")
	elsewhere.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, elsewhere)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("the session of report.example.com opened admin.example.com: %d", rec.Code)
	}

	h.load(`"report.example.com": ["reader@example.org"]`, `"report.example.com": []`)
	auth := b.request(http.MethodGet, prefix+"/auth", nil, "/")
	if auth.StatusCode != http.StatusForbidden {
		t.Errorf("a removed address kept its access: %d", auth.StatusCode)
	}
	denied := b.at("/x")
	denied.expect(t, http.StatusForbidden, "No access", "reader@example.org", prefix+"/sign_out")

	h.load(`["email", "zitadel"]`, `["zitadel"]`)
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusForbidden {
		t.Errorf("a removed sign-in method kept its session: %d", r.StatusCode)
	}
}

func TestDomainEntry(t *testing.T) {
	h := newHarness(t, `"report.example.com": ["reader@example.org"]`, `"report.example.com": ["@example.net"]`)
	b := h.browser("report.example.com")
	b.signInByEmail(" Someone@Example.net ", "/")
	if to := h.mailer.last(t).To; to != "someone@example.net" {
		t.Errorf("mail to %q", to)
	}
	if auth := b.request(http.MethodGet, prefix+"/auth", nil, "/"); auth.StatusCode != http.StatusAccepted {
		t.Errorf("a member of the domain was refused: %d", auth.StatusCode)
	}

	routed := h.browser("report.example.com")
	routed.ip = "203.0.113.8"
	page := routed.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	routed.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"a%b@example.net"}})
	if h.mailer.count() != 1 {
		t.Errorf("a local part with %% got a mail: %d mails", h.mailer.count())
	}

	h.load(`"report.example.com": ["reader@example.org"]`, `"report.example.com": []`)
	if auth := b.request(http.MethodGet, prefix+"/auth", nil, "/"); auth.StatusCode != http.StatusForbidden {
		t.Errorf("a removed domain kept its access: %d", auth.StatusCode)
	}
}

func TestSessionExpiresWithTheConfiguredLifetime(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	b.signInByEmail("reader@example.org", "/")
	h.clock = h.clock.Add(23 * time.Hour)
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d before the end", r.StatusCode)
	}
	h.load(`"allow": ["report.example.com", "all"]}`, `"allow": ["report.example.com", "all"], "session": "1h"}`)
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("a shortened lifetime did not apply: %d", r.StatusCode)
	}
	h.load()
	h.clock = h.clock.Add(time.Hour)
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d after 24 hours", r.StatusCode)
	}
}

func TestTamperedOrForeignCookies(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	b.signInByEmail("reader@example.org", "/")
	cookies := b.jar.Cookies(&url.URL{Scheme: "https", Host: "report.example.com", Path: "/"})
	for _, c := range cookies {
		if c.Name != sessionCookie {
			continue
		}
		raw, _ := base64.RawURLEncoding.DecodeString(c.Value)
		raw[len(raw)/2] ^= 1
		forged := httptest.NewRequest(http.MethodGet, prefix+"/auth", nil)
		forged.RemoteAddr = "127.0.0.1:1"
		forged.Header.Set("X-Forwarded-Host", "report.example.com")
		forged.AddCookie(&http.Cookie{Name: sessionCookie, Value: base64.RawURLEncoding.EncodeToString(raw)})
		rec := httptest.NewRecorder()
		h.h.ServeHTTP(rec, forged)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("a tampered session cookie: %d", rec.Code)
		}
	}

	write(t, h.dir, "secret", strings.Repeat("t", 48))
	h.load()
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("a session survived a new secret: %d", r.StatusCode)
	}
}

func TestForwardedHeadersOnlyFromTrustedProxies(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest(http.MethodGet, prefix+"/auth", nil)
	r.RemoteAddr = "10.1.2.3:4000"
	r.Host = "evil.example.net"
	r.Header.Set("X-Forwarded-Host", "report.example.com")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("an untrusted peer chose the host: %d", rec.Code)
	}
}

func TestRedirectsStayOnTheHost(t *testing.T) {
	h := newHarness(t)
	for _, rd := range []string{"//evil.example.net/", "https://evil.example.net/", "/\\evil.example.net", "/%2F/evil.example.net", "/_gatekeeper/sign_out"} {
		b := h.browser("report.example.com")
		page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
		sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {rd}, "lang": {"en"}, "email": {"reader@example.org"}})
		codePage := b.get(sent.location(t).String())
		r := b.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, codePage.body)}, "rd": {rd}, "lang": {"en"}, "code": {h.mailer.last(t).Code}})
		if got := r.Header.Get("Location"); got != "/" {
			t.Errorf("rd %q led to %q", rd, got)
		}
	}
}

func TestSignOut(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	b.signInByEmail("reader@example.org", "/")
	signedIn := func() bool {
		return b.request(http.MethodGet, prefix+"/auth", nil, "/").StatusCode == http.StatusAccepted
	}

	page := b.get(prefix + "/sign_out?lang=de")
	page.expect(t, http.StatusOK, "<title>Abmelden · Gatekeeper</title>", "Sie sind als reader@example.org angemeldet.", `<form method="post" action="/_gatekeeper/sign_out">`,
		`href="/_gatekeeper/sign_out?lang=ru"`)
	if !signedIn() {
		t.Fatal("the page alone signed out")
	}
	b.post(prefix+"/sign_out", url.Values{"lang": {"en"}}).expect(t, http.StatusForbidden, "The page has expired", `name="csrf"`)
	b.header.Set("Sec-Fetch-Site", "cross-site")
	if r := b.post(prefix+"/sign_out", url.Values{"csrf": {csrfOf(t, page.body)}}); r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site sign-out: status %d", r.StatusCode)
	}
	b.header.Del("Sec-Fetch-Site")
	if !signedIn() {
		t.Fatal("a sign-out without a valid form ended the session")
	}

	r := b.post(prefix+"/sign_out", url.Values{"csrf": {csrfOf(t, page.body)}, "lang": {"de"}})
	if r.location(t).String() != "/" {
		t.Errorf("after sign-out: %s", r.location(t))
	}
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("still signed in: %d", r.StatusCode)
	}
	if !strings.Contains(h.log(), `msg="signed out" host=report.example.com user=reader@example.org`) {
		t.Errorf("log: %s", h.log())
	}
	if r := b.get(prefix + "/sign_out"); r.location(t).String() != "/" {
		t.Errorf("the page without a session: %d", r.StatusCode)
	}
}

func TestSignOutFromTheDeniedPage(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	b.signInByEmail("reader@example.org", "/")
	h.load(`"report.example.com": ["reader@example.org"]`, `"report.example.com": []`)
	denied := b.at("/x")
	denied.expect(t, http.StatusForbidden, "No access", `<form method="post" action="/_gatekeeper/sign_out">`)
	if r := b.post(prefix+"/sign_out", url.Values{"csrf": {csrfOf(t, denied.body)}, "lang": {"en"}}); r.location(t).String() != "/" {
		t.Fatalf("sign-out from the denied page: %d", r.StatusCode)
	}
	if r := b.request(http.MethodGet, prefix+"/auth", nil, "/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("still signed in: %d", r.StatusCode)
	}
}

func TestForwardAuthCarriesThePages(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	page := b.request(http.MethodGet, prefix+"/forward_auth", nil, "/docs/?lang=ru")
	page.expect(t, http.StatusUnauthorized, `<html lang="ru">`, "Вход", `value="/docs/"`)
	b.signInByEmail("reader@example.org", "/")
	ok := b.request(http.MethodGet, prefix+"/forward_auth", nil, "/docs/")
	if ok.StatusCode != http.StatusOK || ok.Header.Get("X-Gatekeeper-User") != "reader@example.org" {
		t.Errorf("signed in: %d %q", ok.StatusCode, ok.Header.Get("X-Gatekeeper-User"))
	}
	h.load(`"report.example.com": ["reader@example.org"]`, `"report.example.com": []`)
	b.request(http.MethodGet, prefix+"/forward_auth", nil, "/docs/").expect(t, http.StatusForbidden, "No access")
}

func TestPagesKeepTheirPolicy(t *testing.T) {
	h := newHarness(t)
	page := h.browser("report.example.com").at("/")
	if !strings.Contains(page.body, "<style>"+string(h.srv.look.css)+"</style>") {
		t.Error("the style element differs from the hashed one")
	}
	sum := sha256.Sum256([]byte(h.srv.look.css))
	if !strings.Contains(page.Header.Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Error("the CSP does not carry the hash of the style")
	}
	if found := regexp.MustCompile(`<script|\sstyle=|\son[a-z]+=`).FindString(page.body); found != "" {
		t.Errorf("the page contains %q", found)
	}
	if page.Header.Get("X-Frame-Options") != "DENY" || page.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", page.Header)
	}
}

func TestEscaping(t *testing.T) {
	h := newHarness(t)
	b := h.browser("report.example.com")
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, `/"><script>alert(1)</script>`)
	if strings.Contains(page.body, "<script>") {
		t.Error("the return path reached the page unescaped")
	}
}

func TestUmami(t *testing.T) {
	var mu sync.Mutex
	var events []map[string]any
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Payload map[string]any `json:"payload"`
		}
		data, _ := io.ReadAll(r.Body)
		json.Unmarshal(data, &body)
		mu.Lock()
		events = append(events, body.Payload)
		mu.Unlock()
	}))
	defer collector.Close()
	h := newHarness(t, "UMAMI", `,
  "umami": {"url": "`+collector.URL+`", "website": "gate", "respect_opt_out": ["admin.example.com"]}`)
	h.srv.umami.client = collector.Client()

	b := h.browser("report.example.com")
	b.at("/reports/?lang=ka")
	b.at("/reports/")
	optOut := h.browser("admin.example.com")
	optOut.header.Set("Sec-GPC", "1")
	optOut.at("/")
	favicon := h.browser("report.example.com")
	favicon.header.Set("Sec-Fetch-Dest", "image")
	favicon.at("/favicon.ico")

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("%d events: %v", len(events), events)
	}
	var language, view map[string]any
	for _, e := range events {
		if e["name"] == "gate-language" {
			language = e
		} else {
			view = e
		}
	}
	if language == nil || language["hostname"] != "report.example.com" || language["ip"] != "203.0.113.7" || language["url"] != "/reports/" {
		t.Errorf("language event %v", language)
	}
	if data, _ := language["data"].(map[string]any); data["lang"] != "ka" || data["domain"] != "report.example.com" {
		t.Errorf("language data %v", language["data"])
	}
	if view == nil || view["name"] != nil || view["website"] != "gate" {
		t.Errorf("page view %v", view)
	}
}

func TestMailQueueFull(t *testing.T) {
	h := newHarness(t)
	h.mailer.full = true
	b := h.browser("report.example.com")
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	r := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}})
	if r.StatusCode != http.StatusSeeOther || !strings.Contains(h.log(), "mail queue full") {
		t.Errorf("status %d, log %s", r.StatusCode, h.log())
	}
}

func TestNoOracleWhenACodeIsReplaced(t *testing.T) {
	h := newHarness(t)
	site := &url.URL{Scheme: "https", Host: "report.example.com", Path: "/"}
	for _, address := range []string{"reader@example.org", "stranger@example.org"} {
		b := h.browser("report.example.com")
		b.ip = "198.51.100.77"
		page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
		form := url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {address}}
		b.post(prefix+"/email", form)
		first := ""
		for _, c := range b.jar.Cookies(site) {
			if c.Name == pendingCookie {
				first = c.Value
			}
		}
		codePage := b.get(b.post(prefix+"/email", form).location(t).String())
		b.jar.SetCookies(site, []*http.Cookie{{Name: pendingCookie, Value: first, Path: "/"}})
		r := b.post(prefix+"/code", url.Values{"csrf": {csrfOf(t, codePage.body)}, "rd": {"/"}, "lang": {"en"}, "code": {"00000000"}})
		if got := r.location(t).Query().Get("e"); got != "expired" {
			t.Errorf("%s: the first code after a second request answers %q - the answers must not differ", address, got)
		}
	}
}

func TestNeutralBranding(t *testing.T) {
	h := newHarness(t)
	page := h.browser("report.example.com").at("/")
	page.expect(t, http.StatusUnauthorized, "<title>Sign in · Gatekeeper</title>", `<div class="brand"><svg class="mark" aria-hidden="true" focusable="false" viewBox="0 0 16 16">`,
		`fill="url(#gatekeeper-mark-mark)"`, "</svg>Gatekeeper</div>", `<link rel="icon" href="data:image/svg&#43;xml;base64,`)
	if strings.Contains(page.body, "epicsoft") || strings.Contains(page.body, `class="owner"`) || strings.Contains(page.body, "</nav>\n<a") {
		t.Error("the neutral page carries a brand or an owner")
	}
	if strings.Contains(page.body, `class="backdrop"`) {
		t.Error("the neutral page has a backdrop")
	}
	if !strings.Contains(string(h.srv.look.css), "--brand:#04a9f3;") {
		t.Error("the neutral page lacks the default colours")
	}
}

func TestBrandingOnThePages(t *testing.T) {
	dir := t.TempDir()
	mark := write(t, dir, "mark.svg", `<svg xmlns="http://www.w3.org/2000/svg" width="20" viewBox="0 0 20 10"><defs><linearGradient id="g"><stop offset="0" stop-color="#8b0000"/></linearGradient></defs><rect width="20" height="10" fill="url(#g)"/></svg>`)
	texts := write(t, dir, "texts.json", `{"en": {"signin_title": "Members of {name}"}}`)
	h := newHarness(t, "UMAMI", `,
  "branding": {"name": "Example", "owner": "Example Ltd", "url": "https://example.com", "mark_file": `+quote(mark)+`, "texts_file": `+quote(texts)+`,
    "colors": {"brand": "#8b0000", "brand_strong": "#5a0000", "brand_dark": "#ff8080"}}`)
	page := h.browser("report.example.com").at("/")
	page.expect(t, http.StatusUnauthorized, "<title>Members of Example</title>", `viewBox="0 0 20 10"><defs><linearGradient id="gatekeeper-mark-g">`,
		`fill="url(#gatekeeper-backdrop-g)"`, "</svg>Example</div>", `<a href="https://example.com">Example Ltd</a>`)
	if !strings.Contains(page.body, `<svg class="mark" aria-hidden="true" focusable="false" viewBox="0 0 20 10">`) {
		t.Error("the inline mark keeps its width")
	}
	css := string(h.srv.look.css)
	for _, want := range []string{"--brand:#8b0000;", "--accent:#5a0000;", "--accent:#ff8080;", ".btn--primary{background:var(--brand);color:#ffffff;", "rgb(139 0 0 / 30%)"} {
		if !strings.Contains(css, want) {
			t.Errorf("the style lacks %q", want)
		}
	}
	sum := sha256.Sum256([]byte(css))
	if !strings.Contains(page.Header.Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") || !strings.Contains(page.body, "<style>"+css+"</style>") {
		t.Error("the CSP does not carry the hash of the branded style")
	}
	favicon, _ := strings.CutPrefix(string(h.srv.look.favicon), "data:image/svg+xml;base64,")
	if document, err := base64.StdEncoding.DecodeString(favicon); err != nil || !strings.HasPrefix(string(document), `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 10">`) {
		t.Errorf("favicon %s", document)
	}
	other := h.browser("report.example.com")
	other.at("/?lang=de").expect(t, http.StatusUnauthorized, "<title>Anmelden · Example</title>")
}

func TestOneNetworkCannotFloodTheStores(t *testing.T) {
	h := newHarness(t)
	refused := 0
	for i := 0; i < 170; i++ {
		b := h.browser("report.example.com")
		b.ip = fmt.Sprintf("2001:db8:7:%x::1", i)
		page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
		if r := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {fmt.Sprintf("x%d@example.org", i)}}); r.StatusCode == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused != 10 {
		t.Errorf("%d of 170 requests from one /48 refused, want the 10 beyond 160", refused)
	}
	other := h.browser("report.example.com")
	other.ip = "2001:db8:8::1"
	page := other.request(http.MethodGet, prefix+"/sign_in", nil, "/")
	if r := other.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {"reader@example.org"}}); r.StatusCode != http.StatusSeeOther {
		t.Errorf("another network was refused: %d", r.StatusCode)
	}
}

func TestDomainEntriesUseHalfOfTotal(t *testing.T) {
	h := newHarness(t, `"from_name": "Example"}`, `"from_name": "Example", "limits": {"total": {"count": 4, "window": "1h"}}}`,
		`"report.example.com": ["reader@example.org"]`, `"report.example.com": ["reader@example.org", "@example.net"]`)
	request := func(address string, i int) {
		b := h.browser("report.example.com")
		b.ip = fmt.Sprintf("198.51.100.%d", i+1)
		page := b.request(http.MethodGet, prefix+"/sign_in", nil, "/")
		if r := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(t, page.body)}, "rd": {"/"}, "lang": {"en"}, "email": {address}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s: status %d - the answer must not change", address, r.StatusCode)
		}
	}
	for i := 0; i < 5; i++ {
		request(fmt.Sprintf("made-up-%d@example.net", i), i)
	}
	if h.mailer.count() != 2 || !strings.Contains(h.log(), "limit=domains") {
		t.Fatalf("%d mails to a domain entry with a total of 4", h.mailer.count())
	}
	request("reader@example.org", 10)
	if h.mailer.count() != 3 || h.mailer.last(t).To != "reader@example.org" {
		t.Errorf("a listed address got no mail after a flood at the domain: %d mails", h.mailer.count())
	}
}
