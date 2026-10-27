package server

import (
	"crypto/rand"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSafeReturn(t *testing.T) {
	kept := []string{"/", "/a/b?c=d&e=f", "/reports/latest/", "/%C3%A4", "/a?next=//b"}
	for _, p := range kept {
		if got := safeReturn(p); got != p {
			t.Errorf("safeReturn(%q) = %q", p, got)
		}
	}
	replaced := []string{
		"", "a", "//evil.example.net", "///evil.example.net", "/\\evil.example.net", "https://evil.example.net/",
		"/%2F/evil.example.net", "/%2f%2fevil", "/%5Cevil", "/ space", "/a\tb", "/a\nb", "/_gatekeeper/sign_out", "/_gatekeeper",
		"/./_gatekeeper/sign_out", "/x/../_gatekeeper/code", "/%2E/_gatekeeper/sign_out",
		"/" + strings.Repeat("a", 2048), "/%zz",
	}
	for _, p := range replaced {
		if got := safeReturn(p); got != "/" {
			t.Errorf("safeReturn(%q) = %q, want /", p, got)
		}
	}
}

func FuzzSafeReturn(f *testing.F) {
	for _, seed := range []string{"/", "//x", "/\\x", "/%2F/x", "/a?b=c", "https://x/"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got := safeReturn(p)
		base, _ := url.Parse("https://report.example.com/x/y")
		target, err := url.Parse(got)
		if err != nil {
			t.Fatalf("%q became the unparsable %q", p, got)
		}
		if resolved := base.ResolveReference(target); resolved.Host != "report.example.com" || resolved.Scheme != "https" {
			t.Errorf("%q leads to %s", p, resolved)
		}
	})
}

func TestSplitAndWithLang(t *testing.T) {
	cases := []struct{ uri, rest, lang string }{
		{"/a", "/a", ""},
		{"/a?lang=de", "/a", "de"},
		{"/a?x=1&lang=ru&y=2", "/a?x=1&y=2", "ru"},
		{"/a?lang=ka&lang=de", "/a", "ka"},
		{"/a?x=%20&&lang=", "/a?x=%20", ""},
	}
	for _, c := range cases {
		if rest, lang := splitLang(c.uri); rest != c.rest || lang != c.lang {
			t.Errorf("splitLang(%q) = %q, %q", c.uri, rest, lang)
		}
	}
	if got := withLang("/a?x=1&lang=de", "en"); got != "/a?x=1&lang=en" {
		t.Errorf("withLang: %q", got)
	}
	if got := withLang("/a", "ka"); got != "/a?lang=ka" {
		t.Errorf("withLang: %q", got)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Report.Example.com":      "report.example.com",
		"report.example.com:443":  "report.example.com",
		"report.example.com.":     "report.example.com",
		"localhost":               "",
		"report.example.com:abc":  "",
		"evil.example.net/x":      "",
		"[::1]:443":               "",
		"report..example.com":     "",
		"xn--80ak6aa92e.com":      "xn--80ak6aa92e.com",
		" report.example.com ":    "report.example.com",
		"report_x.example.com":    "",
		"a.example.com, b.ex.com": "",
		"report.exampİe.com":      "",
		"\u212Aeport.example.com": "",
	}
	for input, want := range cases {
		if got := normalizeHost(input); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestClientAddress(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-Host", "report.example.com")
	r.Header.Set("X-Real-Ip", "::ffff:198.51.100.4")
	req, ok := h.srv.resolve(r)
	if !ok || req.client != "198.51.100.4" {
		t.Errorf("mapped IPv4: %+v", req)
	}
	r.Header.Set("X-Real-Ip", "2001:db8:a:b:c::1")
	if req, _ := h.srv.resolve(r); req.client != "2001:db8:a:b::/64" || req.ip != "2001:db8:a:b:c::1" {
		t.Errorf("IPv6: %+v", req)
	}
	r.Header.Set("X-Real-Ip", "garbage")
	if req, _ := h.srv.resolve(r); req.client != "127.0.0.1" {
		t.Errorf("garbage falls back to the proxy: %+v", req)
	}

	r.Header.Set("X-Real-Ip", "2001:db8:a:b:c::1")
	if req, _ := h.srv.resolve(r); req.network != "2001:db8:a::/48" {
		t.Errorf("IPv6 network: %+v", req)
	}

	h.load(`"trusted_proxies": ["127.0.0.1"],`, `"trusted_proxies": ["127.0.0.1"], "client_ip_header": "X-Forwarded-For",`)
	r.Header.Set("X-Forwarded-For", "192.0.2.1, 198.51.100.9")
	if req, _ := h.srv.resolve(r); req.client != "198.51.100.9" {
		t.Errorf("X-Forwarded-For takes the last entry: %+v", req)
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.66")
	r.Header.Add("X-Forwarded-For", "198.51.100.10")
	if req, _ := h.srv.resolve(r); req.client != "198.51.100.10" {
		t.Errorf("X-Forwarded-For takes the last line, the proxy's own: %+v", req)
	}
}

func TestForwardedHostTheProxyWrote(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = "gatekeeper:8080"
	r.Header.Add("X-Forwarded-Host", "admin.example.com")
	r.Header.Add("X-Forwarded-Host", "report.example.com")
	if req, ok := h.srv.resolve(r); !ok || req.host != "report.example.com" {
		t.Errorf("a second line of the proxy: %+v", req)
	}
	r.Header.Set("X-Forwarded-Host", "admin.example.com, report.example.com")
	if req, ok := h.srv.resolve(r); !ok || req.host != "report.example.com" {
		t.Errorf("a value the proxy appended: %+v", req)
	}

	r.Host = "report.example.com"
	r.Header.Set("X-Forwarded-Host", "admin.example.com")
	if req, ok := h.srv.resolve(r); ok {
		t.Errorf("Host names one configured host, X-Forwarded-Host another, and gatekeeper chose %q", req.host)
	}
	r.Header.Set("X-Forwarded-Host", "Report.Example.com:443")
	if req, ok := h.srv.resolve(r); !ok || req.host != "report.example.com" {
		t.Errorf("the same host twice: %+v", req)
	}
}

func TestCodeStore(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newCodeStore([]byte("key"), 10*time.Minute, 3, 3)
	id, code, link := store.issue("a@example.com", "h.example.com", true, now)
	if len(code) != 8 || !onlyDigits(code) || len(id) != 26 || len(link) != 26 || link == id {
		t.Fatalf("issue: %q %q %q", id, code, link)
	}
	if _, v := store.verify(id, "other.example.com", code, now); v != gone {
		t.Error("a code worked on another host")
	}
	if email, v := store.verify(id, "h.example.com", code[:4]+"-"+code[4:], now); v != accepted || email != "a@example.com" {
		t.Errorf("verify: %q %v", email, v)
	}

	dummy, dummyCode, dummyLink := store.issue("stranger@example.com", "h.example.com", false, now)
	if _, v := store.verify(dummy, "h.example.com", dummyCode, now); v != wrong {
		t.Error("a code for an address without access was accepted")
	}
	if _, v := store.follow(dummy, "h.example.com", dummyLink, now); v != wrong {
		t.Error("a link for an address without access was accepted")
	}

	for _, allowed := range []bool{true, false} {
		first, _, _ := store.issue("x@example.com", "h.example.com", allowed, now)
		store.issue("x@example.com", "h.example.com", allowed, now)
		if _, v := store.verify(first, "h.example.com", "00000000", now); v != gone {
			t.Errorf("allowed=%v: the first code survived the second request (%v) - an oracle", allowed, v)
		}
	}

	full := newCodeStore([]byte("key"), 10*time.Minute, 3, 3)
	oldest, _, _ := full.issue("1@example.com", "h.example.com", false, now)
	full.issue("2@example.com", "h.example.com", false, now.Add(time.Second))
	full.issue("3@example.com", "h.example.com", false, now.Add(2*time.Second))
	newest, newestCode, _ := full.issue("b@example.com", "h.example.com", true, now.Add(3*time.Second))
	if len(full.items) != 3 {
		t.Errorf("%d items in a store of 3", len(full.items))
	}
	if _, ok := full.items[oldest]; ok {
		t.Error("a full store did not give up its oldest entry")
	}
	if _, v := full.verify(newest, "h.example.com", newestCode, now.Add(4*time.Second)); v != accepted {
		t.Error("the newest code does not work in a full store")
	}

	if string(store.mac("x", "12345678")) == string(store.mac("y", "12345678")) {
		t.Error("the mac does not depend on the id")
	}
}

func TestCodeStoreLink(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newCodeStore([]byte("key"), 10*time.Minute, 3, 3)
	id, code, link := store.issue("a@example.com", "h.example.com", true, now)
	for i := 0; i < 5; i++ {
		if _, v := store.follow(id, "h.example.com", rand.Text(), now); v != wrong {
			t.Fatalf("wrong link %d: %v", i+1, v)
		}
	}
	if _, v := store.follow(id, "h.example.com", code, now); v != wrong {
		t.Error("the code worked as the token of the link")
	}
	if _, v := store.follow(id, "other.example.com", link, now); v != gone {
		t.Error("a link worked on another host")
	}
	if email, v := store.follow(id, "h.example.com", link, now); v != accepted || email != "a@example.com" {
		t.Errorf("follow after wrong links: %q %v - they must cost no attempt", email, v)
	}
	if _, v := store.verify(id, "h.example.com", code, now); v != gone {
		t.Error("the code still worked after the link")
	}

	id, code, link = store.issue("a@example.com", "h.example.com", true, now)
	if _, v := store.verify(id, "h.example.com", code, now); v != accepted {
		t.Fatal("verify")
	}
	if _, v := store.follow(id, "h.example.com", link, now); v != gone {
		t.Error("the link still worked after the code")
	}

	id, _, link = store.issue("a@example.com", "h.example.com", true, now)
	if _, v := store.follow(id, "h.example.com", link, now.Add(10*time.Minute)); v != gone {
		t.Error("an expired link worked")
	}
}

func TestSessionCookieStaysSmall(t *testing.T) {
	h := newHarness(t)
	rec := httptest.NewRecorder()
	req := &request{host: "admin.example.com", site: h.cfg.Hosts["admin.example.com"]}
	h.srv.writeSession(rec, req, &session{Email: "admin@example.com", Method: "zitadel", Issued: time.Now().Unix(), IDToken: strings.Repeat("x", 5000)})
	cookie := rec.Result().Cookies()[0]
	if len(cookie.String()) > 4096 {
		t.Errorf("cookie of %d bytes", len(cookie.String()))
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookie)
	if sess, ok := h.srv.readSession(r, req); !ok || sess.IDToken != "" || sess.Email != "admin@example.com" {
		t.Errorf("session %+v %v", sess, ok)
	}
}
