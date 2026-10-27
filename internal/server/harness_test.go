package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/mail"
)

const testConfig = `{
  "secret_file": "SECRET",
  "trusted_proxies": ["127.0.0.1"],
  "default_language": "en",
  "mail": {"host": "mail.example.test", "tls": "none", "from": "gate@example.com", "from_name": "Example"},
  "providers": [
    {"id": "zitadel", "name": "Zitadel", "icon": "zitadel", "issuer": "ISSUER", "client_id": "gatekeeper", "client_secret_file": "CLIENT", "logout": "backend", "groups_claim": "gatekeeper:roles"}
  ],
  "groups": {
    "all": ["admin@example.com"],
    "report.example.com": ["reader@example.org"]
  },
  "hosts": {
    "report.example.com": {"login": ["email", "zitadel"], "allow": ["report.example.com", "all"]},
    "admin.example.com": {"login": ["zitadel"], "allow": ["all"]}
  }UMAMI
}`

type fakeMailer struct {
	mu    sync.Mutex
	codes []mail.Code
	full  bool
}

func (f *fakeMailer) Enqueue(c mail.Code) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.full {
		return false
	}
	f.codes = append(f.codes, c)
	return true
}

func (f *fakeMailer) last(t *testing.T) mail.Code {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.codes) == 0 {
		t.Fatal("no code mail was sent")
	}
	return f.codes[len(f.codes)-1]
}

func (f *fakeMailer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.codes)
}

type harness struct {
	t      *testing.T
	dir    string
	cfg    *config.Config
	srv    *Server
	h      http.Handler
	mailer *fakeMailer
	idp    *fakeIDP
	clock  time.Time
	logs   *safeBuffer
}

type safeBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newHarness(t *testing.T, replace ...string) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), mailer: &fakeMailer{}, clock: time.Now(), logs: &safeBuffer{}}
	h.idp = newFakeIDP(t)
	write(t, h.dir, "secret", strings.Repeat("s", 48))
	write(t, h.dir, "client", "client-secret")
	h.load(replace...)
	return h
}

func (h *harness) load(replace ...string) {
	text := testConfig
	for i := 0; i+1 < len(replace); i += 2 {
		if !strings.Contains(text, replace[i]) {
			h.t.Fatalf("config has no %q", replace[i])
		}
		text = strings.ReplaceAll(text, replace[i], replace[i+1])
	}
	text = strings.ReplaceAll(text, "UMAMI", "")
	text = strings.ReplaceAll(text, `"SECRET"`, quote(filepath.Join(h.dir, "secret")))
	text = strings.ReplaceAll(text, `"CLIENT"`, quote(filepath.Join(h.dir, "client")))
	text = strings.ReplaceAll(text, "ISSUER", h.idp.server.URL)
	cfg, err := config.Load(write(h.t, h.dir, "config.json", text))
	if err != nil {
		h.t.Fatal(err)
	}
	h.cfg = cfg
	h.srv = New(cfg, Options{
		Log:        slog.New(slog.NewTextHandler(h.logs, nil)),
		Mailer:     h.mailer,
		HTTPClient: h.idp.server.Client(),
		Now:        func() time.Time { return h.clock },
	})
	h.h = h.srv.Handler()
}

func (h *harness) log() string { return h.logs.String() }

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func quote(path string) string { return `"` + filepath.ToSlash(path) + `"` }

// browser sends what nginx adds in front of the gatekeeper.
type browser struct {
	h      *harness
	host   string
	ip     string
	jar    *cookiejar.Jar
	header http.Header
}

func (h *harness) browser(host string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{h: h, host: host, ip: "203.0.113.7", jar: jar, header: http.Header{}}
}

type response struct {
	*http.Response
	body string
}

func (b *browser) request(method, target string, form url.Values, original string) *response {
	b.h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = "127.0.0.1:40000"
	req.Host = b.host
	req.Header.Set("X-Forwarded-Host", b.host)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-Ip", b.ip)
	req.Header.Set("Sec-Fetch-Dest", "document")
	if original != "" {
		req.Header.Set("X-Forwarded-Uri", original)
	} else {
		req.Header.Set("X-Forwarded-Uri", target)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://"+b.host)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for name, values := range b.header {
		req.Header[name] = values
	}
	site := &url.URL{Scheme: "https", Host: b.host, Path: "/"}
	for _, c := range b.jar.Cookies(site) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.h.h.ServeHTTP(rec, req)
	result := rec.Result()
	b.jar.SetCookies(site, result.Cookies())
	data, _ := io.ReadAll(result.Body)
	return &response{Response: result, body: string(data)}
}

func (b *browser) get(target string) *response { return b.request(http.MethodGet, target, nil, "") }

// at asks for a protected address and follows nginx: auth_request, then error_page to the gatekeeper.
func (b *browser) at(uri string) *response {
	b.h.t.Helper()
	auth := b.request(http.MethodGet, prefix+"/auth", nil, uri)
	switch auth.StatusCode {
	case http.StatusUnauthorized:
		return b.request(http.MethodGet, prefix+"/sign_in", nil, uri)
	case http.StatusForbidden:
		return b.request(http.MethodGet, prefix+"/denied", nil, uri)
	}
	return auth
}

func (b *browser) post(target string, form url.Values) *response {
	return b.request(http.MethodPost, target, form, "")
}

func csrfOf(t *testing.T, page string) string {
	t.Helper()
	const marker = `name="csrf" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no csrf field in %s", page)
	}
	rest := page[i+len(marker):]
	return rest[:strings.IndexByte(rest, '"')]
}

func (r *response) location(t *testing.T) *url.URL {
	t.Helper()
	if r.StatusCode < 300 || r.StatusCode > 399 {
		t.Fatalf("status %d, want a redirect; body %s", r.StatusCode, r.body)
	}
	u, err := url.Parse(r.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (r *response) expect(t *testing.T, status int, contains ...string) {
	t.Helper()
	if r.StatusCode != status {
		t.Fatalf("status %d, want %d; body %s", r.StatusCode, status, r.body)
	}
	for _, want := range contains {
		if !strings.Contains(r.body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
}

// signOut answers the page with its button, as a person would.
func (b *browser) signOut() *response {
	b.h.t.Helper()
	page := b.get(prefix + "/sign_out")
	return b.post(prefix+"/sign_out", url.Values{"csrf": {csrfOf(b.h.t, page.body)}, "lang": {"en"}})
}

func (b *browser) signInByEmail(address, rd string) *response {
	b.h.t.Helper()
	page := b.request(http.MethodGet, prefix+"/sign_in", nil, rd)
	sent := b.post(prefix+"/email", url.Values{"csrf": {csrfOf(b.h.t, page.body)}, "rd": {rd}, "lang": {"en"}, "email": {address}})
	codePage := b.get(sent.location(b.h.t).String())
	return b.post(prefix+"/code", url.Values{"csrf": {csrfOf(b.h.t, codePage.body)}, "rd": {rd}, "lang": {"en"}, "code": {b.h.mailer.last(b.h.t).Code}})
}

type fakeIDP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	grants   map[string]grant
	logouts  []string
	tamper   func(claims map[string]any)
	userinfo map[string]any
	last     map[string]any
}

type grant struct {
	nonce, challenge, redirect string
	claims                     map[string]any
}

func newFakeIDP(t *testing.T) *fakeIDP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{key: key, grants: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := idp.server.URL
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
			"jwks_uri": base + "/keys", "userinfo_endpoint": base + "/userinfo", "end_session_endpoint": base + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", idp.token)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		info := idp.userinfo
		if info == nil {
			info = idp.last
		}
		if r.Header.Get("Authorization") != "Bearer access-token" || info == nil {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(info)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		idp.logouts = append(idp.logouts, r.URL.Query().Get("id_token_hint"))
		idp.mu.Unlock()
		http.Redirect(w, r, "/logged-out", http.StatusFound)
	})
	idp.server = httptest.NewTLSServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *fakeIDP) authorize(t *testing.T, location *url.URL, claims map[string]any) (code, state string) {
	t.Helper()
	q := location.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("client_id") != "gatekeeper" {
		t.Fatalf("authorization request %s", location)
	}
	code = rand.Text()
	idp.mu.Lock()
	idp.grants[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), claims: claims}
	idp.mu.Unlock()
	return code, q.Get("state")
}

func (idp *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	idp.mu.Lock()
	g, ok := idp.grants[r.PostForm.Get("code")]
	delete(idp.grants, r.PostForm.Get("code"))
	tamper := idp.tamper
	idp.mu.Unlock()
	user, password, basic := r.BasicAuth()
	if !basic {
		user, password = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || user != "gatekeeper" || password != "client-secret" || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || r.PostForm.Get("redirect_uri") != g.redirect {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	claims := map[string]any{
		"iss": idp.server.URL, "sub": "user-1", "aud": "gatekeeper", "nonce": g.nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	for name, value := range g.claims {
		claims[name] = value
	}
	if tamper != nil {
		tamper(claims)
	}
	idp.mu.Lock()
	idp.last = claims
	idp.mu.Unlock()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: idp.key, KeyID: "test", Algorithm: "RS256"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	raw, _ := signed.CompactSerialize()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
}

func (idp *fakeIDP) logoutHints() []string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return append([]string(nil), idp.logouts...)
}
