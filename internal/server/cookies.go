package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/seal"
)

// __Host- cookies are bound to the exact host, https and path "/" by the browser itself.
const (
	sessionCookie = "__Host-gatekeeper"
	pendingCookie = "__Host-gatekeeper-code"
	flowCookie    = "__Host-gatekeeper-oidc"
	csrfCookie    = "__Host-gatekeeper-csrf"
	ticketCookie  = "__Host-gatekeeper-ticket"
)

type session struct {
	Email   string   `json:"e"`
	Method  string   `json:"m"`
	Issued  int64    `json:"i"`
	Groups  []string `json:"g,omitempty"`
	IDToken string   `json:"t,omitempty"`
}

type pending struct {
	ID      string `json:"i"`
	Expires int64  `json:"x"`
}

type flow struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Lang     string `json:"l"`
	Expires  int64  `json:"x"`
}

func aad(purpose, host string) []byte { return []byte(purpose + "|" + host) }

func (s *Server) open(r *http.Request, name string, box *seal.Box, purpose, host string, v any) bool {
	cookie, err := r.Cookie(name)
	if err != nil {
		return false
	}
	plain, err := box.Open(cookie.Value, aad(purpose, host))
	return err == nil && json.Unmarshal(plain, v) == nil
}

func (s *Server) store(w http.ResponseWriter, name string, box *seal.Box, purpose, host string, v any, maxAge time.Duration, sameSite http.SameSite) {
	plain, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	setCookie(w, name, box.Seal(plain, aad(purpose, host)), maxAge, sameSite)
}

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(maxAge / time.Second), Secure: true, HttpOnly: true, SameSite: sameSite})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// readSession checks the lifetime against the current configuration, so a shorter session there applies at once.
func (s *Server) readSession(r *http.Request, req *request) (*session, bool) {
	var sess session
	if !s.open(r, sessionCookie, s.sessions, "session", req.host, &sess) {
		return nil, false
	}
	issued := time.Unix(sess.Issued, 0)
	if sess.Email == "" || issued.After(s.now().Add(time.Minute)) || !s.now().Before(issued.Add(s.cfg.SessionFor(req.site))) {
		return nil, false
	}
	return &sess, true
}

func (s *Server) writeSession(w http.ResponseWriter, req *request, sess *session) {
	lifetime := s.cfg.SessionFor(req.site)
	plain, _ := json.Marshal(sess)
	if len(plain) > 2800 {
		// A cookie over 4 KB is dropped by the browser; without the token only the provider logout is lost.
		sess.IDToken = ""
	}
	s.store(w, sessionCookie, s.sessions, "session", req.host, sess, lifetime, http.SameSiteLaxMode)
}

// permitted asks the configuration on every request: removing an address or a method locks out at once.
func (s *Server) permitted(req *request, sess *session) bool {
	if !req.site.Offers(sess.Method) {
		return false
	}
	if p, ok := s.providers[sess.Method]; ok && p.cfg.GroupsClaim != "" {
		return config.AllowedGroups(req.site, sess.Groups)
	}
	return s.cfg.Allowed(req.site, sess.Email)
}

func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request, req *request) string {
	value := ""
	if cookie, err := r.Cookie(csrfCookie); err == nil && len(cookie.Value) == 26 {
		value = cookie.Value
	} else {
		value = rand.Text()
		setCookie(w, csrfCookie, value, 24*time.Hour, http.SameSiteStrictMode)
	}
	return s.csrfMAC(req.host, value)
}

func (s *Server) csrfValid(r *http.Request, req *request) bool {
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || len(cookie.Value) != 26 {
		return false
	}
	return hmac.Equal([]byte(r.PostFormValue("csrf")), []byte(s.csrfMAC(req.host, cookie.Value)))
}

func (s *Server) csrfMAC(host, value string) string {
	h := hmac.New(sha256.New, s.csrfKey)
	h.Write([]byte(host + "|" + value))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
