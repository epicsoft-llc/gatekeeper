package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

const flowLifetime = 10 * time.Minute

var errRecentlyFailed = errors.New("discovery failed less than 30 seconds ago")

// provider discovers its issuer on first use, so a provider that is down does not stop the start.
type provider struct {
	cfg        *config.Provider
	client     *http.Client
	mu         sync.Mutex
	oidc       *oidc.Provider
	endSession string
	failed     time.Time
}

func (p *provider) get(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.oidc != nil {
		return p.oidc, nil
	}
	if !p.failed.IsZero() && time.Since(p.failed) < 30*time.Second {
		return nil, errRecentlyFailed
	}
	// Discovery outlives the request that started it: a visitor who goes away must not mark the provider as failed.
	ctx, cancel := context.WithTimeout(oidc.ClientContext(context.WithoutCancel(ctx), p.client), 10*time.Second)
	defer cancel()
	discovered, err := oidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		p.failed = time.Now()
		return nil, err
	}
	var metadata struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := discovered.Claims(&metadata); err == nil {
		p.endSession = metadata.EndSession
	}
	p.oidc = discovered
	return discovered, nil
}

func (p *provider) oauth(discovered *oidc.Provider, host string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint:     discovered.Endpoint(),
		RedirectURL:  "https://" + host + prefix + "/callback/" + p.cfg.ID,
		Scopes:       p.cfg.Scopes,
	}
}

// endSessionURL discovers the provider when needed; an end-session endpoint without https is left alone.
func (p *provider) endSessionURL(ctx context.Context) string {
	if _, err := p.get(ctx); err != nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	u, err := url.Parse(p.endSession)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return p.endSession
}

// logoutOrigin is what form-action must admit on a page with the sign-out button: the browser logout leaves the form
// by a redirect, and the browser checks that redirect against form-action too.
func (p *provider) logoutOrigin(ctx context.Context) string {
	if p.cfg.Logout != "browser" {
		return ""
	}
	u, err := url.Parse(p.endSessionURL(ctx))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (p *provider) logout(ctx context.Context, host, idToken string, log *slog.Logger) string {
	if idToken == "" || p.cfg.Logout == "" {
		return "/"
	}
	endSession := p.endSessionURL(ctx)
	if endSession == "" {
		return "/"
	}
	separator := "?"
	if strings.Contains(endSession, "?") {
		separator = "&"
	}
	switch p.cfg.Logout {
	case "backend":
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endSession+separator+url.Values{"id_token_hint": {idToken}}.Encode(), nil)
		if err == nil {
			client := *p.client
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			var response *http.Response
			if response, err = client.Do(request); err == nil {
				_ = response.Body.Close()
			}
		}
		if err != nil {
			// A *url.Error names the URL, and with it the ID token in its query.
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				err = urlErr.Err
			}
			log.Warn("provider logout failed", "provider", p.cfg.ID, "error", err)
		}
	case "browser":
		return endSession + separator + url.Values{
			"id_token_hint":            {idToken},
			"client_id":                {p.cfg.ClientID},
			"post_logout_redirect_uri": {"https://" + host + "/"},
		}.Encode()
	}
	return "/"
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	p, known := s.providers[r.PathValue("provider")]
	if !ok || !known || !req.site.Offers(p.cfg.ID) {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	rd := safeReturn(query.Get("rd"))
	lang := i18n.Negotiate(query.Get("lang"), r.Header.Get("Accept-Language"), s.cfg.Language)
	discovered, err := p.get(r.Context())
	if err != nil {
		s.log.Error("provider unavailable", "provider", p.cfg.ID, "error", err)
		s.renderError(w, req, http.StatusServiceUnavailable, rd, lang, s.texts.T(lang, "error_provider", "name", p.cfg.Name))
		return
	}
	f := flow{
		Provider: p.cfg.ID,
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		Return:   rd,
		Lang:     lang,
		Expires:  s.now().Add(flowLifetime).Unix(),
	}
	s.store(w, flowCookie, s.flows, "oidc", req.host, f, flowLifetime, http.SameSiteLaxMode)
	s.umami.event(r, req, rd, "gate-"+p.cfg.ID, nil)
	target := p.oauth(discovered, req.host).AuthCodeURL(f.State,
		oauth2.S256ChallengeOption(f.Verifier),
		oidc.Nonce(f.Nonce),
		oauth2.SetAuthURLParam("ui_locales", lang))
	http.Redirect(w, r, target, http.StatusFound)
}

// callback accepts a sign-in only with matching state, nonce and PKCE, a token checked by go-oidc and a verified address.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	p, known := s.providers[r.PathValue("provider")]
	if !ok || !known || !req.site.Offers(p.cfg.ID) {
		http.NotFound(w, r)
		return
	}
	var f flow
	found := s.open(r, flowCookie, s.flows, "oidc", req.host, &f)
	clearCookie(w, flowCookie)
	lang := i18n.Negotiate(f.Lang, r.Header.Get("Accept-Language"), s.cfg.Language)
	rd := safeReturn(f.Return)
	if !found || f.Provider != p.cfg.ID || s.now().Unix() >= f.Expires {
		s.renderError(w, req, http.StatusBadRequest, rd, lang, s.texts.T(lang, "error_signin"))
		return
	}
	s.umami.event(r, req, rd, "gate-"+p.cfg.ID+"-callback", nil)
	query := r.URL.Query()
	if query.Get("error") != "" || !hmac.Equal([]byte(query.Get("state")), []byte(f.State)) || query.Get("code") == "" {
		s.renderError(w, req, http.StatusBadRequest, rd, lang, s.texts.T(lang, "error_signin"))
		return
	}
	id, err := s.exchange(r.Context(), p, req.host, query.Get("code"), &f)
	switch {
	case errors.Is(err, errUnverified):
		s.renderError(w, req, http.StatusForbidden, rd, lang, s.texts.T(lang, "error_unverified", "name", p.cfg.Name))
		return
	case err != nil:
		s.log.Warn("provider sign-in failed", "provider", p.cfg.ID, "host", req.host, "error", err)
		s.renderError(w, req, http.StatusBadGateway, rd, lang, s.texts.T(lang, "error_signin"))
		return
	}
	sess := &session{Email: id.address, Method: p.cfg.ID, Issued: s.now().Unix()}
	if p.cfg.GroupsClaim != "" {
		names := s.cfg.GroupNames()
		for _, group := range id.groups {
			if names[group] && !slices.Contains(sess.Groups, group) {
				sess.Groups = append(sess.Groups, group)
			}
		}
		slices.Sort(sess.Groups)
	}
	if !s.permitted(req, sess) {
		s.log.Info("provider sign-in without access", "provider", p.cfg.ID, "host", req.host, "user", id.address)
		s.renderDenied(w, r, req, nil, id.address, lang)
		return
	}
	if p.cfg.Logout != "" {
		sess.IDToken = id.idToken
	}
	s.writeSession(w, req, sess)
	s.log.Info("signed in", "host", req.host, "method", p.cfg.ID, "user", id.address)
	http.Redirect(w, r, rd, http.StatusSeeOther)
}

var errUnverified = errors.New("the provider has not verified the address")

type identity struct {
	address string
	idToken string
	groups  []string
}

func (s *Server) exchange(ctx context.Context, p *provider, host, code string, f *flow) (*identity, error) {
	discovered, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, p.client), 15*time.Second)
	defer cancel()
	token, err := p.oauth(discovered, host).Exchange(ctx, code, oauth2.VerifierOption(f.Verifier))
	if err != nil {
		return nil, err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("no id_token in the token response")
	}
	idToken, err := discovered.Verifier(&oidc.Config{ClientID: p.cfg.ClientID, Now: s.now}).Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(idToken.Nonce), []byte(f.Nonce)) {
		return nil, errors.New("nonce mismatch")
	}
	claims := map[string]json.RawMessage{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	_, hasGroups := claims[p.cfg.GroupsClaim]
	fromToken := claims["email"] != nil && claims["email_verified"] != nil
	if !fromToken || (p.cfg.GroupsClaim != "" && !hasGroups) {
		info, err := discovered.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, err
		}
		if info.Subject != idToken.Subject {
			return nil, errors.New("userinfo belongs to another subject")
		}
		more := map[string]json.RawMessage{}
		if err := info.Claims(&more); err != nil {
			return nil, err
		}
		// The address and its verification come from one document, so a flag never vouches for another address.
		if !fromToken {
			claims["email"], claims["email_verified"] = more["email"], more["email_verified"]
		}
		for name, value := range more {
			if _, ok := claims[name]; !ok {
				claims[name] = value
			}
		}
	}
	var email string
	if json.Unmarshal(claims["email"], &email) != nil || !truthy(claims["email_verified"]) {
		return nil, errUnverified
	}
	address, ok := config.NormalizeAddress(email)
	if !ok {
		return nil, errors.New("the provider sent no usable address")
	}
	id := &identity{address: address, idToken: raw}
	if p.cfg.GroupsClaim != "" {
		id.groups = groupsOf(claims[p.cfg.GroupsClaim])
	}
	return id, nil
}

func truthy(value json.RawMessage) bool {
	var b bool
	var s string
	return (json.Unmarshal(value, &b) == nil && b) || (json.Unmarshal(value, &s) == nil && s == "true")
}

// groupsOf reads a list of names, a single name, or an object keyed by name like the role claims of Zitadel.
func groupsOf(value json.RawMessage) []string {
	var list []string
	if json.Unmarshal(value, &list) == nil {
		return list
	}
	var single string
	if json.Unmarshal(value, &single) == nil && single != "" {
		return []string{single}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(value, &object) == nil {
		for name := range object {
			list = append(list, name)
		}
	}
	return list
}
