package server

import (
	"crypto/rand"
	"net/http"
	"net/url"
	"slices"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/mail"
)

var errorKeys = []string{"address", "code", "expired", "limit", "form", "link"}

// auth answers nginx auth_request: only the status counts, nginx shows the page through error_page.
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sess, ok := s.readSession(r, req)
	switch {
	case !ok:
		w.WriteHeader(http.StatusUnauthorized)
	case !s.permitted(req, sess):
		w.WriteHeader(http.StatusForbidden)
	default:
		w.Header().Set("X-Gatekeeper-User", sess.Email)
		w.WriteHeader(http.StatusAccepted)
	}
}

// forwardAuth answers Traefik forwardAuth, which passes the whole answer on - so it carries the page itself.
func (s *Server) forwardAuth(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok {
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}
	sess, ok := s.readSession(r, req)
	switch {
	case !ok:
		s.signInAtOrigin(w, r, req)
	case !s.permitted(req, sess):
		s.renderDenied(w, r, req, sess, sess.Email, i18n.Negotiate("", r.Header.Get("Accept-Language"), s.cfg.Language))
	default:
		w.Header().Set("X-Gatekeeper-User", sess.Email)
		w.WriteHeader(http.StatusOK)
	}
}

// signIn is reached in two ways: nginx error_page shows it at the protected address, or the browser asks for it directly.
func (s *Server) signIn(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !isGatekeeperPath(originalURI(r, req)) {
		s.signInAtOrigin(w, r, req)
		return
	}
	query := r.URL.Query()
	rd := safeReturn(query.Get("rd"))
	lang := i18n.Negotiate(query.Get("lang"), r.Header.Get("Accept-Language"), s.cfg.Language)
	if sess, ok := s.readSession(r, req); ok && s.permitted(req, sess) {
		http.Redirect(w, r, rd, http.StatusSeeOther)
		return
	}
	errorKey := query.Get("e")
	if !slices.Contains(errorKeys, errorKey) {
		errorKey = ""
	}
	s.umami.page(r, req, rd, query.Get("lang"))
	s.renderSignIn(w, r, req, http.StatusUnauthorized, rd, lang, errorKey, func(code string) string {
		return gatekeeperURL("/sign_in", rd, code)
	})
}

func (s *Server) signInAtOrigin(w http.ResponseWriter, r *http.Request, req *request) {
	rest, chosen := splitLang(originalURI(r, req))
	rd := safeReturn(rest)
	lang := i18n.Negotiate(chosen, r.Header.Get("Accept-Language"), s.cfg.Language)
	s.umami.page(r, req, rd, chosen)
	s.renderSignIn(w, r, req, http.StatusUnauthorized, rd, lang, "", func(code string) string {
		return withLang(rd, code)
	})
}

func (s *Server) renderSignIn(w http.ResponseWriter, r *http.Request, req *request, status int, rd, lang, errorKey string, here func(string) string) {
	v := s.view(req, lang, "signin_title", "signin_heading", here)
	v.Lead = s.texts.T(lang, "signin_lead")
	if errorKey != "" {
		v.Error = s.texts.T(lang, "error_"+errorKey)
	}
	email := req.site.Offers(config.EmailMethod)
	switch {
	case email && s.altcha != nil && !s.hasTicket(r, req):
		v.Script = &script{Src: s.cfg.Altcha.URL + "/widget.i18n.js", Nonce: rand.Text()}
		if lang == "en" {
			v.Script.Src = s.cfg.Altcha.URL + "/widget.js"
		}
		v.AltchaForm = &altchaForm{
			Action:    prefix + "/altcha",
			CSRF:      s.csrfToken(w, r, req),
			Return:    rd,
			Lang:      lang,
			Challenge: s.cfg.Altcha.URL + "/challenge",
			NoScript:  s.texts.T(lang, "altcha_noscript"),
			Button:    s.texts.T(lang, "email_button"),
		}
	case email:
		v.EmailForm = &emailForm{
			Action: prefix + "/email",
			CSRF:   s.csrfToken(w, r, req),
			Return: rd,
			Lang:   lang,
			Label:  s.texts.T(lang, "email_label"),
			Button: s.texts.T(lang, "email_button"),
		}
	}
	if email {
		v.Hint = s.texts.T(lang, "signin_hint")
	}
	for _, method := range req.site.Login {
		if p, ok := s.providers[method]; ok {
			v.Providers = append(v.Providers, providerLink{
				Href:    gatekeeperURL("/start/"+p.cfg.ID, rd, lang),
				Label:   s.texts.T(lang, "provider_button", "name", p.cfg.Name),
				Icon:    p.cfg.Icon,
				Primary: !email && len(v.Providers) == 0,
			})
		}
	}
	if email && len(v.Providers) > 0 {
		v.Or = s.texts.T(lang, "or")
	}
	s.render(w, status, "sign_in", v)
}

// denied is the page behind nginx error_page 403.
func (s *Server) denied(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, chosen := splitLang(originalURI(r, req))
	lang := i18n.Negotiate(chosen, r.Header.Get("Accept-Language"), s.cfg.Language)
	sess, ok := s.readSession(r, req)
	if !ok {
		s.signInAtOrigin(w, r, req)
		return
	}
	s.renderDenied(w, r, req, sess, sess.Email, lang)
}

// renderDenied takes the session of a visitor signed in without access, nil for a provider sign-in that was refused.
func (s *Server) renderDenied(w http.ResponseWriter, r *http.Request, req *request, sess *session, user, lang string) {
	rest, _ := splitLang(originalURI(r, req))
	v := s.view(req, lang, "denied_title", "denied_heading", func(code string) string { return withLang(safeReturn(rest), code) })
	if sess != nil {
		v.Lead = s.texts.T(lang, "denied_lead", "user", user)
		v.SignOut = s.signOutForm(w, r, req, lang, sess)
	} else {
		v.Lead = s.texts.T(lang, "denied_account", "user", user)
		v.Actions = []action{{Href: gatekeeperURL("/sign_in", "/", lang), Label: s.texts.T(lang, "other_account"), Primary: true}}
	}
	s.render(w, http.StatusForbidden, "message", v)
}

func (s *Server) renderError(w http.ResponseWriter, req *request, status int, rd, lang, message string) {
	v := s.view(req, lang, "error_title", "error_heading", func(code string) string { return gatekeeperURL("/sign_in", rd, code) })
	v.Lead = message
	v.Actions = []action{{Href: gatekeeperURL("/sign_in", rd, lang), Label: s.texts.T(lang, "back"), Primary: true}}
	s.render(w, status, "message", v)
}

// email treats an address without access exactly like one with access - only no mail goes out.
func (s *Server) email(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok || !req.site.Offers(config.EmailMethod) || s.codes == nil {
		http.NotFound(w, r)
		return
	}
	rd := safeReturn(r.PostFormValue("rd"))
	lang := i18n.Negotiate(r.PostFormValue("lang"), r.Header.Get("Accept-Language"), s.cfg.Language)
	here := func(code string) string { return gatekeeperURL("/sign_in", rd, code) }
	if !s.csrfValid(r, req) {
		s.renderSignIn(w, r, req, http.StatusForbidden, rd, lang, "form", here)
		return
	}
	var t *ticket
	if s.altcha != nil {
		if t, ok = s.readTicket(r, req); !ok {
			s.renderSignIn(w, r, req, http.StatusForbidden, rd, lang, "form", here)
			return
		}
	}
	now := s.now()
	if !s.requests.Allow(req.client, now) || !s.networks.Allow(req.network, now) {
		s.log.Warn("rate limit", "limit", "per_client", "host", req.host)
		s.renderSignIn(w, r, req, http.StatusTooManyRequests, rd, lang, "limit", here)
		return
	}
	address, ok := config.NormalizeAddress(r.PostFormValue("email"))
	if !ok {
		s.renderSignIn(w, r, req, http.StatusBadRequest, rd, lang, "address", here)
		return
	}
	if !s.addresses.Allow(address, now) {
		s.log.Warn("rate limit", "limit", "per_address", "host", req.host)
		s.renderSignIn(w, r, req, http.StatusTooManyRequests, rd, lang, "limit", here)
		return
	}
	if t != nil {
		if !s.tickets.spend(t.ID, time.Unix(t.Expires, 0), now) {
			s.renderSignIn(w, r, req, http.StatusForbidden, rd, lang, "form", here)
			return
		}
		clearCookie(w, ticketCookie)
	}
	allowed := s.cfg.Allowed(req.site, address)
	id, code, link := s.codes.issue(address, req.host, allowed, now)
	mailed := mail.Code{To: address, Host: req.host, Lang: lang, Code: code, TTL: s.cfg.Mail.CodeTTL.D()}
	// Lax with the link: a click in webmail comes from another site and would arrive without a strict cookie.
	sameSite := http.SameSiteStrictMode
	if s.cfg.Mail.Link {
		mailed.Link = "https://" + req.host + gatekeeperURL("/code", rd, lang, "t", link)
		sameSite = http.SameSiteLaxMode
	}
	switch {
	case !allowed:
		s.log.Info("code requested for an address without access", "host", req.host)
	case !s.cfg.Listed(req.site, address) && !s.domains.Allow("domains", now):
		s.log.Warn("rate limit", "limit", "domains", "host", req.host, "user", address)
	case !s.total.Allow("all", now):
		s.log.Warn("rate limit", "limit", "total", "host", req.host, "user", address)
	case !s.mailer.Enqueue(mailed):
		s.log.Error("mail queue full", "host", req.host, "user", address)
	default:
		s.log.Info("code requested", "host", req.host, "user", address)
	}
	s.store(w, pendingCookie, s.pendings, "pending", req.host, pending{ID: id, Expires: now.Add(s.cfg.Mail.CodeTTL.D()).Unix()}, s.cfg.Mail.CodeTTL.D(), sameSite)
	s.umami.event(r, req, rd, "gate-email", nil)
	http.Redirect(w, r, gatekeeperURL("/code", rd, lang), http.StatusSeeOther)
}

func (s *Server) readPending(r *http.Request, req *request) (*pending, bool) {
	var p pending
	if !s.open(r, pendingCookie, s.pendings, "pending", req.host, &p) || s.now().Unix() >= p.Expires {
		return nil, false
	}
	return &p, true
}

func (s *Server) codeForm(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok || !req.site.Offers(config.EmailMethod) || s.codes == nil {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	rd := safeReturn(query.Get("rd"))
	lang := i18n.Negotiate(query.Get("lang"), r.Header.Get("Accept-Language"), s.cfg.Language)
	if token := query.Get("t"); token != "" && s.cfg.Mail.Link {
		s.follow(w, r, req, rd, lang, token)
		return
	}
	if _, ok := s.readPending(r, req); !ok {
		http.Redirect(w, r, gatekeeperURL("/sign_in", rd, lang, "e", "expired"), http.StatusSeeOther)
		return
	}
	errorKey := query.Get("e")
	if errorKey != "code" && errorKey != "limit" && errorKey != "form" && errorKey != "link" {
		errorKey = ""
	}
	s.renderCode(w, r, req, http.StatusOK, rd, lang, errorKey)
}

// follow signs in by the link of the code mail - only the browser that holds the pending cookie of that code.
func (s *Server) follow(w http.ResponseWriter, r *http.Request, req *request, rd, lang, token string) {
	p, ok := s.readPending(r, req)
	if !ok {
		http.Redirect(w, r, gatekeeperURL("/sign_in", rd, lang, "e", "link"), http.StatusSeeOther)
		return
	}
	now := s.now()
	address, result := s.codes.follow(p.ID, req.host, token, now)
	switch {
	case result == accepted && s.cfg.Allowed(req.site, address):
		clearCookie(w, pendingCookie)
		s.writeSession(w, req, &session{Email: address, Method: config.EmailMethod, Issued: now.Unix()})
		s.log.Info("signed in", "host", req.host, "method", config.EmailMethod, "user", address, "by", "link")
		s.umami.event(r, req, rd, "gate-email-callback", nil)
		http.Redirect(w, r, rd, http.StatusSeeOther)
	case result == wrong:
		http.Redirect(w, r, gatekeeperURL("/code", rd, lang, "e", "link"), http.StatusSeeOther)
	default:
		clearCookie(w, pendingCookie)
		http.Redirect(w, r, gatekeeperURL("/sign_in", rd, lang, "e", "expired"), http.StatusSeeOther)
	}
}

func (s *Server) renderCode(w http.ResponseWriter, r *http.Request, req *request, status int, rd, lang, errorKey string) {
	v := s.view(req, lang, "code_title", "code_heading", func(code string) string { return gatekeeperURL("/code", rd, code) })
	v.Lead = s.texts.T(lang, "code_lead", "minutes", i18n.Minutes(lang, int(s.cfg.Mail.CodeTTL.D()/time.Minute)))
	if errorKey != "" {
		v.Error = s.texts.T(lang, "error_"+errorKey)
	}
	v.CodeForm = &codeForm{
		Action:    prefix + "/code",
		CSRF:      s.csrfToken(w, r, req),
		Return:    rd,
		Lang:      lang,
		Label:     s.texts.T(lang, "code_label"),
		Button:    s.texts.T(lang, "code_button"),
		Again:     s.texts.T(lang, "code_again"),
		AgainHref: gatekeeperURL("/sign_in", rd, lang),
	}
	v.Hint = s.texts.T(lang, "code_hint")
	s.render(w, status, "code", v)
}

func (s *Server) code(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok || !req.site.Offers(config.EmailMethod) || s.codes == nil {
		http.NotFound(w, r)
		return
	}
	rd := safeReturn(r.PostFormValue("rd"))
	lang := i18n.Negotiate(r.PostFormValue("lang"), r.Header.Get("Accept-Language"), s.cfg.Language)
	if !s.csrfValid(r, req) {
		http.Redirect(w, r, gatekeeperURL("/code", rd, lang, "e", "form"), http.StatusSeeOther)
		return
	}
	now := s.now()
	if !s.attempts.Allow(req.client, now) {
		s.log.Warn("rate limit", "limit", "attempts", "host", req.host)
		http.Redirect(w, r, gatekeeperURL("/code", rd, lang, "e", "limit"), http.StatusSeeOther)
		return
	}
	p, ok := s.readPending(r, req)
	if !ok {
		http.Redirect(w, r, gatekeeperURL("/sign_in", rd, lang, "e", "expired"), http.StatusSeeOther)
		return
	}
	address, result := s.codes.verify(p.ID, req.host, r.PostFormValue("code"), now)
	switch {
	case result == accepted && s.cfg.Allowed(req.site, address):
		clearCookie(w, pendingCookie)
		s.writeSession(w, req, &session{Email: address, Method: config.EmailMethod, Issued: now.Unix()})
		s.log.Info("signed in", "host", req.host, "method", config.EmailMethod, "user", address)
		s.umami.event(r, req, rd, "gate-email-callback", nil)
		http.Redirect(w, r, rd, http.StatusSeeOther)
	case result == wrong:
		http.Redirect(w, r, gatekeeperURL("/code", rd, lang, "e", "code"), http.StatusSeeOther)
	default:
		if address != "" {
			s.log.Warn("code attempts used up", "host", req.host, "user", address)
		}
		clearCookie(w, pendingCookie)
		http.Redirect(w, r, gatekeeperURL("/sign_in", rd, lang, "e", "expired"), http.StatusSeeOther)
	}
}

func (s *Server) signOutForm(w http.ResponseWriter, r *http.Request, req *request, lang string, sess *session) *signOutForm {
	f := &signOutForm{Action: prefix + "/sign_out", CSRF: s.csrfToken(w, r, req), Lang: lang, Button: s.texts.T(lang, "sign_out")}
	if p, ok := s.providers[sess.Method]; ok {
		f.Origin = p.logoutOrigin(r.Context())
	}
	return f
}

// signOutPage only asks: a sign-out by GET could be set off by any foreign page.
func (s *Server) signOutPage(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	lang := i18n.Negotiate(r.URL.Query().Get("lang"), r.Header.Get("Accept-Language"), s.cfg.Language)
	sess, signedIn := s.readSession(r, req)
	if !signedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderSignOut(w, r, req, http.StatusOK, sess, lang, "")
}

func (s *Server) renderSignOut(w http.ResponseWriter, r *http.Request, req *request, status int, sess *session, lang, errorKey string) {
	v := s.view(req, lang, "signout_title", "signout_heading", func(code string) string { return prefix + "/sign_out?" + url.Values{"lang": {code}}.Encode() })
	v.Lead = s.texts.T(lang, "signout_lead", "user", sess.Email)
	if errorKey != "" {
		v.Error = s.texts.T(lang, "error_"+errorKey)
	}
	v.SignOut = s.signOutForm(w, r, req, lang, sess)
	s.render(w, status, "message", v)
}

func (s *Server) signOut(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	lang := i18n.Negotiate(r.PostFormValue("lang"), r.Header.Get("Accept-Language"), s.cfg.Language)
	sess, signedIn := s.readSession(r, req)
	if signedIn && !s.csrfValid(r, req) {
		s.renderSignOut(w, r, req, http.StatusForbidden, sess, lang, "form")
		return
	}
	for _, name := range []string{sessionCookie, pendingCookie, flowCookie} {
		clearCookie(w, name)
	}
	target := "/"
	if signedIn {
		s.log.Info("signed out", "host", req.host, "user", sess.Email)
		if p, ok := s.providers[sess.Method]; ok {
			target = p.logout(r.Context(), req.host, sess.IDToken, s.log)
		}
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
