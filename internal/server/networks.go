package server

import (
	"net/http"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

// blocked is a known client address in ip_deny.
func (s *Server) blocked(req *request) bool {
	return req.addr.IsValid() && s.cfg.DeniedIP(req.site, req.addr)
}

// admitted is a known client address in ip_allow, which config.AllowedIP never grants to one in ip_deny.
func (s *Server) admitted(req *request) bool {
	return req.addr.IsValid() && s.cfg.AllowedIP(req.site, req.addr)
}

// refuseDenied keeps a client of ip_deny out of every path: no sign-in page, no code mail, whatever its session.
func (s *Server) refuseDenied(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, ok := s.resolve(r)
		switch {
		case !ok || !s.blocked(req):
			next.ServeHTTP(w, r)
		case r.URL.Path == prefix+"/auth":
			w.WriteHeader(http.StatusForbidden)
		default:
			s.renderBlocked(w, r, req)
		}
	})
}

func (s *Server) renderBlocked(w http.ResponseWriter, r *http.Request, req *request) {
	rest, chosen := splitLang(originalURI(r, req))
	lang := i18n.Negotiate(chosen, r.Header.Get("Accept-Language"), s.cfg.Language)
	v := s.view(req, lang, "denied_title", "denied_heading", func(code string) string { return withLang(safeReturn(rest), code) })
	v.Lead = s.texts.T(lang, "denied_network")
	s.render(w, http.StatusForbidden, "message", v)
}
