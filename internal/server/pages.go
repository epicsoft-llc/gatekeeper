package server

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
	texttemplate "text/template"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/brand"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

//go:embed templates
var templateFiles embed.FS

var (
	// The colours come from the configuration, which checked them as #rrggbb.
	styleTemplate = texttemplate.Must(texttemplate.ParseFS(templateFiles, "templates/style.css"))
	pages         = map[string]*template.Template{}
)

func init() {
	base := template.Must(template.ParseFS(templateFiles, "templates/layout.html"))
	for _, name := range []string{"sign_in", "code", "message"} {
		pages[name] = template.Must(template.Must(base.Clone()).ParseFS(templateFiles, "templates/"+name+".html"))
	}
}

// look is the branding as every page needs it, prepared once.
type look struct {
	css      template.CSS
	cssHash  string
	csp      string
	favicon  template.URL
	mark     template.HTML
	backdrop template.HTML
}

// newLook inlines the mark as it came out of brand.ParseMark: written anew from the allowlist, with ids of its own per copy.
// Only a mark of the configuration lies behind the page as well; the neutral look stays plain.
func newLook(b *config.Branding) *look {
	var css bytes.Buffer
	if err := styleTemplate.Execute(&css, b.Palette); err != nil {
		panic(err)
	}
	hash := hashOf(css.String())
	l := &look{
		css:     template.CSS(css.String()),
		cssHash: hash,
		// The only style on the pages is the one <style> element; its hash keeps 'unsafe-inline' out of the CSP.
		csp:     "default-src 'none'; style-src 'sha256-" + hash + "'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
		favicon: template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.Mark.Document()))),
		mark:    template.HTML(b.Mark.Inline("mark", "gatekeeper-mark-")),
	}
	if b.Mark != brand.Default {
		l.backdrop = template.HTML(b.Mark.Inline("backdrop", "gatekeeper-backdrop-"))
	}
	return l
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

type view struct {
	Lang           string
	Title          string
	CSS            template.CSS
	Favicon        template.URL
	Mark           template.HTML
	Backdrop       template.HTML
	Brand          string
	Owner          string
	OwnerURL       string
	Eyebrow        string
	Heading        string
	Host           string
	Lead           string
	Error          string
	Hint           string
	LanguagesLabel string
	Languages      []languageLink
	Script         *script
	AltchaForm     *altchaForm
	EmailForm      *emailForm
	Or             string
	Providers      []providerLink
	CodeForm       *codeForm
	SignOut        *signOutForm
	Actions        []action
}

type languageLink struct {
	Code, Name, Href string
	Current          bool
}

// script is the widget of the ALTCHA service; its nonce goes to the <style> the widget adds.
type script struct {
	Src, Nonce string
}

type altchaForm struct {
	Action, CSRF, Return, Lang, Challenge, NoScript, Button string
}

type emailForm struct {
	Action, CSRF, Return, Lang, Label, Button string
}

type codeForm struct {
	Action, CSRF, Return, Lang, Label, Button, Again, AgainHref string
}

type signOutForm struct {
	Action, CSRF, Lang, Button string
	// Origin of the end-session endpoint for a browser logout, for form-action.
	Origin string
}

type providerLink struct {
	Href, Label, Icon string
	Primary           bool
}

type action struct {
	Href, Label string
	Primary     bool
}

// view links the languages to here(lang), which keeps the visitor on the same step.
func (s *Server) view(req *request, lang, title, heading string, here func(string) string) *view {
	b := &s.cfg.Branding
	v := &view{
		Lang:           lang,
		Title:          s.texts.T(lang, title, "name", b.Name),
		CSS:            s.look.css,
		Favicon:        s.look.favicon,
		Mark:           s.look.mark,
		Backdrop:       s.look.backdrop,
		Brand:          b.Name,
		Owner:          b.Owner,
		OwnerURL:       b.URL,
		Eyebrow:        s.texts.T(lang, "eyebrow"),
		Heading:        s.texts.T(lang, heading),
		Host:           req.host,
		LanguagesLabel: s.texts.T(lang, "languages"),
	}
	for _, code := range i18n.Languages {
		v.Languages = append(v.Languages, languageLink{Code: code, Name: s.texts.T(code, "name"), Href: here(code), Current: code == lang})
	}
	return v
}

func (s *Server) render(w http.ResponseWriter, status int, name string, v *view) {
	var body bytes.Buffer
	if err := pages[name].ExecuteTemplate(&body, "layout", v); err != nil {
		s.log.Error("page failed", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Language", v.Lang)
	switch {
	case v.Script != nil:
		h.Set("Content-Security-Policy", s.altchaPolicy(v.Script))
	case v.SignOut != nil && v.SignOut.Origin != "":
		h.Set("Content-Security-Policy", strings.Replace(s.look.csp, "form-action 'self'", "form-action 'self' "+v.SignOut.Origin, 1))
	default:
		h.Set("Content-Security-Policy", s.look.csp)
	}
	h.Set("X-Frame-Options", "DENY")
	h.Set("Vary", "Accept-Language, Cookie")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}
