package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/limit"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/mail"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/seal"
)

// All pages and endpoints live under this path on the protected host itself.
const prefix = "/_gatekeeper"

type Mailer interface {
	Enqueue(mail.Code) bool
}

type Options struct {
	Log        *slog.Logger
	Mailer     Mailer
	HTTPClient *http.Client
	Now        func() time.Time
}

type Server struct {
	cfg       *config.Config
	texts     *i18n.Catalog
	look      *look
	log       *slog.Logger
	now       func() time.Time
	mailer    Mailer
	client    *http.Client
	sessions  *seal.Box
	pendings  *seal.Box
	flows     *seal.Box
	csrfKey   []byte
	codes     *codeStore
	requests  *limit.Limiter
	networks  *limit.Limiter
	addresses *limit.Limiter
	total     *limit.Limiter
	domains   *limit.Limiter
	attempts  *limit.Limiter
	providers map[string]*provider
	umami     *umami
	altcha    *altcha
	ticketBox *seal.Box
	tickets   *ticketStore
	checks    *limit.Limiter
	origins   *http.CrossOriginProtection
}

func New(cfg *config.Config, opts Options) *Server {
	s := &Server{
		cfg:       cfg,
		texts:     cfg.Branding.Texts,
		look:      newLook(&cfg.Branding),
		log:       opts.Log,
		now:       opts.Now,
		mailer:    opts.Mailer,
		client:    opts.HTTPClient,
		sessions:  seal.New(cfg.Secret, "session"),
		pendings:  seal.New(cfg.Secret, "pending"),
		flows:     seal.New(cfg.Secret, "oidc"),
		csrfKey:   seal.Key(cfg.Secret, "csrf"),
		providers: map[string]*provider{},
		origins:   http.NewCrossOriginProtection(),
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 10 * time.Second}
	}
	if m := cfg.Mail; m != nil {
		s.codes = newCodeStore(seal.Key(cfg.Secret, "code"), m.CodeTTL.D(), m.CodeAttempts, 10_000)
		s.requests = limit.New(m.Limits.PerClient.Count, m.Limits.PerClient.Window.D(), 50_000)
		// A whole IPv6 /48 gets sixteen clients' worth: enough for a site, too little to flood the stores from one.
		s.networks = limit.New(16*m.Limits.PerClient.Count, m.Limits.PerClient.Window.D(), 50_000)
		s.addresses = limit.New(m.Limits.PerAddress.Count, m.Limits.PerAddress.Window.D(), 50_000)
		s.total = limit.New(m.Limits.Total.Count, m.Limits.Total.Window.D(), 1)
		// Addresses that get in only through a domain entry - anyone can name them - use at most half of total.
		s.domains = limit.New(max(1, m.Limits.Total.Count/2), m.Limits.Total.Window.D(), 1)
		s.attempts = limit.New(m.Limits.Attempts.Count, m.Limits.Attempts.Window.D(), 50_000)
	}
	for i := range cfg.Providers {
		p := &cfg.Providers[i]
		s.providers[p.ID] = &provider{cfg: p, client: s.client}
	}
	if cfg.Umami != nil {
		s.umami = newUmami(cfg.Umami, s.client, s.log)
	}
	if cfg.Altcha != nil && cfg.Mail != nil {
		s.altcha = newAltcha(cfg.Altcha, s.client)
		s.ticketBox = seal.New(cfg.Secret, "ticket")
		s.tickets = newTicketStore(50_000)
		s.checks = limit.New(cfg.Mail.Limits.PerClient.Count, cfg.Mail.Limits.PerClient.Window.D(), 50_000)
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/auth", s.auth)
	mux.HandleFunc(prefix+"/forward_auth", s.forwardAuth)
	mux.HandleFunc("GET "+prefix+"/sign_in", s.signIn)
	mux.HandleFunc("GET "+prefix+"/denied", s.denied)
	mux.Handle("POST "+prefix+"/altcha", s.origins.Handler(http.HandlerFunc(s.altchaCheck)))
	mux.Handle("POST "+prefix+"/email", s.origins.Handler(http.HandlerFunc(s.email)))
	mux.HandleFunc("GET "+prefix+"/code", s.codeForm)
	mux.Handle("POST "+prefix+"/code", s.origins.Handler(http.HandlerFunc(s.code)))
	mux.HandleFunc("GET "+prefix+"/start/{provider}", s.start)
	mux.HandleFunc("GET "+prefix+"/callback/{provider}", s.callback)
	mux.HandleFunc("GET "+prefix+"/sign_out", s.signOutPage)
	mux.Handle("POST "+prefix+"/sign_out", s.origins.Handler(http.HandlerFunc(s.signOut)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return securityHeaders(http.MaxBytesHandler(mux, 16<<10))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Janitor(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := s.now()
			if s.codes != nil {
				s.codes.sweep(now)
				for _, l := range []*limit.Limiter{s.requests, s.networks, s.addresses, s.total, s.domains, s.attempts} {
					l.Sweep(now)
				}
			}
			if s.altcha != nil {
				s.tickets.sweep(now)
				s.checks.Sweep(now)
			}
		}
	}
}
