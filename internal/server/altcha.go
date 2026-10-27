package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

// A solved challenge opens the address field for this long, once.
const ticketLifetime = 10 * time.Minute

// The widget sends base64 of JSON; the ALTCHA service takes at most 8192 characters.
const maxSolution = 8192

var solutionPattern = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

var errRefused = errors.New("the ALTCHA service refused the solution")

type ticket struct {
	ID      string `json:"i"`
	Client  string `json:"c"`
	Expires int64  `json:"x"`
}

// altcha asks the ALTCHA service server to server. The service spends a solution, so it counts once.
type altcha struct {
	cfg    *config.Altcha
	client *http.Client
}

func newAltcha(cfg *config.Altcha, client *http.Client) *altcha {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &altcha{cfg: cfg, client: &c}
}

// verify returns the reason of a refusal; any other answer is an error, and either way no address field opens.
func (a *altcha) verify(ctx context.Context, solution string) (string, error) {
	body, err := json.Marshal(map[string]string{"altcha": solution, "site": a.cfg.Site})
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.URL+"/verify", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var answer struct {
		OK       bool   `json:"ok"`
		Verified bool   `json:"verified"`
		Site     string `json:"site"`
		Error    string `json:"error"`
	}
	decoded := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&answer) == nil
	switch {
	case decoded && response.StatusCode == http.StatusOK && answer.OK && answer.Verified && answer.Site == a.cfg.Site:
		return "", nil
	case decoded && response.StatusCode == http.StatusForbidden && !answer.OK:
		return answer.Error, errRefused
	}
	return "", fmt.Errorf("the ALTCHA service answered %d %q", response.StatusCode, answer.Error)
}

// ticketStore keeps the spent tickets until they expire, so a copied cookie opens the address field only once.
type ticketStore struct {
	mu       sync.Mutex
	spent    map[string]time.Time
	maxItems int
}

func newTicketStore(maxItems int) *ticketStore {
	return &ticketStore{spent: map[string]time.Time{}, maxItems: maxItems}
}

func (t *ticketStore) used(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, used := t.spent[id]
	return used
}

// spend refuses a ticket spent before - and any ticket while the store is full of unexpired ones.
func (t *ticketStore) spend(id string, expires, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, used := t.spent[id]; used {
		return false
	}
	if len(t.spent) >= t.maxItems {
		t.sweepLocked(now)
		if len(t.spent) >= t.maxItems {
			return false
		}
	}
	t.spent[id] = expires
	return true
}

func (t *ticketStore) sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
}

func (t *ticketStore) sweepLocked(now time.Time) {
	for id, expires := range t.spent {
		if !now.Before(expires) {
			delete(t.spent, id)
		}
	}
}

// readTicket accepts only a ticket of this host and client that is neither expired nor spent.
func (s *Server) readTicket(r *http.Request, req *request) (*ticket, bool) {
	var t ticket
	if !s.open(r, ticketCookie, s.ticketBox, "ticket", req.host, &t) || t.Client != req.client || s.now().Unix() >= t.Expires || s.tickets.used(t.ID) {
		return nil, false
	}
	return &t, true
}

// altchaCheck verifies the solution of the widget and only then opens the address field.
func (s *Server) altchaCheck(w http.ResponseWriter, r *http.Request) {
	req, ok := s.resolve(r)
	if !ok || !req.site.Offers(config.EmailMethod) || s.codes == nil || s.altcha == nil {
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
	if !s.checks.Allow(req.client, s.now()) || !s.networks.Allow(req.network, s.now()) {
		s.log.Warn("rate limit", "limit", "per_client", "host", req.host)
		s.renderSignIn(w, r, req, http.StatusTooManyRequests, rd, lang, "limit", here)
		return
	}
	reason, err := "altcha_malformed", errRefused
	if solution := r.PostFormValue("altcha"); len(solution) <= maxSolution && solutionPattern.MatchString(solution) {
		reason, err = s.altcha.verify(r.Context(), solution)
	}
	switch {
	case errors.Is(err, errRefused):
		s.log.Info("altcha refused", "host", req.host, "reason", reason)
		s.renderSignIn(w, r, req, http.StatusForbidden, rd, lang, "altcha", here)
		return
	case err != nil:
		s.log.Error("altcha unavailable", "host", req.host, "error", err)
		s.renderSignIn(w, r, req, http.StatusServiceUnavailable, rd, lang, "altcha_unavailable", here)
		return
	}
	t := ticket{ID: rand.Text(), Client: req.client, Expires: s.now().Add(ticketLifetime).Unix()}
	s.store(w, ticketCookie, s.ticketBox, "ticket", req.host, t, ticketLifetime, http.SameSiteStrictMode)
	http.Redirect(w, r, gatekeeperURL("/sign_in", rd, lang), http.StatusSeeOther)
}

// altchaPolicy is the only policy that admits a script: exactly the widget of the ALTCHA service and exactly its
// challenge, on the step that shows them.
func (s *Server) altchaPolicy(widget *script) string {
	return "default-src 'none'; script-src " + widget.Src + "; connect-src " + s.cfg.Altcha.URL + "/challenge; worker-src blob:; style-src 'sha256-" +
		s.look.cssHash + "' 'nonce-" + widget.Nonce + "'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}

func (s *Server) hasTicket(r *http.Request, req *request) bool {
	_, ok := s.readTicket(r, req)
	return ok
}
