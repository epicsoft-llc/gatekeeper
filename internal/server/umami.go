package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

// umami counts the sign-in page and its steps; a nil *umami counts nothing.
type umami struct {
	url     string
	website string
	optOut  map[string]bool
	client  *http.Client
	slots   chan struct{}
	log     *slog.Logger
}

func newUmami(cfg *config.Umami, client *http.Client, log *slog.Logger) *umami {
	u := &umami{url: cfg.URL, website: cfg.Website, optOut: map[string]bool{}, client: client, slots: make(chan struct{}, 4), log: log}
	for _, host := range cfg.RespectOptOut {
		u.optOut[host] = true
	}
	return u
}

// A click on a language link counts as gate-language, not as a second page view.
func (u *umami) page(r *http.Request, req *request, path, chosen string) {
	if chosen == "" {
		u.event(r, req, path, "", nil)
	} else if i18n.Supported(chosen) {
		u.event(r, req, path, "gate-language", map[string]string{"lang": chosen})
	}
}

func (u *umami) event(r *http.Request, req *request, path, name string, data map[string]string) {
	if u == nil || !navigation(r) || (u.optOut[req.host] && (r.Header.Get("DNT") == "1" || r.Header.Get("Sec-GPC") == "1")) {
		return
	}
	path, _, _ = strings.Cut(path, "?")
	agent := r.Header.Get("User-Agent")
	referrer, _, _ := strings.Cut(r.Header.Get("Referer"), "?")
	referrer, _, _ = strings.Cut(referrer, "#")
	language, _, _ := strings.Cut(r.Header.Get("Accept-Language"), ",")
	language, _, _ = strings.Cut(language, ";")
	payload := map[string]any{
		"website":   u.website,
		"hostname":  req.host,
		"url":       path,
		"referrer":  referrer,
		"language":  strings.TrimSpace(language),
		"ip":        req.ip,
		"userAgent": agent,
	}
	if name != "" {
		values := map[string]string{"domain": req.host}
		for key, value := range data {
			values[key] = value
		}
		payload["name"] = name
		payload["data"] = values
	}
	body, err := json.Marshal(map[string]any{"type": "event", "payload": payload})
	if err != nil {
		return
	}
	select {
	case u.slots <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-u.slots }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(body))
		if err != nil {
			return
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", agent)
		response, err := u.client.Do(request)
		if err != nil {
			u.log.Warn("umami unreachable", "error", err)
			return
		}
		_ = response.Body.Close()
	}()
}

// navigation counts only what the browser shows as a page, not the favicon behind the same answer.
func navigation(r *http.Request) bool {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
