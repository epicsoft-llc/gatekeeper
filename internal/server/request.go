package server

import (
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
)

type request struct {
	host    string
	site    *config.Host
	trusted bool
	ip      string
	// IPv4 address or IPv6 /64, so one client cannot rotate through its own network.
	client string
	// IPv4 address or IPv6 /48: the network a flood of /64 clients would come from.
	network string
}

// resolve believes forwarded headers only from trusted_proxies; an unknown host resolves to nothing.
func (s *Server) resolve(r *http.Request) (*request, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	addr := peer.Addr().Unmap()
	trusted := err == nil && s.trustedPeer(addr)
	host := r.Host
	if trusted {
		if forwarded := lastValue(r.Header.Values("X-Forwarded-Host")); forwarded != "" {
			// A proxy that sends a configured host as Host and another one forwarded passed on what a client chose.
			if own := normalizeHost(r.Host); s.cfg.Hosts[own] != nil && own != normalizeHost(forwarded) {
				return nil, false
			}
			host = forwarded
		}
		if client, ok := s.clientAddress(r); ok {
			addr = client
		}
	}
	host = normalizeHost(host)
	if host == "" {
		return nil, false
	}
	site, ok := s.cfg.HostConfig(host)
	if !ok {
		return nil, false
	}
	req := &request{host: host, site: site, trusted: trusted, client: "unknown", network: "unknown"}
	if addr.IsValid() {
		req.ip = addr.String()
		req.client, req.network = addr.String(), addr.String()
		if addr.Is6() {
			client, _ := addr.Prefix(64)
			network, _ := addr.Prefix(48)
			req.client, req.network = client.String(), network.String()
		}
	}
	return req, true
}

func (s *Server) trustedPeer(addr netip.Addr) bool {
	for _, prefix := range s.cfg.Proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) clientAddress(r *http.Request) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(lastValue(r.Header.Values(s.cfg.ClientIPHeader)))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// lastValue is what the nearest proxy wrote: the last entry of the last line - a client can only put values before it.
func lastValue(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	value := lines[len(lines)-1]
	if i := strings.LastIndexByte(value, ','); i >= 0 {
		value = value[i+1:]
	}
	return strings.TrimSpace(value)
}

// normalizeHost refuses anything but ASCII before lowering: strings.ToLower folds 'İ' into 'i' and the Kelvin sign into 'k'.
func normalizeHost(host string) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return ""
		}
	}
	host = strings.ToLower(host)
	if i := strings.LastIndexByte(host, ':'); i >= 0 && onlyDigits(host[i+1:]) {
		host = host[:i]
	}
	if !config.ValidHost(host) {
		return ""
	}
	return host
}

// originalURI is what the browser asked for: nginx and Traefik pass it in X-Forwarded-Uri.
func originalURI(r *http.Request, req *request) string {
	if req.trusted {
		if lines := r.Header.Values("X-Forwarded-Uri"); len(lines) > 0 && lines[len(lines)-1] != "" {
			return lines[len(lines)-1]
		}
	}
	return r.URL.RequestURI()
}

func isGatekeeperPath(uri string) bool {
	path, _, _ := strings.Cut(uri, "?")
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// safeReturn admits only a path on the same host; anything else becomes "/".
func safeReturn(p string) string {
	if p == "" || len(p) > 2048 || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsRune(p, '\\') {
		return "/"
	}
	for i := 0; i < len(p); i++ {
		if p[i] <= ' ' || p[i] == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || isGatekeeperPath(u.Path) {
		return "/"
	}
	decoded, err := url.PathUnescape(u.Path)
	if err != nil || strings.HasPrefix(decoded, "//") || strings.ContainsRune(decoded, '\\') || isGatekeeperPath(path.Clean(decoded)) {
		return "/"
	}
	return p
}

// splitLang keeps the other parameters as they were written, without encoding them again.
func splitLang(uri string) (string, string) {
	path, query, ok := strings.Cut(uri, "?")
	if !ok {
		return uri, ""
	}
	var kept []string
	lang := ""
	for _, pair := range strings.Split(query, "&") {
		name, value, _ := strings.Cut(pair, "=")
		switch {
		case pair == "":
		case name == "lang":
			if lang == "" {
				lang = value
			}
		default:
			kept = append(kept, pair)
		}
	}
	if len(kept) == 0 {
		return path, lang
	}
	return path + "?" + strings.Join(kept, "&"), lang
}

func withLang(uri, lang string) string {
	rest, _ := splitLang(uri)
	if strings.Contains(rest, "?") {
		return rest + "&lang=" + lang
	}
	return rest + "?lang=" + lang
}

func gatekeeperURL(path, rd, lang string, extra ...string) string {
	values := url.Values{"rd": {rd}, "lang": {lang}}
	for i := 0; i+1 < len(extra); i += 2 {
		values.Set(extra[i], extra[i+1])
	}
	return prefix + path + "?" + values.Encode()
}
