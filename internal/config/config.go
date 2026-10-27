package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/brand"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

const EmailMethod = "email"

const AnyHost = "*"

type Config struct {
	Listen         string              `json:"listen"`
	HealthListen   string              `json:"health_listen"`
	SecretFile     string              `json:"secret_file"`
	TrustedProxies []string            `json:"trusted_proxies"`
	ClientIPHeader string              `json:"client_ip_header"`
	Language       string              `json:"default_language"`
	Session        Duration            `json:"session"`
	Mail           *Mail               `json:"mail"`
	Providers      []Provider          `json:"providers"`
	Groups         map[string][]string `json:"groups"`
	Hosts          map[string]*Host    `json:"hosts"`
	Umami          *Umami              `json:"umami"`
	Altcha         *Altcha             `json:"altcha"`
	Branding       Branding            `json:"branding"`

	Secret  []byte         `json:"-"`
	Proxies []netip.Prefix `json:"-"`

	members map[string]map[string]bool
	domains map[string]map[string]bool
}

type Host struct {
	Login   []string `json:"login"`
	Allow   []string `json:"allow"`
	Session Duration `json:"session"`
}

type Mail struct {
	Host         string     `json:"host"`
	Port         int        `json:"port"`
	TLS          string     `json:"tls"`
	ServerName   string     `json:"server_name"`
	Username     string     `json:"username"`
	PasswordFile string     `json:"password_file"`
	From         string     `json:"from"`
	FromName     string     `json:"from_name"`
	CodeTTL      Duration   `json:"code_ttl"`
	CodeAttempts int        `json:"code_attempts"`
	Link         bool       `json:"link"`
	Limits       MailLimits `json:"limits"`
	Bounces      *Bounces   `json:"bounces"`

	Password string `json:"-"`
}

// Bounces reads the mailbox of the submission account and stops mail to an address whose code mail bounced.
type Bounces struct {
	IMAPHost     string   `json:"imap_host"`
	IMAPPort     int      `json:"imap_port"`
	Poll         Duration `json:"poll"`
	Suppress     Duration `json:"suppress"`
	DeleteOthers bool     `json:"delete_others"`

	// ServerName is the name the IMAP certificate must carry: mail.server_name on mail.host, else imap_host.
	ServerName string `json:"-"`
}

// With mail.bounces the envelope sender is <local>+b-<token>@<domain>, the token 26 characters long.
const maxBounceLocal = 64 - len("+b-") - 26

type MailLimits struct {
	PerClient  Limit `json:"per_client"`
	PerAddress Limit `json:"per_address"`
	Total      Limit `json:"total"`
	Attempts   Limit `json:"attempts"`
}

type Limit struct {
	Count  int      `json:"count"`
	Window Duration `json:"window"`
}

type Provider struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Icon             string   `json:"icon"`
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	Scopes           []string `json:"scopes"`
	Logout           string   `json:"logout"`
	// With a groups claim the provider's groups decide, not the addresses in groups.
	GroupsClaim string `json:"groups_claim"`

	ClientSecret string `json:"-"`
}

type Umami struct {
	URL           string   `json:"url"`
	Website       string   `json:"website"`
	RespectOptOut []string `json:"respect_opt_out"`
}

// Altcha puts a proof of work of the ALTCHA service before the address field of the code by email.
type Altcha struct {
	URL  string `json:"url"`
	Site string `json:"site"`
}

// Branding is optional as a whole: without it the pages and the mail carry the neutral look of brand.Default.
type Branding struct {
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	URL       string `json:"url"`
	MarkFile  string `json:"mark_file"`
	LogoFile  string `json:"logo_file"`
	Colors    Colors `json:"colors"`
	TextsFile string `json:"texts_file"`

	Mark    *brand.Mark   `json:"-"`
	Logo    brand.Logo    `json:"-"`
	Palette brand.Palette `json:"-"`
	Texts   *i18n.Catalog `json:"-"`
}

type Colors struct {
	Brand       string `json:"brand"`
	BrandStrong string `json:"brand_strong"`
	BrandDark   string `json:"brand_dark"`
}

// The texts_file is read whole; it holds a few texts in four languages.
const maxTextsBytes = 256 << 10

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("a duration is a string like \"10m\": %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

var (
	hostPattern     = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	providerPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	// The site names of the ALTCHA service.
	sitePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	groupPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)
	headerPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	// A domain entry admits only these local parts - no '%' or '!' a mail server could read as a route elsewhere.
	localPattern = regexp.MustCompile(`^[a-z0-9._+-]{1,64}$`)
)

var (
	Icons       = []string{"", "zitadel"}
	LogoutModes = []string{"", "backend", "browser"}
	tlsModes    = []string{"starttls", "tls", "none"}
)

// Load reports every problem, not only the first.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	cfg := &Config{}
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%s: more than one JSON value", path)
	}
	cfg.defaults()
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.HealthListen == "" {
		c.HealthListen = "127.0.0.1:8081"
	}
	if c.ClientIPHeader == "" {
		c.ClientIPHeader = "X-Real-Ip"
	}
	if c.Language == "" {
		c.Language = "en"
	}
	if c.Session == 0 {
		c.Session = Duration(24 * time.Hour)
	}
	if m := c.Mail; m != nil {
		if m.Port == 0 {
			m.Port = 587
		}
		if m.TLS == "" {
			m.TLS = "starttls"
		}
		if m.ServerName == "" {
			m.ServerName = m.Host
		}
		if m.CodeTTL == 0 {
			m.CodeTTL = Duration(15 * time.Minute)
		}
		if m.CodeAttempts == 0 {
			m.CodeAttempts = 5
		}
		limitDefault(&m.Limits.PerClient, 10, 15*time.Minute)
		limitDefault(&m.Limits.PerAddress, 5, time.Hour)
		limitDefault(&m.Limits.Total, 100, time.Hour)
		limitDefault(&m.Limits.Attempts, 20, 15*time.Minute)
		if b := m.Bounces; b != nil {
			if b.IMAPHost == "" {
				b.IMAPHost = m.Host
			}
			if b.IMAPPort == 0 {
				b.IMAPPort = 993
			}
			if b.Poll == 0 {
				b.Poll = Duration(time.Minute)
			}
			if b.Suppress == 0 {
				b.Suppress = Duration(48 * time.Hour)
			}
			b.ServerName = b.IMAPHost
			if b.IMAPHost == m.Host {
				b.ServerName = m.ServerName
			}
		}
	}
	for i := range c.Providers {
		if len(c.Providers[i].Scopes) == 0 {
			c.Providers[i].Scopes = []string{"openid", "email", "profile"}
		}
	}
	b := &c.Branding
	if b.Name == "" {
		b.Name = "Gatekeeper"
	}
	colorDefault(&b.Colors.Brand, brand.DefaultBrand)
	colorDefault(&b.Colors.BrandStrong, brand.DefaultStrong)
	colorDefault(&b.Colors.BrandDark, brand.DefaultDark)
}

func colorDefault(color *string, fallback string) {
	if *color == "" {
		*color = fallback
	}
	*color = strings.ToLower(*color)
}

func limitDefault(l *Limit, count int, window time.Duration) {
	if l.Count == 0 {
		l.Count = count
	}
	if l.Window == 0 {
		l.Window = Duration(window)
	}
}

type problems []string

func (p *problems) add(format string, args ...any) { *p = append(*p, fmt.Sprintf(format, args...)) }

func (c *Config) check() error {
	var p problems

	secret, err := readSecret(c.SecretFile)
	switch {
	case c.SecretFile == "":
		p.add("secret_file is missing")
	case err != nil:
		p.add("secret_file: %v", err)
	case len(secret) < 32:
		p.add("secret_file: the secret has %d bytes, at least 32 are needed", len(secret))
	}
	c.Secret = secret

	if len(c.TrustedProxies) == 0 {
		p.add("trusted_proxies is empty - without it every client would share one address in the rate limits")
	}
	for _, entry := range c.TrustedProxies {
		prefix, err := parsePrefix(entry)
		if err != nil {
			p.add("trusted_proxies: %q is neither an address nor a network", entry)
			continue
		}
		if prefix.Bits() == 0 {
			p.add("trusted_proxies: %q trusts every address - name the networks of the proxies, such as the Docker network", entry)
			continue
		}
		c.Proxies = append(c.Proxies, prefix)
	}
	if !headerPattern.MatchString(c.ClientIPHeader) {
		p.add("client_ip_header %q is not a header name", c.ClientIPHeader)
	}
	if !i18n.Supported(c.Language) {
		p.add("default_language %q is none of %v", c.Language, i18n.Languages)
	}
	checkSession(&p, "session", c.Session)

	providers := map[string]bool{}
	for i := range c.Providers {
		c.checkProvider(&p, &c.Providers[i], providers)
	}

	c.members = map[string]map[string]bool{}
	c.domains = map[string]map[string]bool{}
	for name, addresses := range c.Groups {
		if !groupPattern.MatchString(name) {
			p.add("groups: %q is not a valid group name (lower case letters, digits, '.', '_', '-')", name)
		}
		set, domains := map[string]bool{}, map[string]bool{}
		for _, address := range addresses {
			if domain, isDomain := strings.CutPrefix(address, "@"); isDomain {
				if !hostPattern.MatchString(domain) {
					p.add("groups.%s: %q is not a lower case domain like @example.com", name, address)
					continue
				}
				domains[domain] = true
				continue
			}
			normalized, ok := NormalizeAddress(address)
			if !ok || normalized != address {
				p.add("groups.%s: %q is not a plain lower case address", name, address)
				continue
			}
			set[normalized] = true
		}
		c.members[name] = set
		c.domains[name] = domains
	}

	if len(c.Hosts) == 0 {
		p.add("hosts is empty")
	}
	usesEmail := false
	for name, host := range c.Hosts {
		if name != AnyHost && !hostPattern.MatchString(name) {
			p.add("hosts: %q is not a lower case host name", name)
		}
		if host == nil {
			p.add("hosts.%s is empty", name)
			continue
		}
		if len(host.Login) == 0 {
			p.add("hosts.%s.login is empty", name)
		}
		seen := map[string]bool{}
		for _, method := range host.Login {
			switch {
			case seen[method]:
				p.add("hosts.%s.login lists %q twice", name, method)
			case method == EmailMethod:
				usesEmail = true
			case !providers[method]:
				p.add("hosts.%s.login: %q is neither %q nor a provider id", name, method, EmailMethod)
			}
			seen[method] = true
		}
		if len(host.Allow) == 0 {
			p.add("hosts.%s.allow is empty", name)
		}
		claims := false
		for _, method := range host.Login {
			if prov, ok := c.Provider(method); ok && prov.GroupsClaim != "" {
				claims = true
			}
		}
		for _, group := range host.Allow {
			_, defined := c.Groups[group]
			switch {
			case !groupPattern.MatchString(group):
				p.add("hosts.%s.allow: %q is not a valid group name", name, group)
			case !defined && !claims:
				p.add("hosts.%s.allow: there is no group %q, and no provider of this host brings groups", name, group)
			}
		}
		if host.Session != 0 {
			checkSession(&p, "hosts."+name+".session", host.Session)
		}
	}

	if usesEmail && c.Mail == nil {
		p.add("a host signs in by %q, but there is no mail section", EmailMethod)
	}
	if c.Mail != nil {
		c.checkMail(&p)
	}
	if c.Umami != nil {
		c.checkUmami(&p)
	}
	if c.Altcha != nil {
		c.checkAltcha(&p, usesEmail)
	}
	c.checkBranding(&p)

	if len(p) > 0 {
		return errors.New("configuration:\n  - " + strings.Join(p, "\n  - "))
	}
	return nil
}

func checkSession(p *problems, name string, d Duration) {
	if d.D() < 5*time.Minute || d.D() > 30*24*time.Hour {
		p.add("%s must lie between 5m and 720h", name)
	}
}

func (c *Config) checkProvider(p *problems, prov *Provider, seen map[string]bool) {
	if !providerPattern.MatchString(prov.ID) || prov.ID == EmailMethod {
		p.add("providers: id %q must be lower case letters, digits and '-', and not %q", prov.ID, EmailMethod)
	}
	if seen[prov.ID] {
		p.add("providers: id %q is used twice", prov.ID)
	}
	seen[prov.ID] = true
	if strings.TrimSpace(prov.Name) == "" || hasControl(prov.Name) || len(prov.Name) > 40 {
		p.add("providers.%s: name must be printable and at most 40 bytes", prov.ID)
	}
	if !slices.Contains(Icons, prov.Icon) {
		p.add("providers.%s: icon %q is none of %q", prov.ID, prov.Icon, Icons)
	}
	issuer, err := url.Parse(prov.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.User != nil {
		p.add("providers.%s: issuer must be an https URL without query", prov.ID)
	}
	if prov.ClientID == "" {
		p.add("providers.%s: client_id is missing", prov.ID)
	}
	if prov.ClientSecretFile != "" {
		secret, err := readSecret(prov.ClientSecretFile)
		if err != nil || len(secret) == 0 {
			p.add("providers.%s: client_secret_file cannot be read or is empty", prov.ID)
		}
		prov.ClientSecret = string(secret)
	}
	if !slices.Contains(prov.Scopes, "openid") || !slices.Contains(prov.Scopes, "email") {
		p.add("providers.%s: scopes must contain openid and email", prov.ID)
	}
	if !slices.Contains(LogoutModes, prov.Logout) {
		p.add("providers.%s: logout %q is none of %q", prov.ID, prov.Logout, LogoutModes)
	}
	if hasControl(prov.GroupsClaim) || len(prov.GroupsClaim) > 100 {
		p.add("providers.%s: groups_claim must be printable and at most 100 bytes", prov.ID)
	}
}

func (c *Config) checkMail(p *problems) {
	m := c.Mail
	if m.Host == "" {
		p.add("mail.host is missing")
	}
	if m.Port < 1 || m.Port > 65535 {
		p.add("mail.port %d is not a port", m.Port)
	}
	if !slices.Contains(tlsModes, m.TLS) {
		p.add("mail.tls %q is none of %q", m.TLS, tlsModes)
	}
	if m.Username != "" {
		if m.TLS == "none" {
			p.add("mail.username needs mail.tls starttls or tls - the password never travels unencrypted")
		}
		password, err := readSecret(m.PasswordFile)
		if m.PasswordFile == "" || err != nil || len(password) == 0 {
			p.add("mail.password_file cannot be read or is empty")
		}
		m.Password = string(password)
	}
	if from, ok := NormalizeAddress(m.From); !ok || from != m.From {
		p.add("mail.from %q is not a plain lower case address", m.From)
	}
	if hasControl(m.FromName) || len(m.FromName) > 100 {
		p.add("mail.from_name must be printable and at most 100 bytes")
	}
	if m.CodeTTL.D() < time.Minute || m.CodeTTL.D() > time.Hour {
		p.add("mail.code_ttl must lie between 1m and 1h")
	}
	if m.CodeTTL.D()%time.Minute != 0 {
		p.add("mail.code_ttl must be whole minutes - the pages and the mail state it in minutes")
	}
	if m.CodeAttempts < 1 || m.CodeAttempts > 10 {
		p.add("mail.code_attempts must lie between 1 and 10")
	}
	for name, l := range map[string]Limit{"per_client": m.Limits.PerClient, "per_address": m.Limits.PerAddress, "total": m.Limits.Total, "attempts": m.Limits.Attempts} {
		if l.Count < 1 || l.Window.D() < time.Second {
			p.add("mail.limits.%s needs a count of at least 1 and a window of at least 1s", name)
		}
	}
	if b := m.Bounces; b != nil {
		if m.Username == "" {
			p.add("mail.bounces needs mail.username - gatekeeper reads the mailbox of the submission account")
		}
		if b.IMAPHost == "" {
			p.add("mail.bounces.imap_host is missing")
		}
		if b.IMAPPort < 1 || b.IMAPPort > 65535 {
			p.add("mail.bounces.imap_port %d is not a port", b.IMAPPort)
		}
		if b.Poll.D() < 10*time.Second || b.Poll.D() > time.Hour {
			p.add("mail.bounces.poll must lie between 10s and 1h")
		}
		if b.Suppress.D() < time.Hour || b.Suppress.D() > 30*24*time.Hour {
			p.add("mail.bounces.suppress must lie between 1h and 720h")
		}
		if at := strings.LastIndexByte(m.From, '@'); at > maxBounceLocal {
			p.add("mail.from: with mail.bounces the local part has at most %d characters - the envelope senders add +b- and a token", maxBounceLocal)
		}
	}
}

func (c *Config) checkUmami(p *problems) {
	u, err := url.Parse(c.Umami.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		p.add("umami.url must be an http or https URL")
	}
	if c.Umami.Website == "" || hasControl(c.Umami.Website) {
		p.add("umami.website is missing")
	}
	for _, host := range c.Umami.RespectOptOut {
		if !hostPattern.MatchString(host) {
			p.add("umami.respect_opt_out: %q is not a lower case host name", host)
		}
	}
}

func (c *Config) checkAltcha(p *problems, usesEmail bool) {
	a := c.Altcha
	a.URL = strings.TrimRight(a.URL, "/")
	u, err := url.Parse(a.URL)
	// The URL goes into the Content Security Policy of the ALTCHA step.
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(a.URL, " ;,'\"") {
		p.add("altcha.url must be the https URL of the ALTCHA service, without query")
	}
	if !sitePattern.MatchString(a.Site) {
		p.add("altcha.site %q is not a site name of the ALTCHA service (lower case letters, digits, '.', '-')", a.Site)
	}
	if !usesEmail {
		p.add("altcha is set, but no host signs in by %q", EmailMethod)
	}
}

func (c *Config) checkBranding(p *problems) {
	b := &c.Branding
	if strings.TrimSpace(b.Name) == "" || hasControl(b.Name) || len(b.Name) > 40 {
		p.add("branding.name must be printable and at most 40 bytes")
	}
	if hasControl(b.Owner) || len(b.Owner) > 100 {
		p.add("branding.owner must be printable and at most 100 bytes")
	}
	if b.URL != "" {
		u, err := url.Parse(b.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(b.URL) > 200 {
			p.add("branding.url must be an http or https URL of at most 200 bytes")
		}
		if strings.TrimSpace(b.Owner) == "" {
			p.add("branding.url needs branding.owner, the text of the link")
		}
	}
	valid := true
	for name, color := range map[string]string{"brand": b.Colors.Brand, "brand_strong": b.Colors.BrandStrong, "brand_dark": b.Colors.BrandDark} {
		if !brand.ValidColor(color) {
			p.add("branding.colors.%s %q is not a colour like #04a9f3", name, color)
			valid = false
		}
	}
	b.Palette = brand.DefaultPalette
	if valid {
		b.Palette = brand.NewPalette(b.Colors.Brand, b.Colors.BrandStrong, b.Colors.BrandDark)
	}

	b.Mark = brand.Default
	if b.MarkFile != "" {
		data, err := readFile(b.MarkFile, brand.MaxMarkBytes)
		if err == nil {
			b.Mark, err = brand.ParseMark(data)
		}
		if err != nil {
			p.add("branding.mark_file: %v", err)
		}
	}
	b.Logo = brand.DefaultLogo
	if b.LogoFile != "" {
		data, err := readFile(b.LogoFile, brand.MaxLogoBytes)
		if err == nil {
			b.Logo, err = brand.ParseLogo(data)
		}
		if err != nil {
			p.add("branding.logo_file: %v", err)
		}
	}
	var overrides map[string]map[string]string
	if b.TextsFile != "" {
		data, err := readFile(b.TextsFile, maxTextsBytes)
		if err != nil {
			p.add("branding.texts_file: %v", err)
		}
		var found []string
		if err == nil {
			overrides, found = i18n.ParseOverrides(data)
		}
		for _, problem := range found {
			p.add("branding.texts_file: %s", problem)
		}
	}
	b.Texts = i18n.NewCatalog(overrides)
}

// readFile reads one byte more than allowed, so a file that is too long is told apart from one that fits.
func readFile(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("more than %d bytes", limit)
	}
	return data, nil
}

func readSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("no file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(data), nil
}

func parsePrefix(entry string) (netip.Prefix, error) {
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		return prefix.Masked(), err
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// NormalizeAddress accepts only plain ASCII addresses; the result is what groups compare against.
func NormalizeAddress(input string) (string, bool) {
	address := strings.TrimSpace(input)
	if address == "" || len(address) > 254 {
		return "", false
	}
	// Before lowering: strings.ToLower folds 'İ' into 'i' and the Kelvin sign into 'k' - another mailbox, the same address.
	for i := 0; i < len(address); i++ {
		if address[i] <= ' ' || address[i] >= 0x7f {
			return "", false
		}
	}
	address = strings.ToLower(address)
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Name != "" || parsed.Address != address {
		return "", false
	}
	at := strings.LastIndexByte(address, '@')
	if at < 1 || !hostPattern.MatchString(address[at+1:]) {
		return "", false
	}
	return address, true
}

func ValidHost(host string) bool { return hostPattern.MatchString(host) }

// HostConfig falls back to the "*" entry; without one an unknown host gets nothing.
func (c *Config) HostConfig(host string) (*Host, bool) {
	if h, ok := c.Hosts[host]; ok {
		return h, true
	}
	h, ok := c.Hosts[AnyHost]
	return h, ok
}

// Allowed takes a NormalizeAddress result: the address itself or, for a domain entry, exactly its domain.
func (c *Config) Allowed(host *Host, address string) bool {
	domain := domainOf(address)
	for _, group := range host.Allow {
		if c.members[group][address] || (domain != "" && c.domains[group][domain]) {
			return true
		}
	}
	return false
}

// Listed is Allowed without domain entries: the address itself stands in an allowed group.
func (c *Config) Listed(host *Host, address string) bool {
	for _, group := range host.Allow {
		if c.members[group][address] {
			return true
		}
	}
	return false
}

// domainOf is the domain a domain entry would need, or "" when the local part is outside localPattern.
func domainOf(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 1 || !localPattern.MatchString(address[:at]) {
		return ""
	}
	return address[at+1:]
}

// AllowedGroups is the decision for a provider with groups_claim: one of its groups must be allowed on the host.
func AllowedGroups(host *Host, groups []string) bool {
	for _, group := range groups {
		if slices.Contains(host.Allow, group) {
			return true
		}
	}
	return false
}

// GroupNames are all groups any host allows - only these are worth keeping in a session.
func (c *Config) GroupNames() map[string]bool {
	names := map[string]bool{}
	for _, host := range c.Hosts {
		if host == nil {
			continue
		}
		for _, group := range host.Allow {
			names[group] = true
		}
	}
	return names
}

func (c *Config) Provider(id string) (*Provider, bool) {
	for i := range c.Providers {
		if c.Providers[i].ID == id {
			return &c.Providers[i], true
		}
	}
	return nil, false
}

func (h *Host) Offers(method string) bool { return slices.Contains(h.Login, method) }

func (c *Config) SessionFor(h *Host) time.Duration {
	if h.Session != 0 {
		return h.Session.D()
	}
	return c.Session.D()
}
