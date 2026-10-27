package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/brand"
)

const validConfig = `{
  "secret_file": "SECRET",
  "trusted_proxies": ["172.16.0.0/12", "10.0.0.1"],
  "default_language": "de",
  "mail": {
    "host": "mail.example.com",
    "username": "gate@example.com",
    "password_file": "PASSWORD",
    "from": "gate@example.com",
    "from_name": "Example"
  },
  "providers": [
    {"id": "zitadel", "name": "Zitadel", "icon": "zitadel", "issuer": "https://id.example.com", "client_id": "123", "client_secret_file": "CLIENT", "logout": "backend"}
  ],
  "groups": {
    "all": ["admin@example.com"],
    "report.example.com": ["reader@example.org"]
  },
  "hosts": {
    "report.example.com": {"login": ["email", "zitadel"], "allow": ["report.example.com", "all"]},
    "*": {"login": ["zitadel"], "allow": ["all"], "session": "1h"}
  }
}`

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func load(t *testing.T, replace ...string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	text := validConfig
	for i := 0; i+1 < len(replace); i += 2 {
		if !strings.Contains(text, replace[i]) {
			t.Fatalf("config has no %q", replace[i])
		}
		text = strings.ReplaceAll(text, replace[i], replace[i+1])
	}
	text = strings.ReplaceAll(text, `"SECRET"`, quote(write(t, dir, "secret", strings.Repeat("s", 40)+"\n")))
	text = strings.ReplaceAll(text, `"PASSWORD"`, quote(write(t, dir, "password", "mail-password\n")))
	text = strings.ReplaceAll(text, `"CLIENT"`, quote(write(t, dir, "client", "client-secret")))
	return Load(write(t, dir, "config.json", text))
}

func quote(path string) string { return `"` + filepath.ToSlash(path) + `"` }

func TestValidConfigGetsDefaults(t *testing.T) {
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.HealthListen != "127.0.0.1:8081" || cfg.ClientIPHeader != "X-Real-Ip" {
		t.Errorf("listen defaults: %q %q %q", cfg.Listen, cfg.HealthListen, cfg.ClientIPHeader)
	}
	if cfg.Session.D() != 24*time.Hour || cfg.Mail.Port != 587 || cfg.Mail.TLS != "starttls" || cfg.Mail.ServerName != "mail.example.com" {
		t.Errorf("session or mail defaults: %v %d %q %q", cfg.Session.D(), cfg.Mail.Port, cfg.Mail.TLS, cfg.Mail.ServerName)
	}
	if cfg.Mail.CodeTTL.D() != 15*time.Minute || cfg.Mail.CodeAttempts != 5 || cfg.Mail.Limits.PerAddress.Count != 5 {
		t.Errorf("code defaults: %v %d %d", cfg.Mail.CodeTTL.D(), cfg.Mail.CodeAttempts, cfg.Mail.Limits.PerAddress.Count)
	}
	if string(cfg.Secret) != strings.Repeat("s", 40) || cfg.Mail.Password != "mail-password" || cfg.Providers[0].ClientSecret != "client-secret" {
		t.Error("secrets are not read or not trimmed")
	}
	if got := cfg.Providers[0].Scopes; len(got) != 3 {
		t.Errorf("default scopes: %v", got)
	}
	if len(cfg.Proxies) != 2 || cfg.Proxies[1].Bits() != 32 {
		t.Errorf("proxies: %v", cfg.Proxies)
	}
}

func TestAccess(t *testing.T) {
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	report, ok := cfg.HostConfig("report.example.com")
	if !ok {
		t.Fatal("report.example.com is missing")
	}
	other, ok := cfg.HostConfig("other.example.com")
	if !ok || other.Session.D() != time.Hour {
		t.Fatal("the * entry does not apply")
	}
	cases := []struct {
		host    *Host
		address string
		want    bool
	}{
		{report, "reader@example.org", true},
		{report, "admin@example.com", true},
		{report, "stranger@example.org", false},
		{report, "READER@example.org", false},
		{other, "admin@example.com", true},
		{other, "reader@example.org", false},
	}
	for _, c := range cases {
		if got := cfg.Allowed(c.host, c.address); got != c.want {
			t.Errorf("Allowed(%v, %q) = %v", c.host.Allow, c.address, got)
		}
	}
	if cfg.SessionFor(report) != 24*time.Hour || cfg.SessionFor(other) != time.Hour {
		t.Error("SessionFor")
	}
	if !report.Offers("email") || other.Offers("email") {
		t.Error("Offers")
	}
}

func TestDomainEntry(t *testing.T) {
	cfg, err := load(t, `["reader@example.org"]`, `["reader@example.org", "@example.net"]`)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := cfg.HostConfig("report.example.com")
	other, _ := cfg.HostConfig("other.example.com")
	cases := []struct {
		host    *Host
		address string
		want    bool
	}{
		{report, "anyone@example.net", true},
		{report, "first.last+tag@example.net", true},
		{report, "x@sub.example.net", false},
		{report, "x@example.net.evil.com", false},
		{report, "x@notexample.net", false},
		{report, "a%b@example.net", false},
		{report, "a!b@example.net", false},
		{report, "@example.net", false},
		{other, "anyone@example.net", false},
	}
	for _, c := range cases {
		if got := cfg.Allowed(c.host, c.address); got != c.want {
			t.Errorf("Allowed(%v, %q) = %v", c.host.Allow, c.address, got)
		}
	}
	for _, bad := range []string{`"@"`, `"@localhost"`, `"@Example.net"`, `"@*.example.net"`, `"@-example.net"`, `"@example.net."`, `"a@@example.net"`} {
		if _, err := load(t, `["reader@example.org"]`, `["reader@example.org", `+bad+`]`); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestUnknownHostWithoutFallback(t *testing.T) {
	cfg, err := load(t, `,
    "*": {"login": ["zitadel"], "allow": ["all"], "session": "1h"}`, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.HostConfig("other.example.com"); ok {
		t.Error("an unknown host must get no entry")
	}
}

func TestProblems(t *testing.T) {
	cases := []struct {
		name    string
		replace []string
		want    string
	}{
		{"unknown field", []string{`"default_language"`, `"default_lang"`}, "unknown field"},
		{"short secret", []string{`"secret_file": "`, `"secret_file": "` + "x"}, "secret_file"},
		{"no proxies", []string{`["172.16.0.0/12", "10.0.0.1"]`, `[]`}, "trusted_proxies is empty"},
		{"bad proxy", []string{`"10.0.0.1"`, `"10.0.0.300"`}, "neither an address nor a network"},
		{"every IPv4 address", []string{`"10.0.0.1"`, `"0.0.0.0/0"`}, `"0.0.0.0/0" trusts every address`},
		{"every IPv6 address", []string{`"10.0.0.1"`, `"::/0"`}, `"::/0" trusts every address`},
		{"bad header", []string{`"default_language": "de",`, `"default_language": "de", "client_ip_header": "X Real",`}, "client_ip_header"},
		{"language", []string{`"default_language": "de"`, `"default_language": "fr"`}, "default_language"},
		{"session", []string{`"session": "1h"`, `"session": "1m"`}, "hosts.*.session"},
		{"upper case host", []string{`"report.example.com": {"login"`, `"Report.example.com": {"login"`}, "not a lower case host name"},
		{"unknown method", []string{`["email", "zitadel"]`, `["email", "github"]`}, `"github" is neither`},
		{"twice", []string{`["email", "zitadel"]`, `["email", "email"]`}, "twice"},
		{"no login", []string{`["email", "zitadel"]`, `[]`}, "login is empty"},
		{"unknown group", []string{`["report.example.com", "all"]`, `["admins"]`}, `no group "admins"`},
		{"no allow", []string{`["report.example.com", "all"]`, `[]`}, "allow is empty"},
		{"upper case member", []string{`"admin@example.com"`, `"Admin@example.com"`}, "plain lower case address"},
		{"member with name", []string{`"admin@example.com"`, `"Admin <admin@example.com>"`}, "plain lower case address"},
		{"bad group name", []string{`"all": [`, `"All": [`}, "not a valid group name"},
		{"groups claim", []string{`"logout": "backend"`, `"logout": "backend", "groups_claim": "a\nb"`}, "groups_claim"},
		{"no mail", []string{`"mail": {`, `"mailx": {`}, "unknown field"},
		{"password in clear", []string{`"from": "gate@example.com",`, `"from": "gate@example.com", "tls": "none",`}, "never travels unencrypted"},
		{"tls mode", []string{`"from": "gate@example.com",`, `"from": "gate@example.com", "tls": "ssl",`}, "mail.tls"},
		{"from", []string{`"from": "gate@example.com"`, `"from": "gate"`}, "mail.from"},
		{"from name", []string{`"from_name": "Example"`, `"from_name": "Ex\nample"`}, "from_name"},
		{"ttl seconds", []string{`"from_name": "Example"`, `"from_name": "Example", "code_ttl": "90s"`}, "whole minutes"},
		{"attempts", []string{`"from_name": "Example"`, `"from_name": "Example", "code_attempts": 50`}, "code_attempts"},
		{"limit", []string{`"from_name": "Example"`, `"from_name": "Example", "limits": {"total": {"count": -1}}`}, "limits.total"},
		{"http issuer", []string{`https://id.example.com`, `http://id.example.com`}, "issuer"},
		{"provider id", []string{`"id": "zitadel"`, `"id": "email"`}, "providers: id"},
		{"no client id", []string{`"client_id": "123"`, `"client_id": ""`}, "client_id is missing"},
		{"scopes", []string{`"logout": "backend"`, `"logout": "backend", "scopes": ["openid"]`}, "scopes must contain"},
		{"logout", []string{`"logout": "backend"`, `"logout": "always"`}, "logout"},
		{"icon", []string{`"icon": "zitadel"`, `"icon": "github"`}, "icon"},
		{"umami", []string{`"hosts": {`, `"umami": {"url": "ftp://umami", "website": ""}, "hosts": {`}, "umami.url"},
		{"altcha url", []string{`"hosts": {`, `"altcha": {"url": "http://altcha.example.com", "site": "gate"}, "hosts": {`}, "altcha.url"},
		{"altcha query", []string{`"hosts": {`, `"altcha": {"url": "https://altcha.example.com/?x=1", "site": "gate"}, "hosts": {`}, "altcha.url"},
		{"altcha site", []string{`"hosts": {`, `"altcha": {"url": "https://altcha.example.com", "site": "Gate Keeper"}, "hosts": {`}, "altcha.site"},
		{"altcha policy", []string{`"hosts": {`, `"altcha": {"url": "https://altcha.example.com/a;script-src *", "site": "gate"}, "hosts": {`}, "altcha.url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, c.replace...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestEmailWithoutMailSection(t *testing.T) {
	_, err := load(t, `"mail": {
    "host": "mail.example.com",
    "username": "gate@example.com",
    "password_file": "PASSWORD",
    "from": "gate@example.com",
    "from_name": "Example"
  },`, "")
	if err == nil || !strings.Contains(err.Error(), "no mail section") {
		t.Errorf("got %v", err)
	}
}

func TestGroupsClaim(t *testing.T) {
	claim := []string{`"logout": "backend"`, `"logout": "backend", "groups_claim": "gatekeeper:roles"`}
	cfg, err := load(t, append(claim, `["report.example.com", "all"]`, `["report.example.com", "all", "from-the-provider"]`)...)
	if err != nil {
		t.Fatalf("a group only the provider knows was refused: %v", err)
	}
	if !cfg.GroupNames()["from-the-provider"] || !cfg.GroupNames()["all"] {
		t.Errorf("GroupNames %v", cfg.GroupNames())
	}
	report, _ := cfg.HostConfig("report.example.com")
	if !AllowedGroups(report, []string{"x", "from-the-provider"}) || AllowedGroups(report, []string{"x"}) || AllowedGroups(report, nil) {
		t.Error("AllowedGroups")
	}
	if _, err := load(t, append(claim, `["report.example.com", "all"]`, `["report.example.com", "All"]`)...); err == nil || !strings.Contains(err.Error(), "not a valid group name") {
		t.Errorf("an invalid group name passed: %v", err)
	}
	_, err = load(t, `"report.example.com": {"login": ["email", "zitadel"], "allow": ["report.example.com", "all"]}`, `"report.example.com": {"login": ["email", "zitadel"], "allow": ["staff"]}`)
	if err == nil || !strings.Contains(err.Error(), "no provider of this host brings groups") {
		t.Errorf("an unknown group passed without a groups claim: %v", err)
	}
}

func TestExampleLoads(t *testing.T) {
	data, err := os.ReadFile("../../examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	text := string(data)
	for _, name := range []string{"gatekeeper_secret", "gatekeeper_smtp_password", "gatekeeper_zitadel_secret"} {
		text = strings.ReplaceAll(text, `"/run/secrets/`+name+`"`, quote(write(t, dir, name, strings.Repeat("e", 40))))
	}
	texts, err := os.ReadFile("../../examples/texts.json")
	if err != nil {
		t.Fatal(err)
	}
	text = strings.NewReplacer(
		`"/etc/gatekeeper/brand/mark.svg"`, quote(write(t, dir, "mark.svg", brand.Default.Document())),
		`"/etc/gatekeeper/brand/logo.png"`, quote(write(t, dir, "logo.png", string(brand.DefaultLogo.PNG))),
		`"/etc/gatekeeper/brand/texts.json"`, quote(write(t, dir, "texts.json", string(texts))),
	).Replace(text)
	cfg, err := Load(write(t, dir, "config.json", text))
	if err != nil {
		t.Fatal(err)
	}
	if staging, _ := cfg.HostConfig("staging.example.com"); cfg.SessionFor(staging) != 8*time.Hour {
		t.Error("staging session")
	}
	if cfg.Branding.Name != "Example" || cfg.Branding.Texts.T("en", "eyebrow") != "Team only" || cfg.Altcha.URL != "https://altcha.example.com" || cfg.Mail.Bounces.Suppress.D() != 48*time.Hour {
		t.Error("branding, altcha or bounces of the example")
	}
}

func TestNormalizeAddress(t *testing.T) {
	good := map[string]string{
		"a@example.com":        "a@example.com",
		" A.B+c@Example.COM  ": "a.b+c@example.com",
		"x@sub.example.co.uk":  "x@sub.example.co.uk",
	}
	for input, want := range good {
		if got, ok := NormalizeAddress(input); !ok || got != want {
			t.Errorf("NormalizeAddress(%q) = %q, %v", input, got, ok)
		}
	}
	bad := []string{
		"", "a", "a@", "@example.com", "a@localhost", "a b@example.com", "a@example.com\r\nBcc: x@example.com",
		"<a@example.com>", "A <a@example.com>", "a@exa_mple.com", "ä@example.com", "a@example.com,b@example.com",
		`"a"@example.com`, "a@-example.com", strings.Repeat("a", 250) + "@example.com",
		"bob@gmaİl.com", "\u212Aate@example.com", "İ@example.com",
	}
	for _, input := range bad {
		if got, ok := NormalizeAddress(input); ok {
			t.Errorf("NormalizeAddress(%q) accepted as %q", input, got)
		}
	}
}

func FuzzNormalizeAddress(f *testing.F) {
	for _, seed := range []string{"a@example.com", "A <a@example.com>", "a@b@c.de", "\"x y\"@example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		address, ok := NormalizeAddress(input)
		if !ok {
			return
		}
		if strings.ContainsAny(address, " \r\n\t<>,;\"") || address != strings.ToLower(address) {
			t.Errorf("%q accepted as %q", input, address)
		}
		if trimmed := strings.TrimSpace(input); !strings.EqualFold(trimmed, address) || strings.ContainsFunc(trimmed, func(r rune) bool { return r >= 0x80 }) {
			t.Errorf("%q folded into %q", input, address)
		}
		if again, ok := NormalizeAddress(address); !ok || again != address {
			t.Errorf("%q is not stable", address)
		}
	})
}

func TestBrandingDefaults(t *testing.T) {
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Branding
	if b.Name != "Gatekeeper" || b.Owner != "" || b.URL != "" || b.Mark != brand.Default || b.Palette != brand.DefaultPalette || !bytes.Equal(b.Logo.PNG, brand.DefaultLogo.PNG) {
		t.Errorf("defaults %+v", b)
	}
	if got := b.Texts.T("de", "signin_title", "name", b.Name); got != "Anmelden · Gatekeeper" {
		t.Errorf("title %q", got)
	}
}

func brandFiles(t *testing.T, texts string) (mark, logo, overrides string) {
	t.Helper()
	dir := t.TempDir()
	mark = quote(write(t, dir, "mark.svg", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="5" fill="#8b0000"/></svg>`))
	logo = quote(write(t, dir, "logo.png", string(brand.DefaultLogo.PNG)))
	overrides = quote(write(t, dir, "texts.json", texts))
	return mark, logo, overrides
}

func TestBranding(t *testing.T) {
	mark, logo, texts := brandFiles(t, `{"de": {"eyebrow": "Intern"}}`)
	cfg, err := load(t, `"hosts": {`, `"branding": {"name": "Example", "owner": "Example Ltd", "url": "https://example.com/", "mark_file": `+mark+`, "logo_file": `+logo+`, "texts_file": `+texts+`,
    "colors": {"brand": "#8B0000", "brand_strong": "#5a0000", "brand_dark": "#ff8080"}},
  "hosts": {`)
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Branding
	if b.Name != "Example" || b.Owner != "Example Ltd" || b.URL != "https://example.com/" || b.Colors.Brand != "#8b0000" {
		t.Errorf("branding %+v", b)
	}
	if b.Palette.Brand != "#8b0000" || b.Palette.OnBrand != "#ffffff" || !strings.Contains(b.Mark.Inline("mark", "m-"), `<circle cx="5" cy="5" r="5" fill="#8b0000"/>`) {
		t.Errorf("palette %+v or mark %s", b.Palette, b.Mark.Inline("mark", "m-"))
	}
	if b.Texts.T("de", "eyebrow") != "Intern" || b.Texts.T("en", "eyebrow") != "Secure Area" {
		t.Error("texts_file")
	}
}

func TestBrandingProblems(t *testing.T) {
	mark, logo, texts := brandFiles(t, `{"de": {"eyebrows": "Intern"}, "fr": {}}`)
	dir := t.TempDir()
	script := quote(write(t, dir, "script.svg", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><script>alert(1)</script></svg>`))
	notPNG := quote(write(t, dir, "logo.gif", "GIF89a"))
	cases := []struct{ branding, want string }{
		{`"name": "` + strings.Repeat("x", 41) + `"`, "branding.name"},
		{`"name": "a\nb"`, "branding.name"},
		{`"owner": "a\tb"`, "branding.owner"},
		{`"url": "https://example.com"`, "branding.url needs branding.owner"},
		{`"owner": "x", "url": "javascript:alert(1)"`, "branding.url must be an http or https URL"},
		{`"owner": "x", "url": "https://user@example.com"`, "branding.url must be an http or https URL"},
		{`"colors": {"brand": "red"}`, `branding.colors.brand "red" is not a colour`},
		{`"colors": {"brand_dark": "#fff"}`, `branding.colors.brand_dark "#fff"`},
		{`"mark_file": "/does/not/exist.svg"`, "branding.mark_file: open"},
		{`"mark_file": ` + script, "branding.mark_file: the element <script> is not allowed"},
		{`"mark_file": ` + logo, "branding.mark_file:"},
		{`"logo_file": ` + notPNG, "branding.logo_file: not a PNG file"},
		{`"logo_file": ` + mark, "branding.logo_file: not a PNG file"},
		{`"texts_file": ` + texts, "branding.texts_file: de.eyebrows is no text of gatekeeper"},
		{`"texts_file": ` + texts, `branding.texts_file: "fr" is none of`},
		{`"colour": "#000000"`, "unknown field"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			_, err := load(t, `"hosts": {`, `"branding": {`+c.branding+`}, "hosts": {`)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestAltcha(t *testing.T) {
	cfg, err := load(t, `"hosts": {`, `"altcha": {"url": "https://altcha.example.com:8443/base/", "site": "gate.example"}, "hosts": {`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Altcha.URL != "https://altcha.example.com:8443/base" || cfg.Altcha.Site != "gate.example" {
		t.Errorf("altcha %+v", cfg.Altcha)
	}
	_, err = load(t, `"hosts": {`, `"altcha": {"url": "https://altcha.example.com", "site": "gate"}, "hosts": {`, `["email", "zitadel"]`, `["zitadel"]`)
	if err == nil || !strings.Contains(err.Error(), `altcha is set, but no host signs in by "email"`) {
		t.Errorf("altcha without code by email: %v", err)
	}
}

func TestBounces(t *testing.T) {
	cfg, err := load(t, `"from_name": "Example"`, `"from_name": "Example", "bounces": {}`)
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Mail.Bounces
	if b.IMAPHost != "mail.example.com" || b.IMAPPort != 993 || b.Poll.D() != time.Minute || b.Suppress.D() != 48*time.Hour || b.DeleteOthers || b.ServerName != "mail.example.com" {
		t.Errorf("defaults %+v", b)
	}
	cfg, err = load(t, `"from_name": "Example"`, `"from_name": "Example", "server_name": "smtp.example.com", "bounces": {"poll": "30s", "suppress": "24h", "delete_others": true}`)
	if err != nil || cfg.Mail.Bounces.ServerName != "smtp.example.com" || cfg.Mail.Bounces.Poll.D() != 30*time.Second || !cfg.Mail.Bounces.DeleteOthers {
		t.Errorf("imap on mail.host: %+v, %v", cfg.Mail.Bounces, err)
	}
	cfg, err = load(t, `"from_name": "Example"`, `"from_name": "Example", "server_name": "smtp.example.com", "bounces": {"imap_host": "imap.example.com", "imap_port": 1993}`)
	if err != nil || cfg.Mail.Bounces.ServerName != "imap.example.com" || cfg.Mail.Bounces.IMAPPort != 1993 {
		t.Errorf("imap elsewhere: %+v, %v", cfg.Mail.Bounces, err)
	}

	cases := map[string][]string{
		"mail.bounces.poll":           {`"from_name": "Example"`, `"from_name": "Example", "bounces": {"poll": "5s"}`},
		"mail.bounces.suppress":       {`"from_name": "Example"`, `"from_name": "Example", "bounces": {"suppress": "800h"}`},
		"mail.bounces.imap_port":      {`"from_name": "Example"`, `"from_name": "Example", "bounces": {"imap_port": 70000}`},
		"mail.bounces needs":          {`"username": "gate@example.com",`, ``, `"from_name": "Example"`, `"from_name": "Example", "bounces": {}`},
		"at most 35 characters":       {`"from": "gate@example.com"`, `"from": "` + strings.Repeat("g", 36) + `@example.com"`, `"from_name": "Example"`, `"from_name": "Example", "bounces": {}`},
		`unknown field "imap_server"`: {`"from_name": "Example"`, `"from_name": "Example", "bounces": {"imap_server": "x"}`},
	}
	for want, replace := range cases {
		if _, err := load(t, replace...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v, want one containing %q", err, want)
		}
	}
	if _, err := load(t, `"from": "gate@example.com"`, `"from": "`+strings.Repeat("g", 35)+`@example.com"`, `"from_name": "Example"`, `"from_name": "Example", "bounces": {}`); err != nil {
		t.Errorf("35 characters: %v", err)
	}
}
