package i18n

import (
	"slices"
	"strings"
	"testing"
)

func TestEveryLanguageHasTheSameKeys(t *testing.T) {
	want := Keys("en")
	for _, lang := range Languages {
		if got := Keys(lang); !slices.Equal(got, want) {
			t.Errorf("%s has keys %v, want %v", lang, got, want)
		}
	}
	if len(texts) != len(Languages) {
		t.Errorf("texts.json has %d languages, Languages lists %d", len(texts), len(Languages))
	}
}

func TestEveryTextIsFilledAndKeepsItsPlaceholders(t *testing.T) {
	for _, key := range Keys("en") {
		placeholders := Placeholders(texts["en"][key])
		for _, lang := range Languages {
			text := texts[lang][key]
			if strings.TrimSpace(text) == "" {
				t.Errorf("%s/%s is empty", lang, key)
			}
			if got := Placeholders(text); !slices.Equal(got, placeholders) {
				t.Errorf("%s/%s has placeholders %v, want %v", lang, key, got, placeholders)
			}
		}
	}
}

func TestT(t *testing.T) {
	texts := NewCatalog(nil)
	if got := texts.T("en", "provider_button", "name", "Zitadel"); got != "Sign in with Zitadel" {
		t.Errorf("got %q", got)
	}
	if got := texts.T("ka", "provider_button", "name", "Zitadel"); got != "შესვლა Zitadel-ით" {
		t.Errorf("got %q", got)
	}
}

func TestOverrides(t *testing.T) {
	overrides, problems := ParseOverrides([]byte(`{"de": {"eyebrow": "Intern", "signin_title": "Anmelden"}, "en": {"provider_button": "Use {name}"}}`))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	texts := NewCatalog(overrides)
	if texts.T("de", "eyebrow") != "Intern" || texts.T("de", "signin_title", "name", "x") != "Anmelden" || texts.T("en", "provider_button", "name", "Zitadel") != "Use Zitadel" {
		t.Error("an override is not used")
	}
	if texts.T("en", "eyebrow") != "Secure Area" || texts.T("ru", "signin_title", "name", "Example") != "Вход · Example" {
		t.Error("a text without override changed")
	}

	cases := map[string]string{
		`{"fr": {"eyebrow": "x"}}`:                                 `"fr" is none of`,
		`{"de": {"eyebrows": "x"}}`:                                "de.eyebrows is no text",
		`{"de": {"eyebrow": ""}}`:                                  "de.eyebrow must be printable",
		`{"de": {"eyebrow": "a\nb"}}`:                              "de.eyebrow must be printable",
		`{"de": {"eyebrow": "{name}"}}`:                            "{name} is none of the placeholders []",
		`{"en": {"code_lead": "{minute} left"}}`:                   "{minute} is none of the placeholders [{minutes}]",
		`{"de": {"eyebrow": 1}}`:                                   "an object of languages",
		`["eyebrow"]`:                                              "an object of languages",
		`{"de": {"eyebrow": "` + strings.Repeat("x", 1001) + `"}}`: "at most 1000 bytes",
	}
	for input, want := range cases {
		if _, problems := ParseOverrides([]byte(input)); len(problems) == 0 || !strings.Contains(strings.Join(problems, "; "), want) {
			t.Errorf("%s: problems %v, want one containing %q", input, problems, want)
		}
	}
}

func TestMinutes(t *testing.T) {
	cases := map[string]string{
		"de/1": "1 Minute", "de/10": "10 Minuten",
		"en/1": "1 minute", "en/10": "10 minutes",
		"ru/1": "1 минуту", "ru/2": "2 минуты", "ru/5": "5 минут", "ru/11": "11 минут", "ru/12": "12 минут", "ru/21": "21 минуту", "ru/22": "22 минуты",
		"ka/10": "10 წუთის განმავლობაში",
	}
	for input, want := range cases {
		lang, n, _ := strings.Cut(input, "/")
		count := 0
		for _, c := range n {
			count = count*10 + int(c-'0')
		}
		if got := Minutes(lang, count); got != want {
			t.Errorf("Minutes(%s, %d) = %q, want %q", lang, count, got, want)
		}
	}
}

func TestNegotiate(t *testing.T) {
	cases := []struct{ chosen, accept, want string }{
		{"ru", "de-DE,de;q=0.9", "ru"},
		{"xx", "de-DE,de;q=0.9,en;q=0.8", "de"},
		{"", "fr-FR,fr;q=0.9,en-US;q=0.8,ka;q=0.7", "en"},
		{"", "fr, ka;q=0.5", "ka"},
		{"", "fr", "en"},
		{"", "", "de"},
		{"", "en;q=0, ru", "ru"},
	}
	for _, c := range cases {
		fallback := "en"
		if c.want == "de" && c.accept == "" {
			fallback = "de"
		}
		if got := Negotiate(c.chosen, c.accept, fallback); got != c.want {
			t.Errorf("Negotiate(%q, %q) = %q, want %q", c.chosen, c.accept, got, c.want)
		}
	}
}
