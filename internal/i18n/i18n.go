package i18n

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Order of the language links on every page.
var Languages = []string{"de", "en", "ru", "ka"}

//go:embed texts.json
var textsJSON []byte

var texts map[string]map[string]string

func init() {
	if err := json.Unmarshal(textsJSON, &texts); err != nil {
		panic(fmt.Sprintf("i18n: texts.json: %v", err))
	}
}

func Supported(lang string) bool {
	for _, l := range Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// Catalog is texts.json with the overrides of a texts_file.
type Catalog struct {
	overrides map[string]map[string]string
}

// NewCatalog takes overrides that passed ParseOverrides; nil keeps every built-in text.
func NewCatalog(overrides map[string]map[string]string) *Catalog {
	return &Catalog{overrides: overrides}
}

// T replaces the {placeholders} given as name, value pairs.
func (c *Catalog) T(lang, key string, pairs ...string) string {
	text, ok := c.overrides[lang][key]
	if !ok {
		text, ok = texts[lang][key]
	}
	if !ok {
		panic(fmt.Sprintf("i18n: no text %q for %q", key, lang))
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		text = strings.ReplaceAll(text, "{"+pairs[i]+"}", pairs[i+1])
	}
	return text
}

// ParseOverrides reads a texts_file: per language only keys of texts.json, and no placeholder the built-in text lacks.
func ParseOverrides(data []byte) (map[string]map[string]string, []string) {
	var overrides map[string]map[string]string
	if err := json.Unmarshal(data, &overrides); err != nil {
		return nil, []string{"an object of languages with an object of texts each: " + err.Error()}
	}
	var problems []string
	for lang, entries := range overrides {
		if !Supported(lang) {
			problems = append(problems, fmt.Sprintf("%q is none of %v", lang, Languages))
			continue
		}
		for key, text := range entries {
			builtIn, known := texts[lang][key]
			switch {
			case !known:
				problems = append(problems, fmt.Sprintf("%s.%s is no text of gatekeeper", lang, key))
			case strings.TrimSpace(text) == "" || len(text) > 1000 || strings.ContainsFunc(text, func(r rune) bool { return r < 0x20 || r == 0x7f }):
				problems = append(problems, fmt.Sprintf("%s.%s must be printable, on one line and at most 1000 bytes", lang, key))
			default:
				allowed := Placeholders(builtIn)
				for _, placeholder := range Placeholders(text) {
					if !slices.Contains(allowed, placeholder) {
						problems = append(problems, fmt.Sprintf("%s.%s: %s is none of the placeholders %v", lang, key, placeholder, allowed))
					}
				}
			}
		}
	}
	sort.Strings(problems)
	return overrides, problems
}

// Placeholders lists the {names} of a text, sorted.
func Placeholders(text string) []string {
	var found []string
	for {
		start := strings.IndexByte(text, '{')
		if start < 0 {
			break
		}
		end := strings.IndexByte(text[start:], '}')
		if end < 0 {
			break
		}
		found = append(found, text[start:start+end+1])
		text = text[start+end+1:]
	}
	slices.Sort(found)
	return found
}

func Keys(lang string) []string {
	keys := make([]string, 0, len(texts[lang]))
	for key := range texts[lang] {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Minutes fits into the {minutes} of code_lead and mail_lead, so it carries the case each language needs there.
func Minutes(lang string, n int) string {
	switch lang {
	case "de":
		if n == 1 {
			return "1 Minute"
		}
		return strconv.Itoa(n) + " Minuten"
	case "ru":
		word := "минут"
		switch {
		case n%10 == 1 && n%100 != 11:
			word = "минуту"
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			word = "минуты"
		}
		return strconv.Itoa(n) + " " + word
	case "ka":
		return strconv.Itoa(n) + " წუთის განმავლობაში"
	default:
		if n == 1 {
			return "1 minute"
		}
		return strconv.Itoa(n) + " minutes"
	}
}

// Negotiate prefers an explicit choice, then the best supported entry of Accept-Language.
func Negotiate(chosen, acceptLanguage, fallback string) string {
	if Supported(chosen) {
		return chosen
	}
	best, bestQuality := "", 0.0
	for _, entry := range strings.Split(acceptLanguage, ",") {
		parts := strings.Split(entry, ";")
		lang := strings.ToLower(strings.TrimSpace(parts[0]))
		if i := strings.IndexByte(lang, '-'); i > 0 {
			lang = lang[:i]
		}
		quality := 1.0
		for _, param := range parts[1:] {
			param = strings.TrimSpace(param)
			if strings.HasPrefix(param, "q=") {
				if q, err := strconv.ParseFloat(param[2:], 64); err == nil {
					quality = q
				}
			}
		}
		if Supported(lang) && quality > bestQuality {
			best, bestQuality = lang, quality
		}
	}
	if best != "" {
		return best
	}
	return fallback
}
