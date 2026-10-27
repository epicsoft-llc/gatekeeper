package brand

import (
	"regexp"
	"strings"
	"testing"
)

const head = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">`

func TestDefaultMark(t *testing.T) {
	inline := Default.Inline("mark", "gatekeeper-mark-")
	for _, want := range []string{`<svg class="mark" aria-hidden="true" focusable="false" viewBox="0 0 16 16">`, `id="gatekeeper-mark-mark"`, `fill="url(#gatekeeper-mark-mark)"`, `<path d="M5.338 1.59`} {
		if !strings.Contains(inline, want) {
			t.Errorf("inline mark lacks %q: %s", want, inline)
		}
	}
	if strings.Contains(inline, "xmlns") || strings.Contains(inline, "<!--") {
		t.Errorf("inline mark: %s", inline)
	}
	if document := Default.Document(); !strings.HasPrefix(document, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">`) || !strings.Contains(document, `id="mark"`) {
		t.Errorf("document: %s", document)
	}
}

func TestMarkKeepsWhatIsAllowed(t *testing.T) {
	source := `<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="64" height="32" viewBox="0,0,64,32" fill="none">
  <defs>
    <radialGradient id="g.1" cx="50%" cy="50%" r="50%" gradientTransform="rotate(45 .5 .5)"><stop offset="0" stop-color="rgb(4, 169, 243)"/><stop offset="1" stop-color="#0270A8" stop-opacity=".5"/></radialGradient>
    <clipPath id="c"><circle cx="16" cy="16" r="16"/></clipPath>
  </defs>
  <g clip-path="url(#c)" transform="translate(1 2) scale(.5)">
    <rect x="1" y="1" width="30" height="30" rx="4" fill="url(#g.1)" stroke="url(#g.1)"/>
    <polygon points="1,2 3,4 5,6" fill-rule="evenodd"/>
    <polyline points="1 2 3 4"/><line x1="0" y1="0" x2="1" y2="1" stroke-linecap="round"/><ellipse cx="1" cy="1" rx="1" ry="2"/>
    <path d="M1 1L2 2z" stroke-width="1.5e-1" opacity=".8"/>
  </g>
</svg>`
	m, err := ParseMark([]byte("\xef\xbb\xbf" + source))
	if err != nil {
		t.Fatal(err)
	}
	inline := m.Inline("backdrop", "p-")
	for _, want := range []string{`viewBox="0,0,64,32" fill="none">`, `id="p-g.1"`, `clip-path="url(#p-c)"`, `fill="url(#p-g.1)" stroke="url(#p-g.1)"`, `<stop offset="0" stop-color="rgb(4, 169, 243)"/>`} {
		if !strings.Contains(inline, want) {
			t.Errorf("inline mark lacks %q: %s", want, inline)
		}
	}
	if strings.Contains(inline, "width=\"64\"") || strings.Contains(inline, "xlink") {
		t.Errorf("inline mark keeps the size or a namespace: %s", inline)
	}
	again, err := ParseMark([]byte(m.Document()))
	if err != nil || again.Document() != m.Document() {
		t.Errorf("the document does not parse to itself: %v\n%s\n%s", err, m.Document(), again.Document())
	}
}

func TestMarkRefuses(t *testing.T) {
	cases := []struct{ name, svg, want string }{
		{"script", head + `<script>alert(1)</script></svg>`, "<script> is not allowed"},
		{"foreign object", head + `<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject></svg>`, "<foreignObject> is not allowed"},
		{"event handler", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" onload="alert(1)"/>`, "onload is not allowed"},
		{"event handler on a shape", head + `<rect width="1" height="1" onclick="x()"/></svg>`, "onclick is not allowed"},
		{"style attribute", head + `<path d="M0 0" style="fill:red"/></svg>`, "style is not allowed"},
		{"style element", head + `<style>path{fill:red}</style></svg>`, "<style> is not allowed"},
		{"external url", head + `<path d="M0 0" fill="url(https://evil.example.net/x.svg#a)"/></svg>`, "a value may hold only"},
		{"pointer to nothing", head + `<path d="M0 0" fill="url(#missing)"/></svg>`, "points to no element"},
		{"pointer in another attribute", head + `<defs><linearGradient id="a"/></defs><path d="M0 0" transform="url(#a)"/></svg>`, "only fill, stroke and clip-path"},
		{"pointer in capitals", head + `<defs><linearGradient id="a"/></defs><path d="M0 0" fill="URL(#a)"/></svg>`, "only fill, stroke and clip-path"},
		{"expression", head + `<path d="M0 0" fill="expression(alert(1))"/></svg>`, "expression() is not allowed"},
		{"css variable", head + `<path d="M0 0" fill="var(--x)"/></svg>`, "var() is not allowed"},
		{"use", head + `<defs><path id="a" d="M0 0"/></defs><use href="#a"/></svg>`, "<use> is not allowed"},
		{"xlink href", head + `<defs><linearGradient id="a"/><linearGradient id="b" xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#a"/></defs></svg>`, "href of the namespace"},
		{"plain href", head + `<defs><linearGradient id="a"/><linearGradient id="b" href="#a"/></defs></svg>`, "href is not allowed"},
		{"image", head + `<image href="https://evil.example.net/x.png" width="1" height="1"/></svg>`, "<image> is not allowed"},
		{"link", head + `<a href="https://evil.example.net/"><path d="M0 0"/></a></svg>`, "<a> is not allowed"},
		{"animation", head + `<path d="M0 0"><set attributeName="fill" to="red"/></path></svg>`, "<set> is not allowed"},
		{"animate", head + `<path d="M0 0"><animate attributeName="d" to="M1 1"/></path></svg>`, "<animate> is not allowed"},
		{"filter", head + `<filter id="f"/></svg>`, "<filter> is not allowed"},
		{"mask", head + `<mask id="m"/></svg>`, "<mask> is not allowed"},
		{"text", head + `<text>hello</text></svg>`, "<text> is not allowed"},
		{"loose text", head + `<g>hello</g></svg>`, "text is not allowed"},
		{"cdata", head + `<g><![CDATA[alert(1)]]></g></svg>`, "text is not allowed"},
		{"doctype", `<!DOCTYPE svg [<!ENTITY x "y">]>` + head + `</svg>`, "<!DOCTYPE>"},
		{"entity", head + `<path d="&x;"/></svg>`, "invalid character entity"},
		{"stylesheet instruction", `<?xml-stylesheet href="https://evil.example.net/x.css"?>` + head + `</svg>`, "<?xml-stylesheet?>"},
		{"html root", `<html xmlns="http://www.w3.org/1999/xhtml"></html>`, "must start with <svg"},
		{"no namespace", `<svg viewBox="0 0 16 16"></svg>`, "must start with <svg"},
		{"other namespace", head + `<sodipodi:namedview xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"/></svg>`, "of the namespace"},
		{"namespaced attribute", head + `<path d="M0 0" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" inkscape:label="x"/></svg>`, "label of the namespace"},
		{"nested svg", head + `<svg viewBox="0 0 1 1"/></svg>`, "<svg> is not allowed"},
		{"no viewBox", `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"/>`, "viewBox"},
		{"empty viewBox", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 0 16"/>`, "viewBox"},
		{"short viewBox", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16"/>`, "viewBox"},
		{"hex viewBox", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 0x10 16"/>`, "viewBox"},
		{"duplicate id", head + `<g id="a"/><g id="a"/></svg>`, "used twice"},
		{"bad id", head + `<g id="1a"/></svg>`, "an id starts with"},
		{"quote", head + `<path d="M0 0" fill="&quot;"/></svg>`, "a value may hold only"},
		{"angle bracket", head + `<path d="M0 0" fill="&lt;script&gt;"/></svg>`, "a value may hold only"},
		{"scheme", head + `<path d="M0 0" fill="javascript:alert(1)"/></svg>`, "a value may hold only"},
		{"two roots", head + `</svg>` + head + `</svg>`, "more than one root"},
		{"unclosed", head + `<g>`, "unexpected EOF"},
		{"empty", ``, "no svg element"},
		{"too deep", head + strings.Repeat("<g>", 40) + strings.Repeat("</g>", 40) + `</svg>`, "levels"},
		{"too large", head + `<path d="` + strings.Repeat("M0 0", MaxMarkBytes/4) + `"/></svg>`, "at most"},
		{"latin-1", `<?xml version="1.0" encoding="ISO-8859-1"?>` + head + `</svg>`, "CharsetReader"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseMark([]byte(c.svg))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v, want one containing %q", err, c.want)
			}
		})
	}
}

var (
	unsafeOutput = regexp.MustCompile(`(?i)<script|<style|<foreignobject|<use|<image|<a[\s>]|\sstyle=|\son[a-z]+=|href|javascript|expression|@import|<!`)
	pointerOut   = regexp.MustCompile(`url\(`)
)

func FuzzMark(f *testing.F) {
	f.Add(string(defaultMark))
	f.Add(head + `<defs><linearGradient id="a"><stop offset="0" stop-color="#fff"/></linearGradient></defs><rect width="16" height="16" fill="url(#a)"/></svg>`)
	f.Add(head + `<g clip-path="url(#c)"><clipPath id="c"><circle r="1"/></clipPath></g></svg>`)
	f.Add(head + `<path d="M0 0" fill="url(https://x/)" onload="x"/></svg>`)
	f.Fuzz(func(t *testing.T, input string) {
		m, err := ParseMark([]byte(input))
		if err != nil {
			return
		}
		inline := m.Inline("mark", "p-")
		if found := unsafeOutput.FindString(inline); found != "" {
			t.Errorf("%q passed and wrote %q: %s", input, found, inline)
		}
		if strings.Count(inline, "url(") != strings.Count(inline, "url(#p-") || len(pointerOut.FindAllString(inline, -1)) != strings.Count(inline, "url(#p-") {
			t.Errorf("a pointer leaves the mark: %s", inline)
		}
		if strings.ContainsAny(strings.NewReplacer("</", "<", "/>", ">").Replace(inline), ":/") {
			t.Errorf("the inline mark holds ':' or '/': %s", inline)
		}
		again, err := ParseMark([]byte(m.Document()))
		if err != nil || again.Document() != m.Document() {
			t.Errorf("%q: the document does not parse to itself: %v", input, err)
		}
	})
}
