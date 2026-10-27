package brand

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const svgNamespace = "http://www.w3.org/2000/svg"

// The mark is inlined into every page twice and once more as the favicon.
const MaxMarkBytes = 32 << 10

const (
	maxDepth    = 32
	maxElements = 2000
)

var (
	// Paths, basic shapes, groups and gradients with the attributes they need - anything else stops the start.
	elements = map[string][]string{
		"svg":            {"viewBox", "preserveAspectRatio", "width", "height"},
		"g":              nil,
		"defs":           nil,
		"clipPath":       {"clipPathUnits"},
		"path":           {"d", "pathLength"},
		"rect":           {"x", "y", "width", "height", "rx", "ry"},
		"circle":         {"cx", "cy", "r"},
		"ellipse":        {"cx", "cy", "rx", "ry"},
		"line":           {"x1", "y1", "x2", "y2"},
		"polyline":       {"points"},
		"polygon":        {"points"},
		"linearGradient": {"x1", "y1", "x2", "y2", "gradientUnits", "gradientTransform", "spreadMethod"},
		"radialGradient": {"cx", "cy", "r", "fx", "fy", "fr", "gradientUnits", "gradientTransform", "spreadMethod"},
		"stop":           {"offset", "stop-color", "stop-opacity"},
	}
	presentation = []string{"id", "transform", "fill", "fill-opacity", "fill-rule", "stroke", "stroke-width",
		"stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-dasharray", "stroke-dashoffset",
		"stroke-opacity", "opacity", "clip-path", "clip-rule", "color", "display", "visibility", "shape-rendering",
		"vector-effect", "paint-order"}
	// Only these point to another element, and only to one of the mark itself.
	pointers = []string{"fill", "stroke", "clip-path"}
	// Colours and transforms; no expression(), var() or anything else a browser might evaluate.
	functions = []string{"url", "rgb", "rgba", "hsl", "hsla", "matrix", "translate", "scale", "rotate", "skewx", "skewy"}

	// No ':', '/', quotes or angle brackets: no scheme, no path and nothing that leaves the attribute.
	valuePattern    = regexp.MustCompile(`^[A-Za-z0-9 \t\r\n.,#()%+_-]*$`)
	idPattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	pointerPattern  = regexp.MustCompile(`url\(#([A-Za-z_][A-Za-z0-9_.-]{0,63})\)`)
	functionPattern = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_-]*)\s*\(`)
	numberPattern   = regexp.MustCompile(`^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
	escaper         = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;")
)

//go:embed mark.svg
var defaultMark []byte

// Default is the neutral mark: shield-lock of Bootstrap Icons on a rounded square.
var Default = mustParseMark(defaultMark)

// Mark is an SVG that passed the allowlist. It is written out anew, never passed on as it came.
type Mark struct {
	root *element
}

type element struct {
	name     string
	attrs    []xml.Attr
	children []*element
}

func mustParseMark(data []byte) *Mark {
	m, err := ParseMark(data)
	if err != nil {
		panic("brand: mark.svg: " + err.Error())
	}
	return m
}

func ParseMark(data []byte) (*Mark, error) {
	if len(data) > MaxMarkBytes {
		return nil, fmt.Errorf("%d bytes, at most %d are allowed", len(data), MaxMarkBytes)
	}
	decoder := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	var root *element
	var open []*element
	ids := map[string]bool{}
	var targets []string
	count := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if root != nil && len(open) == 0 {
				return nil, errors.New("there is more than one root element")
			}
			if count++; count > maxElements || len(open) >= maxDepth {
				return nil, fmt.Errorf("more than %d elements or %d levels", maxElements, maxDepth)
			}
			e, err := newElement(t, root == nil)
			if err != nil {
				return nil, err
			}
			for _, a := range e.attrs {
				if a.Name.Local == "id" {
					if ids[a.Value] {
						return nil, fmt.Errorf("the id %q is used twice", a.Value)
					}
					ids[a.Value] = true
				}
				for _, match := range pointerPattern.FindAllStringSubmatch(a.Value, -1) {
					targets = append(targets, match[1])
				}
			}
			if root == nil {
				root = e
			} else {
				parent := open[len(open)-1]
				parent.children = append(parent.children, e)
			}
			open = append(open, e)
		case xml.EndElement:
			open = open[:len(open)-1]
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return nil, errors.New("text is not allowed")
			}
		case xml.ProcInst:
			if t.Target != "xml" || root != nil {
				return nil, fmt.Errorf("the processing instruction <?%s?> is not allowed", t.Target)
			}
		case xml.Directive:
			return nil, errors.New("declarations like <!DOCTYPE> are not allowed")
		}
	}
	if root == nil {
		return nil, errors.New("there is no svg element")
	}
	for _, target := range targets {
		if !ids[target] {
			return nil, fmt.Errorf("url(#%s) points to no element of the mark", target)
		}
	}
	return &Mark{root: root}, nil
}

func newElement(t xml.StartElement, root bool) (*element, error) {
	name := t.Name.Local
	allowed, known := elements[name]
	switch {
	case root && (name != "svg" || t.Name.Space != svgNamespace):
		return nil, fmt.Errorf(`the file must start with <svg xmlns="%s">`, svgNamespace)
	case t.Name.Space != svgNamespace:
		return nil, fmt.Errorf("the element <%s> of the namespace %q is not allowed", name, t.Name.Space)
	case !known || (name == "svg") != root:
		return nil, fmt.Errorf("the element <%s> is not allowed", name)
	}
	e := &element{name: name}
	for _, a := range t.Attr {
		if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
			continue
		}
		if a.Name.Space != "" {
			return nil, fmt.Errorf("the attribute %s of the namespace %q is not allowed on <%s>", a.Name.Local, a.Name.Space, name)
		}
		if !slices.Contains(allowed, a.Name.Local) && !slices.Contains(presentation, a.Name.Local) {
			return nil, fmt.Errorf("the attribute %s is not allowed on <%s>", a.Name.Local, name)
		}
		if err := checkValue(a.Name.Local, a.Value); err != nil {
			return nil, fmt.Errorf("<%s %s>: %w", name, a.Name.Local, err)
		}
		e.attrs = append(e.attrs, xml.Attr{Name: xml.Name{Local: a.Name.Local}, Value: a.Value})
	}
	if root && !validViewBox(e.attr("viewBox")) {
		return nil, errors.New("the svg element needs a viewBox of four numbers with a positive width and height")
	}
	return e, nil
}

func checkValue(name, value string) error {
	if !valuePattern.MatchString(value) {
		return errors.New("a value may hold only letters, digits, white space and . , # ( ) % + _ -")
	}
	if name == "id" && !idPattern.MatchString(value) {
		return errors.New("an id starts with a letter or '_' and has at most 64 letters, digits, '_', '.' and '-'")
	}
	for _, match := range functionPattern.FindAllStringSubmatch(value, -1) {
		if !slices.Contains(functions, strings.ToLower(match[1])) {
			return fmt.Errorf("%s() is not allowed - only colours, transforms and url(#id)", match[1])
		}
	}
	rest := strings.ToLower(pointerPattern.ReplaceAllString(value, ""))
	if strings.Contains(rest, "url(") || (pointerPattern.MatchString(value) && !slices.Contains(pointers, name)) {
		return errors.New("only fill, stroke and clip-path point to an element, as url(#id)")
	}
	return nil
}

func validViewBox(value string) bool {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n' })
	if len(fields) != 4 {
		return false
	}
	var numbers [4]float64
	for i, field := range fields {
		n, err := strconv.ParseFloat(field, 64)
		if !numberPattern.MatchString(field) || err != nil {
			return false
		}
		numbers[i] = n
	}
	return numbers[2] > 0 && numbers[3] > 0
}

func (e *element) attr(name string) string {
	for _, a := range e.attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Inline is the mark for a page. Every id carries the prefix, so two copies on one page do not collide.
func (m *Mark) Inline(class, prefix string) string {
	var b strings.Builder
	b.WriteString(`<svg class="` + escaper.Replace(class) + `" aria-hidden="true" focusable="false"`)
	m.root.write(&b, prefix, true)
	return b.String()
}

// Document is the mark as a file of its own, for the favicon.
func (m *Mark) Document() string {
	var b strings.Builder
	b.WriteString(`<svg xmlns="` + svgNamespace + `"`)
	m.root.write(&b, "", true)
	return b.String()
}

// write leaves out width and height of the root: the page sizes the mark, the viewBox keeps its proportions.
func (e *element) write(b *strings.Builder, prefix string, root bool) {
	if !root {
		b.WriteString("<" + e.name)
	}
	for _, a := range e.attrs {
		name, value := a.Name.Local, a.Value
		switch {
		case root && (name == "width" || name == "height"):
			continue
		case name == "id":
			value = prefix + value
		default:
			value = pointerPattern.ReplaceAllString(value, "url(#"+prefix+"${1})")
		}
		b.WriteString(" " + name + `="` + escaper.Replace(value) + `"`)
	}
	if !root && len(e.children) == 0 {
		b.WriteString("/>")
		return
	}
	b.WriteString(">")
	for _, child := range e.children {
		child.write(b, prefix, false)
	}
	b.WriteString("</" + e.name + ">")
}
