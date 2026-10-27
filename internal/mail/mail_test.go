package mail

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/bounce"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/brand"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

var now = time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)

func neutral() *config.Branding {
	return &config.Branding{Name: "Gatekeeper", Logo: brand.DefaultLogo, Palette: brand.DefaultPalette, Texts: i18n.NewCatalog(nil)}
}

func TestBuild(t *testing.T) {
	texts := i18n.NewCatalog(nil)
	for _, lang := range i18n.Languages {
		t.Run(lang, func(t *testing.T) {
			raw, err := Build(Code{To: "reader@example.org", Host: "report.example.com", Lang: lang, Code: "12345678", TTL: 10 * time.Minute}, neutral(), "gate@example.com", "Example", now)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := mail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			from, err := mail.ParseAddress(msg.Header.Get("From"))
			if err != nil || from.Address != "gate@example.com" || from.Name != "Example" {
				t.Errorf("From %q", msg.Header.Get("From"))
			}
			if msg.Header.Get("To") != "<reader@example.org>" || msg.Header.Get("Auto-Submitted") != "auto-generated" {
				t.Errorf("To %q, Auto-Submitted %q", msg.Header.Get("To"), msg.Header.Get("Auto-Submitted"))
			}
			subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
			if err != nil || subject != texts.T(lang, "mail_subject") {
				t.Errorf("Subject %q", subject)
			}
			if !strings.HasSuffix(msg.Header.Get("Message-Id"), "@example.com>") {
				t.Errorf("Message-Id %q", msg.Header.Get("Message-Id"))
			}

			_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
			if err != nil {
				t.Fatal(err)
			}
			parts := multipart.NewReader(msg.Body, params["boundary"])
			text := readPart(t, parts, "text/plain; charset=utf-8")
			for _, want := range []string{"1234 5678", i18n.Minutes(lang, 10)} {
				if !strings.Contains(text, want) {
					t.Errorf("text part lacks %q", want)
				}
			}
			related, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			_, relatedParams, _ := mime.ParseMediaType(related.Header.Get("Content-Type"))
			inner := multipart.NewReader(related, relatedParams["boundary"])
			html := readPart(t, inner, "text/html; charset=utf-8")
			for _, want := range []string{"1234 5678", `src="cid:logo@gatekeeper"`, `lang="` + lang + `"`, ">Gatekeeper</td>", `width="42" height="42"`, "color:#0270a8", `bgcolor="#e6f6fe"`, "color:#6fd0fb !important"} {
				if !strings.Contains(html, want) {
					t.Errorf("html part lacks %q", want)
				}
			}
			if strings.Contains(html+text, "{") && strings.Contains(html+text, "{minutes}") {
				t.Error("a placeholder is left")
			}
			image, err := inner.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			if image.Header.Get("Content-Id") != "<logo@gatekeeper>" {
				t.Errorf("Content-Id %q", image.Header.Get("Content-Id"))
			}
			encoded, _ := io.ReadAll(image)
			decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(encoded), "\r\n", ""))
			if err != nil || !bytes.Equal(decoded, brand.DefaultLogo.PNG) {
				t.Error("the logo does not decode")
			}
			if strings.Contains(string(raw), "report.example.com") {
				t.Error("the mail names the host")
			}
			if strings.Contains(html+text, "epicsoft") || strings.Contains(html, `style="padding:22px 0 0`) {
				t.Error("the neutral mail carries a brand or an empty footer")
			}
			for _, line := range strings.Split(string(raw), "\r\n") {
				if len(line) > 998 {
					t.Errorf("line of %d bytes", len(line))
				}
			}
		})
	}
}

func TestBuildWithLink(t *testing.T) {
	texts := i18n.NewCatalog(nil)
	link := "https://report.example.com/_gatekeeper/code?lang=de&rd=%2Freports%2F&t=ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for _, lang := range i18n.Languages {
		raw, err := Build(Code{To: "reader@example.org", Host: "report.example.com", Lang: lang, Code: "12345678", TTL: 10 * time.Minute, Link: link}, neutral(), "gate@example.com", "Example", now)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
		parts := multipart.NewReader(msg.Body, params["boundary"])
		text := readPart(t, parts, "text/plain; charset=utf-8")
		related, err := parts.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		_, relatedParams, _ := mime.ParseMediaType(related.Header.Get("Content-Type"))
		html := readPart(t, multipart.NewReader(related, relatedParams["boundary"]), "text/html; charset=utf-8")
		for _, want := range []string{link, texts.T(lang, "mail_link"), texts.T(lang, "mail_link_hint"), "1234 5678"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: text part lacks %q", lang, want)
			}
		}
		for _, want := range []string{`href="` + strings.ReplaceAll(link, "&", "&amp;") + `"`, ">" + texts.T(lang, "mail_link") + "</a>", "background:#04a9f3"} {
			if !strings.Contains(html, want) {
				t.Errorf("%s: html part lacks %q", lang, want)
			}
		}
	}
}

func readPart(t *testing.T, r *multipart.Reader, contentType string) string {
	t.Helper()
	part, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if got := part.Header.Get("Content-Type"); got != contentType {
		t.Fatalf("Content-Type %q, want %q", got, contentType)
	}
	// The reader decodes quoted-printable itself; decoding again would turn "=de" of a link into a byte.
	body, err := io.ReadAll(part)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestBuildRefusesLineBreaks(t *testing.T) {
	cases := []Code{
		{To: "a@example.com\r\nBcc: b@example.com", Host: "h.example.com", Lang: "en", Code: "12345678", TTL: time.Minute},
		{To: "a@example.com", Host: "h.example.com\nX: y", Lang: "en", Code: "12345678", TTL: time.Minute},
	}
	for _, c := range cases {
		if _, err := Build(c, neutral(), "gate@example.com", "Example", now); err == nil {
			t.Errorf("built a mail for %q / %q", c.To, c.Host)
		}
	}
	if _, err := Build(Code{To: "a@example.com", Host: "h.example.com", Lang: "fr", Code: "12345678", TTL: time.Minute}, neutral(), "gate@example.com", "", now); err == nil {
		t.Error("built a mail in an unsupported language")
	}
}

type received struct {
	tls  bool
	auth string
	from string
	to   []string
	data string
}

type fakeServer struct {
	addr     string
	starttls bool
	mu       sync.Mutex
	got      []received
	sessions []received
}

func certificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func startServer(t *testing.T, cert tls.Certificate, starttls, implicit bool) *fakeServer {
	t.Helper()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	var ln net.Listener
	var err error
	if implicit {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeServer{addr: ln.Addr().String(), starttls: starttls}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, tlsConfig, implicit)
		}
	}()
	return s
}

func (s *fakeServer) serve(conn net.Conn, tlsConfig *tls.Config, implicit bool) {
	defer conn.Close()
	state := received{tls: implicit}
	defer func() {
		s.mu.Lock()
		s.sessions = append(s.sessions, state)
		s.mu.Unlock()
	}()
	tp := textproto.NewConn(conn)
	tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, argument, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			tp.PrintfLine("250-fake")
			if s.starttls && !state.tls {
				tp.PrintfLine("250-STARTTLS")
			}
			tp.PrintfLine("250 AUTH PLAIN")
		case "STARTTLS":
			tp.PrintfLine("220 go ahead")
			secure := tls.Server(conn, tlsConfig)
			if err := secure.Handshake(); err != nil {
				return
			}
			conn, tp, state.tls = secure, textproto.NewConn(secure), true
		case "AUTH":
			_, initial, _ := strings.Cut(argument, " ")
			decoded, _ := base64.StdEncoding.DecodeString(initial)
			state.auth = string(decoded)
			tp.PrintfLine("235 ok")
		case "MAIL":
			state.from = strings.Trim(strings.TrimPrefix(argument, "FROM:"), "<>")
			tp.PrintfLine("250 ok")
		case "RCPT":
			state.to = append(state.to, strings.Trim(strings.TrimPrefix(argument, "TO:"), "<>"))
			tp.PrintfLine("250 ok")
		case "DATA":
			tp.PrintfLine("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			state.data = string(data)
			s.mu.Lock()
			s.got = append(s.got, state)
			s.mu.Unlock()
			tp.PrintfLine("250 queued")
		case "QUIT":
			tp.PrintfLine("221 bye")
			return
		default:
			tp.PrintfLine("502 not implemented")
		}
	}
}

func (s *fakeServer) result() ([]received, []received) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.got...), append([]received(nil), s.sessions...)
}

func senderFor(t *testing.T, s *fakeServer, mode, serverName, username string, pool *x509.CertPool) *Sender {
	t.Helper()
	host, port, _ := net.SplitHostPort(s.addr)
	portNumber, _ := strconv.Atoi(port)
	cfg := &config.Mail{Host: host, Port: portNumber, TLS: mode, ServerName: serverName, Username: username, Password: "secret"}
	sender := NewSender(cfg)
	sender.RootCAs = pool
	return sender
}

func TestSendWithSTARTTLS(t *testing.T) {
	cert, pool := certificate(t, "mail.example.test")
	server := startServer(t, cert, true, false)
	sender := senderFor(t, server, "starttls", "mail.example.test", "gate@example.com", pool)
	if err := sender.Send(context.Background(), "gate@example.com", "reader@example.org", []byte("Subject: x\r\n\r\nhello\r\n.dot\r\n")); err != nil {
		t.Fatal(err)
	}
	got, _ := waitFor(server, 1)
	if len(got) != 1 {
		t.Fatalf("%d mails received", len(got))
	}
	m := got[0]
	if !m.tls || m.auth != "\x00gate@example.com\x00secret" || m.from != "gate@example.com" || len(m.to) != 1 || m.to[0] != "reader@example.org" {
		t.Errorf("received %+v", m)
	}
	if !strings.Contains(m.data, "hello\n.dot") {
		t.Errorf("data %q", m.data)
	}
}

func TestSendRefusesWithoutSTARTTLS(t *testing.T) {
	cert, pool := certificate(t, "mail.example.test")
	server := startServer(t, cert, false, false)
	sender := senderFor(t, server, "starttls", "mail.example.test", "gate@example.com", pool)
	err := sender.Send(context.Background(), "gate@example.com", "reader@example.org", []byte("x\r\n"))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("got %v", err)
	}
	got, sessions := waitFor(server, 0)
	if len(got) != 0 || len(sessions) != 1 || sessions[0].auth != "" {
		t.Errorf("the password or the mail went out without TLS: %+v", sessions)
	}
}

func TestSendRefusesAWrongCertificate(t *testing.T) {
	cert, pool := certificate(t, "other.example.test")
	server := startServer(t, cert, true, false)
	sender := senderFor(t, server, "starttls", "mail.example.test", "gate@example.com", pool)
	if err := sender.Send(context.Background(), "gate@example.com", "reader@example.org", []byte("x\r\n")); err == nil {
		t.Fatal("sent with a certificate for another name")
	}
	got, sessions := waitFor(server, 0)
	if len(got) != 0 || (len(sessions) > 0 && sessions[0].auth != "") {
		t.Errorf("credentials or mail went to a server with a wrong certificate: %+v", sessions)
	}
}

func TestSendWithImplicitTLS(t *testing.T) {
	cert, pool := certificate(t, "mail.example.test")
	server := startServer(t, cert, false, true)
	sender := senderFor(t, server, "tls", "mail.example.test", "gate@example.com", pool)
	if err := sender.Send(context.Background(), "gate@example.com", "reader@example.org", []byte("x\r\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := waitFor(server, 1); len(got) != 1 || !got[0].tls {
		t.Errorf("received %+v", got)
	}
}

func TestSendPlainWithoutAuth(t *testing.T) {
	cert, _ := certificate(t, "mail.example.test")
	server := startServer(t, cert, false, false)
	sender := senderFor(t, server, "none", "127.0.0.1", "", nil)
	if err := sender.Send(context.Background(), "gate@example.com", "reader@example.org", []byte("x\r\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := waitFor(server, 1); len(got) != 1 || got[0].auth != "" {
		t.Errorf("received %+v", got)
	}
}

func waitFor(s *fakeServer, mails int) ([]received, []received) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, sessions := s.result()
		if (len(got) >= mails && len(sessions) > 0) || time.Now().After(deadline) {
			return got, sessions
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type recordingSender struct {
	mu   sync.Mutex
	sent []string
	err  error
	done chan struct{}
}

func (r *recordingSender) Send(_ context.Context, _, to string, message []byte) error {
	r.mu.Lock()
	r.sent = append(r.sent, to)
	r.mu.Unlock()
	r.done <- struct{}{}
	return r.err
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestQueue(t *testing.T) {
	logs := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	recorder := &recordingSender{done: make(chan struct{}, 100), err: io.ErrUnexpectedEOF}
	queue := NewQueue(&config.Config{Mail: &config.Mail{From: "gate@example.com", FromName: "Example"}, Branding: *neutral()}, recorder, nil, log)
	for i := 0; i < cap(queue.jobs); i++ {
		if !queue.Enqueue(Code{To: "reader@example.org", Host: "report.example.com", Lang: "en", Code: "87654321", TTL: 10 * time.Minute}) {
			t.Fatalf("job %d refused", i)
		}
	}
	if queue.Enqueue(Code{To: "reader@example.org", Host: "report.example.com", Lang: "en", Code: "87654321", TTL: time.Minute}) {
		t.Error("a full queue took another job")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go queue.Run(ctx)
	for i := 0; i < cap(queue.jobs); i++ {
		<-recorder.done
	}
	deadline := time.Now().Add(2 * time.Second)
	for strings.Count(logs.String(), "code mail failed") < cap(queue.jobs) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if strings.Contains(logs.String(), "87654321") || strings.Contains(logs.String(), "8765 4321") {
		t.Error("the code reached the log")
	}
	if !strings.Contains(logs.String(), "code mail failed") {
		t.Errorf("log: %s", logs.String())
	}
}

func TestDisplay(t *testing.T) {
	if Display("12345678") != "1234 5678" || Display("123") != "123" {
		t.Error("Display")
	}
}

func TestBuildWithBranding(t *testing.T) {
	overrides, problems := i18n.ParseOverrides([]byte(`{"en": {"mail_subject": "Your code for Example"}}`))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	logo := brand.DefaultLogo
	logo.Width = 168
	b := &config.Branding{Name: "Example", Owner: "Example Ltd", URL: "https://example.com", Logo: logo, Palette: brand.NewPalette("#8b0000", "#5a0000", "#ff8080"), Texts: i18n.NewCatalog(overrides)}
	raw, err := Build(Code{To: "reader@example.org", Host: "report.example.com", Lang: "en", Code: "12345678", TTL: 10 * time.Minute}, b, "gate@example.com", "Example", now)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := mail.ReadMessage(bytes.NewReader(raw))
	if subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); subject != "Your code for Example" {
		t.Errorf("Subject %q", subject)
	}
	decoded := decodedParts(t, raw)
	for _, want := range []string{">Example</td>", `width="168" height="42"`, `<a href="https://example.com" style="color:#9db2c6;text-decoration:none">Example Ltd</a>`, "color:#5a0000", "color:#ff8080 !important", "Example Ltd · https://example.com"} {
		if !strings.Contains(decoded, want) {
			t.Errorf("mail lacks %q", want)
		}
	}
}

// decodedParts is the text and the HTML part of a code mail, decoded.
func decodedParts(t *testing.T, raw []byte) string {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	parts := multipart.NewReader(msg.Body, params["boundary"])
	text := readPart(t, parts, "text/plain; charset=utf-8")
	related, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	_, relatedParams, _ := mime.ParseMediaType(related.Header.Get("Content-Type"))
	return text + readPart(t, multipart.NewReader(related, relatedParams["boundary"]), "text/html; charset=utf-8")
}

type envelopeSender struct {
	mu       sync.Mutex
	from     []string
	messages [][]byte
	done     chan struct{}
}

func (e *envelopeSender) Send(_ context.Context, from, _ string, message []byte) error {
	e.mu.Lock()
	e.from = append(e.from, from)
	e.messages = append(e.messages, message)
	e.mu.Unlock()
	e.done <- struct{}{}
	return nil
}

func TestQueueWithBounces(t *testing.T) {
	logs := &lockedBuffer{}
	sender := &envelopeSender{done: make(chan struct{}, 10)}
	tracker := bounce.NewTracker("gate@example.com", 48*time.Hour, 100)
	queue := NewQueue(&config.Config{Mail: &config.Mail{From: "gate@example.com", FromName: "Example"}, Branding: *neutral()}, sender, tracker, slog.New(slog.NewTextHandler(logs, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go queue.Run(ctx)

	job := Code{To: "reader@example.org", Host: "report.example.com", Lang: "en", Code: "12345678", TTL: 10 * time.Minute}
	queue.Enqueue(job)
	<-sender.done
	sender.mu.Lock()
	envelope, message := sender.from[0], sender.messages[0]
	sender.mu.Unlock()
	token, ok := tracker.Token(envelope)
	if !ok {
		t.Fatalf("envelope sender %q carries no token", envelope)
	}
	if msg, err := mail.ReadMessage(bytes.NewReader(message)); err != nil || !strings.Contains(msg.Header.Get("From"), "<gate@example.com>") {
		t.Error("the From header changed with the envelope sender")
	}

	if _, ok := tracker.Bounced(token, "reader@example.org", time.Now()); !ok {
		t.Fatal("the bounce did not count")
	}
	queue.Enqueue(job)
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "code mail suppressed") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), `msg="code mail suppressed" host=report.example.com user=reader@example.org`) || len(sender.done) != 0 {
		t.Errorf("a mail went to a suppressed address; log %s", logs.String())
	}
}

func TestSendStopsAServerThatNeverEnds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		_, _ = io.WriteString(conn, "220 ")
		for {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	sender := NewSender(&config.Mail{Host: host, Port: portNumber, TLS: "none", ServerName: host})
	if err := sender.Send(context.Background(), "gate@example.com", "reader@example.org", []byte("x\r\n")); err == nil || !strings.Contains(err.Error(), "more than any answer needs") {
		t.Errorf("error %v", err)
	}
}
