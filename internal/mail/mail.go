package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/bounce"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
	"gitlab.com/epicsoft-networks/gatekeeper/internal/i18n"
)

//go:embed templates
var files embed.FS

var (
	htmlTemplate = htmltemplate.Must(htmltemplate.ParseFS(files, "templates/code.html"))
	textTemplate = texttemplate.Must(texttemplate.ParseFS(files, "templates/code.txt"))
)

// Also written into templates/code.html.
const logoID = "logo@gatekeeper"

// To and Host come from the configuration, never from a request. The mail does not name the host - only the log does.
type Code struct {
	To   string
	Host string
	Lang string
	Code string
	TTL  time.Duration
}

type content struct {
	Lang, Eyebrow, Heading, Code, Lead, Ignore string
	Name, Owner, URL                           string
	LogoWidth, LogoHeight                      int
	Strong, Dark, Tint, Line                   string
}

func Build(c Code, b *config.Branding, from, fromName string, now time.Time) ([]byte, error) {
	if !i18n.Supported(c.Lang) {
		return nil, fmt.Errorf("language %q", c.Lang)
	}
	for _, value := range []string{c.To, c.Host, from, fromName} {
		if strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("line break in a header value")
		}
	}
	minutes := i18n.Minutes(c.Lang, int(c.TTL/time.Minute))
	data := content{
		Lang:       c.Lang,
		Eyebrow:    b.Texts.T(c.Lang, "eyebrow"),
		Heading:    b.Texts.T(c.Lang, "mail_heading"),
		Code:       Display(c.Code),
		Lead:       b.Texts.T(c.Lang, "mail_lead", "minutes", minutes),
		Ignore:     b.Texts.T(c.Lang, "mail_ignore"),
		Name:       b.Name,
		Owner:      b.Owner,
		URL:        b.URL,
		LogoWidth:  b.Logo.Width,
		LogoHeight: b.Logo.Height,
		Strong:     b.Palette.Strong,
		Dark:       b.Palette.Dark,
		Tint:       b.Palette.Tint,
		Line:       b.Palette.Line,
	}
	var text, html bytes.Buffer
	if err := textTemplate.Execute(&text, data); err != nil {
		return nil, err
	}
	if err := htmlTemplate.Execute(&html, data); err != nil {
		return nil, err
	}

	var related bytes.Buffer
	relatedWriter := multipart.NewWriter(&related)
	if err := writeQuotedPrintable(relatedWriter, "text/html; charset=utf-8", html.Bytes()); err != nil {
		return nil, err
	}
	logoPart, err := relatedWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"image/png"},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Id":                {"<" + logoID + ">"},
		"Content-Disposition":       {`inline; filename="logo.png"`},
	})
	if err != nil {
		return nil, err
	}
	if err := writeBase64(logoPart, b.Logo.PNG); err != nil {
		return nil, err
	}
	if err := relatedWriter.Close(); err != nil {
		return nil, err
	}

	var body bytes.Buffer
	alternative := multipart.NewWriter(&body)
	if err := writeQuotedPrintable(alternative, "text/plain; charset=utf-8", text.Bytes()); err != nil {
		return nil, err
	}
	relatedPart, err := alternative.CreatePart(textproto.MIMEHeader{
		"Content-Type": {`multipart/related; type="text/html"; boundary="` + relatedWriter.Boundary() + `"`},
	})
	if err != nil {
		return nil, err
	}
	if _, err := relatedPart.Write(related.Bytes()); err != nil {
		return nil, err
	}
	if err := alternative.Close(); err != nil {
		return nil, err
	}

	var message bytes.Buffer
	header := func(name, value string) { message.WriteString(name + ": " + value + "\r\n") }
	header("From", (&mail.Address{Name: fromName, Address: from}).String())
	header("To", (&mail.Address{Address: c.To}).String())
	header("Subject", mime.QEncoding.Encode("utf-8", b.Texts.T(c.Lang, "mail_subject")))
	header("Date", now.UTC().Format(time.RFC1123Z))
	header("Message-Id", "<"+rand.Text()+"@"+from[strings.LastIndexByte(from, '@')+1:]+">")
	header("Mime-Version", "1.0")
	header("Auto-Submitted", "auto-generated")
	header("Content-Type", `multipart/alternative; boundary="`+alternative.Boundary()+`"`)
	message.WriteString("\r\n")
	message.Write(body.Bytes())
	return message.Bytes(), nil
}

func Display(code string) string {
	if len(code) != 8 {
		return code
	}
	return code[:4] + " " + code[4:]
}

func writeQuotedPrintable(w *multipart.Writer, contentType string, data []byte) error {
	part, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {contentType},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return err
	}
	qp := quotedprintable.NewWriter(part)
	if _, err := qp.Write(data); err != nil {
		return err
	}
	return qp.Close()
}

func writeBase64(w io.Writer, data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 76 {
		if _, err := io.WriteString(w, encoded[:76]+"\r\n"); err != nil {
			return err
		}
		encoded = encoded[76:]
	}
	_, err := io.WriteString(w, encoded+"\r\n")
	return err
}

type Sender struct {
	cfg  *config.Mail
	helo string
	// RootCAs replaces the system pool, for tests.
	RootCAs *x509.CertPool
}

func NewSender(cfg *config.Mail) *Sender {
	helo, err := os.Hostname()
	if err != nil || helo == "" {
		helo = "gatekeeper"
	}
	return &Sender{cfg: cfg, helo: helo}
}

// Send never falls back to plain text: without STARTTLS on a starttls server the mail is not sent.
func (s *Sender) Send(ctx context.Context, from, to string, message []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	address := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	tlsConfig := &tls.Config{ServerName: s.cfg.ServerName, MinVersion: tls.VersionTLS12, RootCAs: s.RootCAs}

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return err
	}
	// net/smtp reads answers without a limit; below TLS, so the TLS connection stays a *tls.Conn for smtp.PlainAuth.
	var conn net.Conn = &budget{Conn: raw, left: maxAnswers}
	if s.cfg.TLS == "tls" {
		secure := tls.Client(conn, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return err
		}
		conn = secure
	}
	client, err := smtp.NewClient(conn, s.cfg.ServerName)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()
	if err := client.Hello(s.helo); err != nil {
		return err
	}
	if s.cfg.TLS == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("the mail server offers no STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if s.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.ServerName)); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(message); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// A mail server answers a whole session in a few kilobytes.
const maxAnswers = 1 << 20

// budget ends a connection that reads more than left bytes.
type budget struct {
	net.Conn
	left int
}

func (b *budget) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errors.New("the mail server sent more than any answer needs")
	}
	n, err := b.Conn.Read(p[:min(len(p), b.left)])
	b.left -= n
	return n, err
}

type sender interface {
	Send(ctx context.Context, from, to string, message []byte) error
}

// Queue sends in the background, so answering a request takes as long whether a mail goes out or not.
type Queue struct {
	jobs     chan Code
	sender   sender
	from     string
	fromName string
	branding *config.Branding
	bounces  *bounce.Tracker
	log      *slog.Logger
	now      func() time.Time
}

// NewQueue takes a nil tracker without mail.bounces: then every mail goes out with mail.from as envelope sender.
func NewQueue(cfg *config.Config, s sender, bounces *bounce.Tracker, log *slog.Logger) *Queue {
	return &Queue{jobs: make(chan Code, 64), sender: s, from: cfg.Mail.From, fromName: cfg.Mail.FromName, branding: &cfg.Branding, bounces: bounces, log: log, now: time.Now}
}

func (q *Queue) Enqueue(c Code) bool {
	select {
	case q.jobs <- c:
		return true
	default:
		return false
	}
}

func (q *Queue) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-q.jobs:
			q.send(ctx, job)
		}
	}
}

// send leaves out an address that bounced: the visitor got the same answer as always, only the log tells.
func (q *Queue) send(ctx context.Context, job Code) {
	now := q.now()
	envelope := q.from
	if q.bounces != nil {
		if q.bounces.Suppressed(job.To, now) {
			q.log.Info("code mail suppressed", "host", job.Host, "user", job.To)
			return
		}
		envelope = q.bounces.Sender(job.To, now)
	}
	message, err := Build(job, q.branding, q.from, q.fromName, now)
	if err == nil {
		err = q.sender.Send(ctx, envelope, job.To, message)
	}
	if err != nil {
		q.log.Error("code mail failed", "host", job.Host, "user", job.To, "error", err)
		return
	}
	q.log.Info("code mail sent", "host", job.Host, "user", job.To)
}
