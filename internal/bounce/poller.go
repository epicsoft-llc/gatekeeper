package bounce

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/mail"
	"strconv"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
)

// A poll reads at most this many mails; the rest waits for the next one.
const perPoll = 100

// Poller reads the mailbox of the submission account: bounces to a token of the Tracker go, other mail stays.
type Poller struct {
	address      string
	serverName   string
	username     string
	password     string
	deleteOthers bool
	poll         time.Duration
	tracker      *Tracker
	log          *slog.Logger
	now          func() time.Time
	// RootCAs replaces the system pool, for tests.
	RootCAs *x509.CertPool

	validity uint32
	next     uint32
}

func NewPoller(cfg *config.Mail, tracker *Tracker, log *slog.Logger) *Poller {
	b := cfg.Bounces
	return &Poller{
		address:      net.JoinHostPort(b.IMAPHost, strconv.Itoa(b.IMAPPort)),
		serverName:   b.ServerName,
		username:     cfg.Username,
		password:     cfg.Password,
		deleteOthers: b.DeleteOthers,
		poll:         b.Poll.D(),
		tracker:      tracker,
		log:          log,
		now:          time.Now,
	}
}

func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.poll)
	defer ticker.Stop()
	for {
		if err := p.Poll(ctx); err != nil && ctx.Err() == nil {
			p.log.Warn("bounce mailbox unreachable", "error", err)
		}
		p.tracker.Sweep(p.now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Poll reads the mail that arrived since the last poll; the UIDs keep it from reading a mail twice.
func (p *Poller) Poll(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c, err := dialIMAP(ctx, p.address, &tls.Config{ServerName: p.serverName, MinVersion: tls.VersionTLS12, RootCAs: p.RootCAs})
	if err != nil {
		return err
	}
	defer c.close()
	if err := c.login(p.username, p.password); err != nil {
		return err
	}
	validity, err := c.selectInbox()
	if err != nil {
		return err
	}
	if validity != p.validity {
		p.validity, p.next = validity, 1
	}
	uids, err := c.search(p.next)
	if err != nil {
		return err
	}
	var remove []uint32
	for _, uid := range uids[:min(len(uids), perPoll)] {
		// Moving on first: a mail that breaks the session is not read again on every poll.
		p.next = uid + 1
		header, err := c.fetch(uid, "BODY.PEEK[HEADER]<0.65536>")
		if err != nil {
			return err
		}
		token, ours := p.token(header)
		switch {
		case ours:
			message, err := c.fetch(uid, "BODY.PEEK[]<0.262144>")
			if err != nil {
				return err
			}
			p.process(token, message)
			remove = append(remove, uid)
		case p.deleteOthers && header != nil:
			remove = append(remove, uid)
		}
	}
	if len(remove) > 0 {
		if err := c.remove(remove); err != nil {
			return err
		}
	}
	return c.logout()
}

// token looks where a bounce names the address it came back to.
func (p *Poller) token(header []byte) (string, bool) {
	msg, err := mail.ReadMessage(bytes.NewReader(header))
	if err != nil {
		return "", false
	}
	for _, name := range []string{"Delivered-To", "X-Original-To", "To"} {
		for _, value := range msg.Header[name] {
			if token, ok := p.tracker.Token(value); ok {
				return token, true
			}
		}
	}
	return "", false
}

// process logs no address of a bounce it ignores: a forged one may name anybody.
func (p *Poller) process(token string, message []byte) {
	recipients, err := Parse(message)
	if err != nil {
		p.log.Info("bounce ignored", "reason", "not a readable delivery status notification")
		return
	}
	now := p.now()
	for _, r := range recipients {
		if !r.Failed() {
			continue
		}
		for _, address := range []string{r.Final, r.Original} {
			if until, ok := p.tracker.Bounced(token, address, now); ok {
				p.log.Info("code mail bounced", "user", address, "status", r.Status, "suppressed_until", until.UTC().Format(time.RFC3339))
				return
			}
		}
	}
	p.log.Info("bounce ignored", "reason", "no failure for the address of a known token")
}
