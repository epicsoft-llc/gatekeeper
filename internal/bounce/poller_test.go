package bounce

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
)

// fakeIMAP answers the commands of the poller like an IMAP4rev1 server with one mailbox.
type fakeIMAP struct {
	addr     string
	mu       sync.Mutex
	validity uint32
	uidplus  bool
	esearch  bool
	messages map[uint32][]byte
	deleted  map[uint32]bool
	logins   []string
	commands []string
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

func startIMAP(t *testing.T, name string) (*fakeIMAP, *x509.CertPool) {
	t.Helper()
	cert, pool := certificate(t, name)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeIMAP{addr: ln.Addr().String(), validity: 7, uidplus: true, messages: map[uint32][]byte{}, deleted: map[uint32]bool{}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f, pool
}

func (f *fakeIMAP) add(uid uint32, message []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages[uid] = bytes.ReplaceAll(bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
}

func (f *fakeIMAP) uids() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var uids []uint32
	for uid := range f.messages {
		uids = append(uids, uid)
	}
	slices.Sort(uids)
	return uids
}

func (f *fakeIMAP) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

var partial = regexp.MustCompile(`^UID FETCH (\d+) \(BODY\.PEEK\[(HEADER)?\]<0\.(\d+)>\)$`)

func (f *fakeIMAP) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	say := func(format string, args ...any) { _, _ = fmt.Fprintf(conn, format+"\r\n", args...) }
	say("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] fake ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		tag, command, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		f.mu.Lock()
		f.commands = append(f.commands, command)
		f.mu.Unlock()
		switch upper := strings.ToUpper(command); {
		case upper == "AUTHENTICATE PLAIN":
			say("+ ")
			answer, _ := r.ReadString('\n')
			plain, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(answer))
			f.mu.Lock()
			f.logins = append(f.logins, string(plain))
			f.mu.Unlock()
			if string(plain) != "\x00gate@example.test\x00secret" {
				say("%s NO [AUTHENTICATIONFAILED] Authentication failed", tag)
				continue
			}
			say("%s OK done", tag)
		case upper == "CAPABILITY":
			capabilities := "IMAP4rev1 AUTH=PLAIN"
			if f.uidplus {
				capabilities += " UIDPLUS"
			}
			if f.esearch {
				capabilities += " ESEARCH"
			}
			say("* CAPABILITY %s", capabilities)
			say("%s OK done", tag)
		case upper == "SELECT INBOX":
			f.mu.Lock()
			say("* %d EXISTS", len(f.messages))
			say("* OK [UIDVALIDITY %d] UIDs valid", f.validity)
			f.mu.Unlock()
			say("%s OK [READ-WRITE] done", tag)
		case strings.HasPrefix(upper, "UID SEARCH RETURN (ALL) UID ") && f.esearch:
			first, _ := strconv.ParseUint(strings.TrimSuffix(command[len("UID SEARCH RETURN (ALL) UID "):], ":*"), 10, 32)
			var ranges []string
			for _, uid := range f.uids() {
				switch last := len(ranges) - 1; {
				case uint64(uid) < first:
				case last >= 0 && strings.HasSuffix(ranges[last], ":"+strconv.Itoa(int(uid)-1)):
					ranges[last] = strings.TrimSuffix(ranges[last], strconv.Itoa(int(uid)-1)) + strconv.Itoa(int(uid))
				case last >= 0 && ranges[last] == strconv.Itoa(int(uid)-1):
					ranges[last] += ":" + strconv.Itoa(int(uid))
				default:
					ranges = append(ranges, strconv.Itoa(int(uid)))
				}
			}
			if len(ranges) > 0 {
				say(`* ESEARCH (TAG "%s") UID ALL %s`, tag, strings.Join(ranges, ","))
			} else {
				say(`* ESEARCH (TAG "%s") UID`, tag)
			}
			say("%s OK done", tag)
		case strings.HasPrefix(upper, "UID SEARCH UID "):
			first, _ := strconv.ParseUint(strings.TrimSuffix(command[len("UID SEARCH UID "):], ":*"), 10, 32)
			uids := f.uids()
			var found []string
			for _, uid := range uids {
				if uint64(uid) >= first {
					found = append(found, strconv.Itoa(int(uid)))
				}
			}
			if len(found) == 0 && len(uids) > 0 {
				found = append(found, strconv.Itoa(int(uids[len(uids)-1])))
			}
			say("* SEARCH %s", strings.Join(found, " "))
			say("%s OK done", tag)
		case partial.MatchString(command):
			m := partial.FindStringSubmatch(command)
			uid, _ := strconv.ParseUint(m[1], 10, 32)
			limit, _ := strconv.Atoi(m[3])
			f.mu.Lock()
			data, ok := f.messages[uint32(uid)]
			f.mu.Unlock()
			if ok {
				item := "BODY[]<0>"
				if m[2] != "" {
					item = "BODY[HEADER]<0>"
					end := bytes.Index(data, []byte("\r\n\r\n"))
					data = data[:end+4]
				}
				data = data[:min(len(data), limit)]
				say("* 1 FETCH (UID %d %s {%d}", uid, item, len(data))
				_, _ = conn.Write(data)
				say(")")
			}
			say("%s OK done", tag)
		case strings.HasPrefix(upper, "UID STORE ") && strings.HasSuffix(upper, ` +FLAGS.SILENT (\DELETED)`):
			f.mu.Lock()
			for _, uid := range strings.Split(strings.Fields(command)[2], ",") {
				n, _ := strconv.ParseUint(uid, 10, 32)
				f.deleted[uint32(n)] = true
			}
			f.mu.Unlock()
			say("%s OK done", tag)
		case strings.HasPrefix(upper, "UID EXPUNGE ") && f.uidplus:
			f.mu.Lock()
			for _, uid := range strings.Split(strings.Fields(command)[2], ",") {
				n, _ := strconv.ParseUint(uid, 10, 32)
				if f.deleted[uint32(n)] {
					delete(f.messages, uint32(n))
				}
			}
			f.mu.Unlock()
			say("%s OK done", tag)
		case upper == "EXPUNGE":
			f.mu.Lock()
			for uid := range f.deleted {
				delete(f.messages, uid)
			}
			f.mu.Unlock()
			say("%s OK done", tag)
		case upper == "LOGOUT":
			say("* BYE logging out")
			say("%s OK done", tag)
			return
		default:
			say("%s BAD unknown command", tag)
		}
	}
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

func poller(t *testing.T, f *fakeIMAP, pool *x509.CertPool, serverName string, deleteOthers bool) (*Poller, *Tracker, *lockedBuffer) {
	t.Helper()
	host, port, _ := net.SplitHostPort(f.addr)
	portNumber, _ := strconv.Atoi(port)
	tracker := NewTracker("gate@example.test", 48*time.Hour, 100)
	logs := &lockedBuffer{}
	cfg := &config.Mail{Username: "gate@example.test", Password: "secret", Bounces: &config.Bounces{
		IMAPHost: host, IMAPPort: portNumber, ServerName: serverName, Poll: config.Duration(time.Minute), DeleteOthers: deleteOthers,
	}}
	p := NewPoller(cfg, tracker, slog.New(slog.NewTextHandler(logs, nil)))
	p.RootCAs = pool
	p.now = func() time.Time { return now }
	return p, tracker, logs
}

const otherMail = "From: someone@example.org\nTo: gate@example.test\nSubject: Question\n\nHello\n"

// mailbox holds a bounce of a mail sent through the tracker, one with an unknown token, an auto-reply and a mail of a person.
func mailbox(t *testing.T, f *fakeIMAP, tracker *Tracker) {
	t.Helper()
	token, _ := tracker.Token(tracker.Sender("nobody-here@example.test", now))
	postfix := sample(t, "postfix.eml")
	f.add(3, bytes.ReplaceAll(postfix, []byte("abcdefghijklmnopqrstuvwxyz"), []byte(token)))
	f.add(5, []byte(otherMail))
	f.add(8, bytes.ReplaceAll(postfix, []byte("nobody-here"), []byte("victim")))
	f.add(10, []byte("To: gate+b-"+token+"@example.test\r\nSubject: Out of office\r\n\r\nvictim@example.test is away.\r\n"))
}

func TestPollSuppressesWhatBounced(t *testing.T) {
	f, pool := startIMAP(t, "imap.example.test")
	p, tracker, logs := poller(t, f, pool, "imap.example.test", false)
	mailbox(t, f, tracker)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !tracker.Suppressed("nobody-here@example.test", now) || tracker.Suppressed("victim@example.test", now) {
		t.Error("the wrong address is suppressed")
	}
	if !strings.Contains(logs.String(), `reason="not a readable delivery status notification"`) {
		t.Errorf("an unreadable bounce was not ignored: %s", logs.String())
	}
	if got := f.uids(); !slices.Equal(got, []uint32{5}) {
		t.Errorf("left in the mailbox: %v, want the mail of a person only", got)
	}
	log := logs.String()
	if !strings.Contains(log, `msg="code mail bounced" user=nobody-here@example.test status=5.1.1`) || !strings.Contains(log, `msg="bounce ignored"`) || strings.Contains(log, "victim") {
		t.Errorf("log: %s", log)
	}
	if f.logins[0] != "\x00gate@example.test\x00secret" {
		t.Errorf("login %q", f.logins[0])
	}

	before := len(f.seen())
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, command := range f.seen()[before:] {
		if strings.HasPrefix(command, "UID FETCH") {
			t.Errorf("a mail was read twice: %s", command)
		}
	}
	f.add(9, []byte(otherMail))
	f.mu.Lock()
	f.validity = 8
	f.mu.Unlock()
	before = len(f.seen())
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetched := strings.Join(f.seen()[before:], "\n"); !strings.Contains(fetched, "UID FETCH 5 ") || !strings.Contains(fetched, "UID FETCH 9 ") {
		t.Errorf("a new UIDVALIDITY did not start over: %s", fetched)
	}
}

func TestPollDeletesOthersOnlyWhenTold(t *testing.T) {
	f, pool := startIMAP(t, "imap.example.test")
	f.uidplus = false
	p, tracker, _ := poller(t, f, pool, "imap.example.test", true)
	mailbox(t, f, tracker)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.uids(); len(got) != 0 {
		t.Errorf("left in the mailbox: %v", got)
	}
	if !slices.Contains(f.seen(), "EXPUNGE") {
		t.Error("without UIDPLUS the poller must expunge the mailbox")
	}
}

func TestPollRefusesAWrongCertificate(t *testing.T) {
	f, pool := startIMAP(t, "other.example.test")
	p, _, _ := poller(t, f, pool, "imap.example.test", false)
	if err := p.Poll(context.Background()); err == nil {
		t.Fatal("polled a server with a certificate for another name")
	}
	if len(f.logins) != 0 {
		t.Error("credentials went to a server with a wrong certificate")
	}
}

func TestPollWithAWrongPassword(t *testing.T) {
	f, pool := startIMAP(t, "imap.example.test")
	p, _, _ := poller(t, f, pool, "imap.example.test", false)
	p.password = "wrong"
	err := p.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "AUTHENTICATIONFAILED") || strings.Contains(err.Error(), "wrong") {
		t.Errorf("error %v", err)
	}
}

func TestPollWithESEARCH(t *testing.T) {
	f, pool := startIMAP(t, "imap.example.test")
	f.esearch = true
	p, tracker, _ := poller(t, f, pool, "imap.example.test", false)
	mailbox(t, f, tracker)
	for uid := uint32(20); uid < 25; uid++ {
		f.add(uid, []byte(otherMail))
	}
	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !tracker.Suppressed("nobody-here@example.test", now) || !slices.Equal(f.uids(), []uint32{5, 20, 21, 22, 23, 24}) {
		t.Errorf("left in the mailbox: %v", f.uids())
	}
	if !slices.Contains(f.seen(), "UID SEARCH RETURN (ALL) UID 1:*") {
		t.Errorf("no ESEARCH: %v", f.seen())
	}
}

func TestPollAFullMailbox(t *testing.T) {
	f, pool := startIMAP(t, "imap.example.test")
	p, _, _ := poller(t, f, pool, "imap.example.test", false)
	for uid := uint32(1); uid <= 20_000; uid++ {
		f.messages[uid] = []byte("To: gate@example.test\r\n\r\nHello\r\n")
	}
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("a mailbox of 20000 mails: %v", err)
	}
	if p.next != perPoll+1 {
		t.Errorf("next %d after one poll", p.next)
	}
}
