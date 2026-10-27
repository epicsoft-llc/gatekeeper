package bounce

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
)

const (
	// A plain SEARCH answers in one line, about seven bytes a mail.
	maxLine     = 1 << 20
	maxLiteral  = 1 << 20
	maxAnswer   = 4 << 20
	maxUntagged = 10_000
)

// imapClient speaks the part of IMAP4rev1 the poller needs, over TLS only.
type imapClient struct {
	conn         net.Conn
	r            *bufio.Reader
	tag          int
	capabilities []string
}

// response is one server response; each literal in it stands as "\x00" in text.
type response struct {
	text     string
	literals [][]byte
}

func dialIMAP(ctx context.Context, address string, tlsConfig *tls.Config) (*imapClient, error) {
	conn, err := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	c := &imapClient{conn: conn, r: bufio.NewReaderSize(conn, 16<<10)}
	greeting, err := c.read()
	if err == nil && !strings.HasPrefix(greeting.text, "* OK") {
		err = fmt.Errorf("imap: greeting %q", clip(greeting.text))
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *imapClient) close() error { return c.conn.Close() }

func (c *imapClient) line() (string, error) {
	var line []byte
	for {
		chunk, isPrefix, err := c.r.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, chunk...)
		if len(line) > maxLine {
			return "", errors.New("imap: line too long")
		}
		if !isPrefix {
			return string(line), nil
		}
	}
}

// read collects a response with its literals, the {n} at the end of a line announcing n bytes.
func (c *imapClient) read() (*response, error) {
	resp := &response{}
	var text strings.Builder
	total := 0
	for {
		line, err := c.line()
		if err != nil {
			return nil, err
		}
		size, ok := literal(line)
		if !ok {
			text.WriteString(line)
			resp.text = text.String()
			return resp, nil
		}
		if size > maxLiteral || len(resp.literals) >= 8 {
			return nil, errors.New("imap: literal too large")
		}
		if total += size; total > maxAnswer {
			return nil, errors.New("imap: answer too large")
		}
		text.WriteString(line[:strings.LastIndexByte(line, '{')] + "\x00")
		data := make([]byte, size)
		if _, err := io.ReadFull(c.r, data); err != nil {
			return nil, err
		}
		resp.literals = append(resp.literals, data)
		if text.Len() > maxLine {
			return nil, errors.New("imap: answer too large")
		}
	}
}

func literal(line string) (int, bool) {
	if !strings.HasSuffix(line, "}") {
		return 0, false
	}
	open := strings.LastIndexByte(line, '{')
	if open < 0 {
		return 0, false
	}
	size, err := strconv.Atoi(strings.TrimSuffix(line[open+1:len(line)-1], "+"))
	return size, err == nil && size >= 0
}

func (c *imapClient) send(line string) (string, error) {
	c.tag++
	tag := "g" + strconv.Itoa(c.tag)
	_, err := io.WriteString(c.conn, tag+" "+line+"\r\n")
	return tag, err
}

// command returns the untagged responses of one command; anything but a tagged OK is an error.
func (c *imapClient) command(line string) ([]*response, error) {
	tag, err := c.send(line)
	if err != nil {
		return nil, err
	}
	return c.collect(tag)
}

// collect keeps at most maxAnswer bytes of one command: a server cannot fill the memory with untagged answers.
func (c *imapClient) collect(tag string) ([]*response, error) {
	var untagged []*response
	total := 0
	for {
		resp, err := c.read()
		if err != nil {
			return nil, err
		}
		total += len(resp.text)
		for _, data := range resp.literals {
			total += len(data)
		}
		if total > maxAnswer {
			return nil, errors.New("imap: answer too large")
		}
		status, tagged := strings.CutPrefix(resp.text, tag+" ")
		switch {
		case tagged && strings.HasPrefix(strings.ToUpper(status), "OK"):
			return untagged, nil
		case tagged:
			return nil, fmt.Errorf("imap: %s", clip(status))
		case strings.HasPrefix(resp.text, "+"):
			return nil, errors.New("imap: unexpected continuation")
		case len(untagged) >= maxUntagged:
			return nil, errors.New("imap: too many responses")
		}
		untagged = append(untagged, resp)
	}
}

// login sends the credentials with AUTHENTICATE PLAIN, base64 - so no character of a password needs quoting.
func (c *imapClient) login(username, password string) error {
	tag, err := c.send("AUTHENTICATE PLAIN")
	if err != nil {
		return err
	}
	resp, err := c.read()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp.text, "+") {
		return fmt.Errorf("imap: AUTHENTICATE PLAIN refused: %s", clip(resp.text))
	}
	if _, err := io.WriteString(c.conn, base64.StdEncoding.EncodeToString([]byte("\x00"+username+"\x00"+password))+"\r\n"); err != nil {
		return err
	}
	if _, err := c.collect(tag); err != nil {
		return err
	}
	untagged, err := c.command("CAPABILITY")
	for _, r := range untagged {
		if words, ok := strings.CutPrefix(r.text, "* CAPABILITY "); ok {
			c.capabilities = strings.Fields(strings.ToUpper(words))
		}
	}
	return err
}

func (c *imapClient) selectInbox() (uint32, error) {
	untagged, err := c.command("SELECT INBOX")
	if err != nil {
		return 0, err
	}
	for _, r := range untagged {
		if _, rest, found := strings.Cut(strings.ToUpper(r.text), "[UIDVALIDITY "); found {
			value, _, _ := strings.Cut(rest, "]")
			if validity, err := strconv.ParseUint(value, 10, 32); err == nil && validity > 0 {
				return uint32(validity), nil
			}
		}
	}
	return 0, errors.New("imap: SELECT without UIDVALIDITY")
}

// search lists the UIDs from first on, ascending; "first:*" also names the highest UID when that is lower.
func (c *imapClient) search(first uint32) ([]uint32, error) {
	command := fmt.Sprintf("UID SEARCH UID %d:*", first)
	if slices.Contains(c.capabilities, "ESEARCH") || slices.Contains(c.capabilities, "IMAP4REV2") {
		// Ranges instead of one number a mail: the answer stays short however full the mailbox is.
		command = fmt.Sprintf("UID SEARCH RETURN (ALL) UID %d:*", first)
	}
	untagged, err := c.command(command)
	if err != nil {
		return nil, err
	}
	var uids []uint32
	for _, r := range untagged {
		upper := strings.ToUpper(r.text)
		switch {
		case strings.HasPrefix(upper, "* SEARCH"):
			for _, word := range strings.Fields(r.text[len("* SEARCH"):]) {
				uids = appendUID(uids, word, first)
			}
		case strings.HasPrefix(upper, "* ESEARCH"):
			if _, set, found := strings.Cut(upper, " ALL "); found && len(strings.Fields(set)) > 0 {
				for _, item := range strings.Split(strings.Fields(set)[0], ",") {
					low, high, isRange := strings.Cut(item, ":")
					if !isRange {
						uids = appendUID(uids, low, first)
						continue
					}
					from, err1 := strconv.ParseUint(low, 10, 32)
					to, err2 := strconv.ParseUint(high, 10, 32)
					for uid := from; err1 == nil && err2 == nil && uid <= to && len(uids) < 100_000; uid++ {
						uids = appendUID(uids, strconv.FormatUint(uid, 10), first)
					}
				}
			}
		}
	}
	slices.Sort(uids)
	return slices.Compact(uids), nil
}

func appendUID(uids []uint32, word string, first uint32) []uint32 {
	uid, err := strconv.ParseUint(word, 10, 32)
	if err != nil || uint32(uid) < first {
		return uids
	}
	return append(uids, uint32(uid))
}

// fetch returns the literal of one item of one message; a message deleted meanwhile gives nil.
func (c *imapClient) fetch(uid uint32, item string) ([]byte, error) {
	untagged, err := c.command(fmt.Sprintf("UID FETCH %d (%s)", uid, item))
	if err != nil {
		return nil, err
	}
	want := strconv.FormatUint(uint64(uid), 10)
	for _, r := range untagged {
		words := strings.FieldsFunc(strings.ToUpper(r.text), func(r rune) bool { return r == ' ' || r == '(' || r == ')' })
		if len(r.literals) == 0 || len(words) < 3 || words[2] != "FETCH" {
			continue
		}
		for i := 3; i+1 < len(words); i++ {
			if words[i] == "UID" && words[i+1] == want {
				return r.literals[0], nil
			}
		}
	}
	return nil, nil
}

// remove expunges only the given messages where the server can (UIDPLUS), otherwise everything flagged \Deleted.
func (c *imapClient) remove(uids []uint32) error {
	set := make([]string, len(uids))
	for i, uid := range uids {
		set[i] = strconv.FormatUint(uint64(uid), 10)
	}
	joined := strings.Join(set, ",")
	if _, err := c.command("UID STORE " + joined + ` +FLAGS.SILENT (\Deleted)`); err != nil {
		return err
	}
	if slices.Contains(c.capabilities, "UIDPLUS") || slices.Contains(c.capabilities, "IMAP4REV2") {
		_, err := c.command("UID EXPUNGE " + joined)
		return err
	}
	_, err := c.command("EXPUNGE")
	return err
}

func (c *imapClient) logout() error {
	_, err := c.command("LOGOUT")
	return err
}

// clip keeps a server answer short in an error.
func clip(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
