package bounce

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
)

const (
	maxParts  = 16
	maxStatus = 64 << 10
)

var errNoReport = errors.New("not a delivery status notification")

// Recipient is one per-recipient block of a delivery status notification.
type Recipient struct {
	Final, Original string
	Action, Status  string
}

// Failed is a permanent failure, or a delay after which the server gave up - a warning about a delay is not.
func (r Recipient) Failed() bool {
	return r.Action == "failed" && (strings.HasPrefix(r.Status, "5.") || strings.HasPrefix(r.Status, "4."))
}

// Parse reads a delivery status notification (RFC 3464, RFC 6533): a multipart/report with a delivery-status part.
func Parse(message []byte) ([]Recipient, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return nil, err
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	report := strings.ToLower(params["report-type"])
	if err != nil || mediaType != "multipart/report" || (report != "delivery-status" && report != "global-delivery-status") || params["boundary"] == "" {
		return nil, errNoReport
	}
	parts := multipart.NewReader(msg.Body, params["boundary"])
	for range maxParts {
		part, err := parts.NextPart()
		if err != nil {
			return nil, errNoReport
		}
		partType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if partType != "message/delivery-status" && partType != "message/global-delivery-status" {
			continue
		}
		var body io.Reader = io.LimitReader(part, maxStatus)
		if strings.EqualFold(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")), "base64") {
			body = base64.NewDecoder(base64.StdEncoding, body)
		}
		status, err := io.ReadAll(body)
		if err != nil && len(status) == 0 {
			return nil, err
		}
		return recipients(status), nil
	}
	return nil, errNoReport
}

// recipients reads the blocks after the per-message block; a block without Final-Recipient is not one of them.
func recipients(status []byte) []Recipient {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(status)))
	var found []Recipient
	for range 1 + maxParts*8 {
		fields, err := reader.ReadMIMEHeader()
		if final := fields.Get("Final-Recipient"); final != "" {
			found = append(found, Recipient{
				Final:    addressOf(final),
				Original: addressOf(fields.Get("Original-Recipient")),
				Action:   strings.ToLower(strings.TrimSpace(fields.Get("Action"))),
				Status:   strings.TrimSpace(fields.Get("Status")),
			})
		}
		if err != nil {
			break
		}
	}
	return found
}

// addressOf takes "rfc822; Someone@Example.org" (or the utf-8 type of RFC 6533) to the form groups compare against.
func addressOf(field string) string {
	_, value, found := strings.Cut(field, ";")
	if !found {
		return ""
	}
	value = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(value), "<"), ">")
	address, ok := config.NormalizeAddress(value)
	if !ok {
		return ""
	}
	return address
}
