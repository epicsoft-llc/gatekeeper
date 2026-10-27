package bounce

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/epicsoft-networks/gatekeeper/internal/config"
)

func sample(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParsePostfix(t *testing.T) {
	want := Recipient{Final: "nobody-here@example.test", Original: "nobody-here@example.test", Action: "failed", Status: "5.1.1"}
	recipients, err := Parse(sample(t, "postfix.eml"))
	if err != nil || len(recipients) != 1 || recipients[0] != want || !recipients[0].Failed() {
		t.Errorf("%+v, %v", recipients, err)
	}
}

// exchange takes the form of the real bounces of Exchange Online and Outlook.com in sisimai/set-of-emails
// (lhost-office365-13.eml, lhost-outlook-09.eml), which stay out of the repository for their BSD 2-Clause License:
// a quoted boundary with '=' and '?', the text as multipart/alternative first, no space after "rfc822;", 5.1.10.
const exchange = "From: postmaster@outlook.example\r\n" +
	"To: gate+b-abcdefghijklmnopqrstuvwxyz@example.com\r\n" +
	"Subject: Undeliverable: Your sign-in code\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"=_b?1\"\r\n" +
	"\r\n" +
	"--=_b?1\r\n" +
	"Content-Type: multipart/alternative; boundary=\"inner\"\r\n" +
	"\r\n" +
	"--inner\r\n" +
	"Content-Type: text/plain; charset=\"us-ascii\"\r\n" +
	"\r\n" +
	"Delivery has failed to these recipients or groups:\r\n" +
	"--inner\r\n" +
	"Content-Type: text/html; charset=\"us-ascii\"\r\n" +
	"\r\n" +
	"<html><body>Delivery has failed</body></html>\r\n" +
	"--inner--\r\n" +
	"\r\n" +
	"--=_b?1\r\n" +
	"Content-Type: message/delivery-status\r\n" +
	"\r\n" +
	"Reporting-MTA: dns;mail.outlook.example\r\n" +
	"Received-From-MTA: dns;mx.example.com\r\n" +
	"Arrival-Date: Tue, 27 Oct 2026 08:00:00 +0000\r\n" +
	"\r\n" +
	"Final-Recipient: rfc822;someone@example.org\r\n" +
	"Action: failed\r\n" +
	"Status: 5.1.10\r\n" +
	"Diagnostic-Code: smtp;550 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup\r\n" +
	"\r\n" +
	"--=_b?1\r\n" +
	"Content-Type: message/rfc822\r\n" +
	"\r\n" +
	"From: gate@example.com\r\n" +
	"To: someone@example.org\r\n" +
	"Subject: Your sign-in code\r\n" +
	"\r\n" +
	"The code\r\n" +
	"--=_b?1--\r\n"

func TestParseExchange(t *testing.T) {
	want := Recipient{Final: "someone@example.org", Action: "failed", Status: "5.1.10"}
	recipients, err := Parse([]byte(exchange))
	if err != nil || len(recipients) != 1 || recipients[0] != want || !recipients[0].Failed() {
		t.Errorf("%+v, %v", recipients, err)
	}
}

const report = "From: Mail Delivery System <MAILER-DAEMON@mx.example.org>\r\n" +
	"To: gate+b-abcdefghijklmnopqrstuvwxyz@example.com\r\n" +
	"Subject: Undelivered Mail\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/report; report-type=TYPE; boundary=\"b\"\r\n" +
	"\r\n" +
	"--b\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"The mail could not be delivered.\r\n" +
	"--b\r\n" +
	"Content-Type: PART\r\n" +
	"ENCODING" +
	"\r\n" +
	"STATUS\r\n" +
	"--b--\r\n"

func build(reportType, part, encoding, status string) []byte {
	return []byte(strings.NewReplacer("TYPE", reportType, "PART", part, "ENCODING", encoding, "STATUS", status).Replace(report))
}

func TestParseVariants(t *testing.T) {
	perMessage := "Reporting-MTA: dns; mx.example.org\r\n\r\n"
	cases := []struct {
		name    string
		message []byte
		want    []Recipient
		failed  []bool
	}{
		{"delay warning", build("delivery-status", "message/delivery-status", "", perMessage+"Final-Recipient: rfc822; a@example.org\r\nAction: delayed\r\nStatus: 4.4.1\r\n"),
			[]Recipient{{Final: "a@example.org", Action: "delayed", Status: "4.4.1"}}, []bool{false}},
		{"given up after a delay", build("delivery-status", "message/delivery-status", "", perMessage+"Final-Recipient: rfc822; a@example.org\r\nAction: Failed\r\nStatus: 4.4.7\r\n"),
			[]Recipient{{Final: "a@example.org", Action: "failed", Status: "4.4.7"}}, []bool{true}},
		{"delivered", build("delivery-status", "message/delivery-status", "", perMessage+"Final-Recipient: rfc822; a@example.org\r\nAction: delivered\r\nStatus: 2.0.0\r\n"),
			[]Recipient{{Final: "a@example.org", Action: "delivered", Status: "2.0.0"}}, []bool{false}},
		{"two recipients, folded", build("delivery-status", "message/delivery-status", "", perMessage+"Final-Recipient: rfc822;\r\n <A@Example.org>\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n\r\nFinal-Recipient: rfc822; b@example.org\r\nOriginal-Recipient: rfc822; c@example.org\r\nAction: failed\r\nStatus: 5.2.2\r\n"),
			[]Recipient{{Final: "a@example.org", Action: "failed", Status: "5.1.1"}, {Final: "b@example.org", Original: "c@example.org", Action: "failed", Status: "5.2.2"}}, []bool{true, true}},
		{"global", build("global-delivery-status", "message/global-delivery-status", "", perMessage+"Final-Recipient: utf-8; a@example.org\r\nAction: failed\r\nStatus: 5.1.1\r\n"),
			[]Recipient{{Final: "a@example.org", Action: "failed", Status: "5.1.1"}}, []bool{true}},
		{"base64", build("delivery-status", "message/delivery-status", "Content-Transfer-Encoding: base64\r\n", base64.StdEncoding.EncodeToString([]byte(perMessage+"Final-Recipient: rfc822; a@example.org\r\nAction: failed\r\nStatus: 5.1.1\r\n"))),
			[]Recipient{{Final: "a@example.org", Action: "failed", Status: "5.1.1"}}, []bool{true}},
		{"no usable address", build("delivery-status", "message/delivery-status", "", perMessage+"Final-Recipient: rfc822; a b@example.org\r\nAction: failed\r\nStatus: 5.1.1\r\n"),
			[]Recipient{{Action: "failed", Status: "5.1.1"}}, []bool{true}},
		{"empty status part, as Google sent one", build("delivery-status", "message/delivery-status", "", ""), nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			recipients, err := Parse(c.message)
			if err != nil || len(recipients) != len(c.want) {
				t.Fatalf("%+v, %v", recipients, err)
			}
			for i := range recipients {
				if recipients[i] != c.want[i] || recipients[i].Failed() != c.failed[i] {
					t.Errorf("recipient %d: %+v, failed %v", i, recipients[i], recipients[i].Failed())
				}
			}
		})
	}
}

func TestParseRefuses(t *testing.T) {
	status := "Final-Recipient: rfc822; a@example.org\r\nAction: failed\r\nStatus: 5.1.1\r\n"
	cases := map[string][]byte{
		"plain text":                []byte("From: MAILER-DAEMON@example.org\r\nSubject: failure\r\n\r\nThe mail to a@example.org failed: 550 5.1.1\r\n"),
		"read receipt":              build("disposition-notification", "message/disposition-notification", "", status),
		"no status part":            build("delivery-status", "text/plain", "", status),
		"no boundary":               []byte("Content-Type: multipart/report; report-type=delivery-status\r\n\r\n" + status),
		"mixed":                     []byte(strings.Replace(string(build("delivery-status", "message/delivery-status", "", status)), "multipart/report", "multipart/mixed", 1)),
		"no header":                 []byte(status),
		"unterminated":              []byte(strings.TrimSuffix(string(build("delivery-status", "text/plain", "", "x")), "--b--\r\n")),
		"report of an auto-replier": []byte("To: gate+b-abcdefghijklmnopqrstuvwxyz@example.com\r\nSubject: Out of office\r\nAuto-Submitted: auto-replied\r\n\r\nBack on Monday.\r\n"),
	}
	for name, message := range cases {
		if recipients, err := Parse(message); err == nil {
			t.Errorf("%s: parsed as %+v", name, recipients)
		}
	}
	if _, err := Parse(cases["plain text"]); !errors.Is(err, errNoReport) {
		t.Errorf("plain text: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample(f, "postfix.eml"))
	f.Add([]byte(exchange))
	f.Add(build("delivery-status", "message/delivery-status", "Content-Transfer-Encoding: base64\r\n", "RmluYWwtUmVjaXBpZW50OiByZmM4MjI7IGFAZXhhbXBsZS5vcmc="))
	f.Fuzz(func(t *testing.T, message []byte) {
		recipients, err := Parse(message)
		if err != nil {
			return
		}
		for _, r := range recipients {
			for _, address := range []string{r.Final, r.Original} {
				if normalized, ok := config.NormalizeAddress(address); address != "" && (!ok || normalized != address) {
					t.Errorf("%q is not an address groups compare against", address)
				}
			}
			if r.Failed() && r.Action != "failed" {
				t.Errorf("%+v counts as failed", r)
			}
		}
	})
}
