package smtp

import (
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strconv"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestSendReport(t *testing.T) {
	f := newFake(t, &fakeServer{})
	// The event filter applies to events, not to report subscriptions.
	y := "host: 127.0.0.1\ntls: none\nport: " + strconv.Itoa(f.port()) +
		"\nfrom: packeteer@example.invalid\nto: [noc@example.invalid]\nevents: [\"commit.*\"]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	rs, ok := n.(plugin.ReportSender)
	if !ok {
		t.Fatal("smtp does not send reports")
	}
	csv := strings.Repeat("prefix,provider\r\n198.51.100.0/24,transit-b\r\n", 20)
	err = rs.SendReport(context.Background(), plugin.ReportMail{
		Subscription: "weekly", Report: "summary", Subject: "summary report\r\nBcc: victim@example.invalid",
		Text: "Packeteer summary\nline two", To: []string{"ops@example.invalid", "Team <team@example.invalid>"},
		Attachments: []plugin.Attachment{{Name: `summary"x.csv`, ContentType: "text/csv", Data: []byte(csv)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rcpt) != 2 || !strings.Contains(f.rcpt[0], "ops@example.invalid") || !strings.Contains(f.rcpt[1], "team@example.invalid") {
		t.Fatalf("rcpt = %v (the subscription's to replaces the notifier's)", f.rcpt)
	}
	msg, err := mail.ReadMessage(strings.NewReader(f.data))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Bcc") != "" || msg.Header.Get("X-Packeteer-Subscription") != "weekly" || msg.Header.Get("X-Packeteer-Report") != "summary" {
		t.Fatalf("headers = %v", msg.Header)
	}
	subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if !strings.HasPrefix(subj, "[packeteer] summary report") {
		t.Fatalf("subject = %q", subj)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("content type %q %v", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	text, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(text))
	if string(body) != "Packeteer summary\r\nline two" {
		t.Fatalf("text = %q", body)
	}
	att, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if att.FileName() != "summary_x.csv" || att.Header.Get("Content-Type") != "text/csv" {
		t.Fatalf("attachment %q %q", att.FileName(), att.Header.Get("Content-Type"))
	}
	raw, _ := io.ReadAll(att)
	dec, err := decodeB64(string(raw))
	if err != nil || dec != csv {
		t.Fatalf("attachment = %q %v", dec, err)
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Fatalf("extra part: %v", err)
	}
}

func TestSendReportDefaultRecipients(t *testing.T) {
	f := newFake(t, &fakeServer{})
	y := "host: 127.0.0.1\ntls: none\nport: " + strconv.Itoa(f.port()) + "\nfrom: packeteer@example.invalid\nto: [noc@example.invalid]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.(plugin.ReportSender).SendReport(context.Background(), plugin.ReportMail{Subject: "s", Text: "t"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rcpt) != 1 || !strings.Contains(f.rcpt[0], "noc@example.invalid") {
		t.Fatalf("rcpt = %v", f.rcpt)
	}
	if err := n.(plugin.ReportSender).SendReport(context.Background(), plugin.ReportMail{To: []string{"bad"}}); err == nil {
		t.Fatal("bad address accepted")
	}
}

func decodeB64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(s))
	return string(b), err
}
