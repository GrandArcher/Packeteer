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

func TestSendReportWithHTMLAndInlineImages(t *testing.T) {
	f := newFake(t, &fakeServer{})
	y := "host: 127.0.0.1\ntls: none\nport: " + strconv.Itoa(f.port()) + "\nfrom: packeteer@example.invalid\nto: [noc@example.invalid]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	png := []byte("\x89PNG\r\n\x1a\nnot really an image, but binary \x00\x01\x02")
	html := "<html><body><p>Caf\u00e9 report</p><img src=\"cid:loss@packeteer.invalid\"></body></html>"
	err = n.(plugin.ReportSender).SendReport(context.Background(), plugin.ReportMail{
		Subscription: "graphs", Report: "timeseries", Subject: "timeseries report",
		Text: "plain body", HTML: html,
		Inline:      []plugin.Attachment{{Name: "loss.png", ContentType: "image/png", Data: png, ContentID: "<loss@packeteer.invalid>"}},
		Attachments: []plugin.Attachment{{Name: "timeseries.csv", ContentType: "text/csv", Data: []byte("day,bucket\r\n")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	msg, err := mail.ReadMessage(strings.NewReader(f.data))
	if err != nil {
		t.Fatal(err)
	}
	next := func(mr *multipart.Reader, wantType string) *multipart.Part {
		t.Helper()
		p, err := mr.NextPart()
		if err != nil {
			t.Fatalf("want %s part: %v", wantType, err)
		}
		if mt, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type")); mt != wantType {
			t.Fatalf("part type %q, want %q", mt, wantType)
		}
		return p
	}
	sub := func(p *multipart.Part) *multipart.Reader {
		t.Helper()
		_, params, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		return multipart.NewReader(p, params["boundary"])
	}
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mixed := multipart.NewReader(msg.Body, params["boundary"])
	alt := sub(next(mixed, "multipart/alternative"))
	text := next(alt, "text/plain")
	if b, _ := io.ReadAll(quotedprintable.NewReader(text)); string(b) != "plain body" {
		t.Fatalf("text = %q", b)
	}
	rel := sub(next(alt, "multipart/related"))
	htmlPart := next(rel, "text/html")
	if b, _ := io.ReadAll(quotedprintable.NewReader(htmlPart)); !strings.Contains(string(b), `src="cid:loss@packeteer.invalid"`) || !strings.Contains(string(b), "Caf\u00e9") {
		t.Fatalf("html = %q", b)
	}
	img := next(rel, "image/png")
	if got := img.Header.Get("Content-ID"); got != "<loss@packeteer.invalid>" {
		t.Fatalf("Content-ID = %q", got)
	}
	if d, _, _ := mime.ParseMediaType(img.Header.Get("Content-Disposition")); d != "inline" {
		t.Fatalf("image disposition %q", d)
	}
	raw, _ := io.ReadAll(img)
	if dec, err := decodeB64(string(raw)); err != nil || dec != string(png) {
		t.Fatalf("image bytes differ: %v", err)
	}
	if _, err := rel.NextPart(); err != io.EOF {
		t.Fatalf("extra related part: %v", err)
	}
	if _, err := alt.NextPart(); err != io.EOF {
		t.Fatalf("extra alternative part: %v", err)
	}
	csv := next(mixed, "text/csv")
	if d, _, _ := mime.ParseMediaType(csv.Header.Get("Content-Disposition")); d != "attachment" || csv.FileName() != "timeseries.csv" {
		t.Fatalf("csv part %q %q", d, csv.FileName())
	}
	if _, err := mixed.NextPart(); err != io.EOF {
		t.Fatalf("extra part: %v", err)
	}
}
