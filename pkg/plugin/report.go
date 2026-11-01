package plugin

import "context"

// ReportMail is one scheduled report (#34 report subscriptions).
type ReportMail struct {
	// Subscription and Report name what is sent; Subject is the subject
	// line (the notifier may add its own prefix).
	Subscription string
	Report       string
	Subject      string
	// Text is the plain-text body.
	Text string
	// HTML is an optional HTML body. When set, a sender that supports it
	// sends the text and the HTML as alternatives and shows Inline images
	// in the HTML by their ContentID ("cid:" URLs).
	HTML   string
	Inline []Attachment
	// To overrides the notifier's recipients when not empty. It comes
	// from the config file, never from an API request.
	To          []string
	Attachments []Attachment
}

// Attachment is one file sent with a report.
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
	// ContentID names an Inline image for "cid:" references; it is empty
	// on a downloadable attachment.
	ContentID string
}

// ReportSender is optional on a Notifier: it sends a stored report on a
// report subscription's schedule. The built-in smtp notifier implements
// it. It must not announce or change decisions.
type ReportSender interface {
	SendReport(ctx context.Context, m ReportMail) error
}
