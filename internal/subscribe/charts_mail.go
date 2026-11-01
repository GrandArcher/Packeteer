package subscribe

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// bucketLabels are the destination buckets as /graphs.html names them.
var bucketLabels = map[string]string{
	history.BucketAll:      "All destinations",
	history.BucketProblem:  "Problem prefixes",
	history.BucketBetter20: "20% or more better",
	history.BucketBetter50: "50% or more better",
}

type mailChart struct {
	CID, Title, Alt string
}

type mailBucket struct {
	Label  string
	Days   int
	Charts []mailChart
}

var chartsHTML = template.Must(template.New("charts").Parse(`<!DOCTYPE html>
<html><body style="font-family: sans-serif; color: #333333;">
<h2 style="font-size: 18px;">{{.Report}} report</h2>
<p>Range: {{.From}} to {{.To}} UTC, {{.Days}} day(s). The rows are attached as CSV.</p>
{{if .Buckets}}<p><span style="color: #D55E00;"><b>Dashed orange</b>: before, the native path.</span>
<span style="color: #0072B2;"><b>Solid blue</b>: after, the chosen path.</span> One point per UTC day.</p>
{{range .Buckets}}<h3 style="font-size: 15px;">{{.Label}} ({{.Days}} day(s) with data)</h3>
{{range .Charts}}<p style="margin-bottom: 2px;"><b>{{.Title}}</b><br><img src="cid:{{.CID}}" alt="{{.Alt}}" width="640" height="240"></p>
{{end}}{{end}}{{else}}<p>No before/after data in this range. A day needs an improvement and probe history for both its native and its chosen provider.</p>
{{end}}</body></html>
`))

// addCharts adds the HTML body and one inline PNG per metric and bucket
// that has rows. The loss chart is in percent and the latency chart in
// milliseconds.
func addCharts(m *plugin.ReportMail, rows []history.TimeSeriesRow, from, to time.Time) error {
	data := struct {
		Report, From, To string
		Days             int
		Buckets          []mailBucket
	}{Report: m.Report, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339),
		Days: int(to.Sub(from).Round(time.Hour) / (24 * time.Hour))}
	for _, bucket := range history.Buckets {
		var in []history.TimeSeriesRow
		for _, r := range rows {
			if r.Bucket == bucket {
				in = append(in, r)
			}
		}
		if len(in) == 0 {
			continue
		}
		mb := mailBucket{Label: bucketLabels[bucket], Days: len(in)}
		for _, metric := range chartMetrics {
			img, err := chartPNG(in, from, to, metric)
			if err != nil {
				return err
			}
			cid := fmt.Sprintf("%s-%s@packeteer.invalid", bucket, metric.id)
			m.Inline = append(m.Inline, plugin.Attachment{Name: fmt.Sprintf("%s-%s.png", bucket, metric.id), ContentType: "image/png", Data: img, ContentID: cid})
			mb.Charts = append(mb.Charts, mailChart{CID: cid, Title: fmt.Sprintf("%s (%s)", metric.title, metric.unit), Alt: fmt.Sprintf("%s (%s), %s: dashed line before, solid line after, one point per day", metric.title, metric.unit, mb.Label)})
		}
		data.Buckets = append(data.Buckets, mb)
	}
	var out bytes.Buffer
	if err := chartsHTML.Execute(&out, data); err != nil {
		return err
	}
	m.HTML = out.String()
	return nil
}
