package subscribe

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"math"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
)

// Chart size, plot margins, dash pattern, and glyph metrics, in pixels.
const (
	chartW, chartH                         = 640, 240
	marginL, marginR, marginT, marginB     = 44, 14, 12, 24
	dashOn, dashPeriod                     = 6, 10
	secondsPerDay                          = 24 * 60 * 60
	glyphW, glyphH, glyphAdvance, glyphGap = 5, 7, 6, 3
)

// Before is dashed and After is solid, as on /graphs.html, so the two stay
// apart without color. The colors are a color-blind-safe pair.
var (
	colBefore = color.RGBA{0xD5, 0x5E, 0x00, 0xFF}
	colAfter  = color.RGBA{0x00, 0x72, 0xB2, 0xFF}
	colText   = color.RGBA{0x33, 0x33, 0x33, 0xFF}
	colAxis   = color.RGBA{0x66, 0x66, 0x66, 0xFF}
	colGrid   = color.RGBA{0xDD, 0xDD, 0xDD, 0xFF}
	colBack   = color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
)

// chartMetric is one plotted quantity of a timeseries row.
type chartMetric struct {
	id, title, unit string
	before, after   func(history.TimeSeriesRow) float64
}

var chartMetrics = []chartMetric{
	{"loss", "Loss", "%",
		func(r history.TimeSeriesRow) float64 { return r.BeforeLossPct },
		func(r history.TimeSeriesRow) float64 { return r.AfterLossPct }},
	{"rtt", "Latency", "ms",
		func(r history.TimeSeriesRow) float64 { return r.BeforeRTTMs },
		func(r history.TimeSeriesRow) float64 { return r.AfterRTTMs }},
}

type point struct {
	day int
	v   float64
}

// chartPNG draws one metric of one bucket's rows between the days of from
// and to: a dashed before line and a solid after line, one point per UTC
// day. A day with no row breaks the line, and a lone day is a square.
// Labels are digits only; the caption with the title and unit is in the
// email HTML, so no font is needed.
func chartPNG(rows []history.TimeSeriesRow, from, to time.Time, m chartMetric) ([]byte, error) {
	var before, after []point
	first, last := math.MaxInt, math.MinInt
	maxV := 0.0
	for _, r := range rows {
		t, err := time.Parse(time.DateOnly, r.Day)
		if err != nil {
			continue
		}
		d := int(t.Unix() / secondsPerDay)
		first, last = min(first, d), max(last, d)
		b, a := m.before(r), m.after(r)
		before, after = append(before, point{d, b}), append(after, point{d, a})
		maxV = max(maxV, b, a)
	}
	if len(before) == 0 {
		return nil, errors.New("no rows with a valid day")
	}
	// The range ends at to, so a midnight to has no day of its own.
	first = min(first, int(from.UTC().Unix()/secondsPerDay))
	endDay := int(to.UTC().Unix() / secondsPerDay)
	if to.UTC().Equal(to.UTC().Truncate(24 * time.Hour)) {
		endDay--
	}
	last = max(last, endDay)
	ticks := chartTicks(maxV)
	top := ticks[len(ticks)-1]

	img := image.NewRGBA(image.Rect(0, 0, chartW, chartH))
	fill(img, img.Bounds(), colBack)
	plotL, plotR, plotT, plotB := marginL, chartW-marginR, marginT, chartH-marginB
	xOf := func(d int) int {
		if last == first {
			return (plotL + plotR) / 2
		}
		return plotL + (plotR-plotL)*(d-first)/(last-first)
	}
	yOf := func(v float64) int { return plotB - int(math.Round(float64(plotB-plotT)*v/top)) }

	for _, tv := range ticks {
		y := yOf(tv)
		hline(img, plotL, plotR, y, colGrid)
		s := formatTick(tv)
		drawText(img, plotL-glyphGap-textWidth(s), y-glyphH/2, s, colText)
	}
	hline(img, plotL, plotR, plotB, colAxis)
	vline(img, plotL, plotT, plotB, colAxis)
	labelled := map[int]bool{}
	for _, d := range []int{first, first + (last-first)/2, last} {
		if labelled[d] {
			continue
		}
		labelled[d] = true
		s := time.Unix(int64(d)*secondsPerDay, 0).UTC().Format("01-02")
		x := min(max(xOf(d)-textWidth(s)/2, 0), chartW-textWidth(s))
		drawText(img, x, plotB+glyphGap+2, s, colText)
	}
	plotLine(img, before, xOf, yOf, colBefore, true)
	plotLine(img, after, xOf, yOf, colAfter, false)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// plotLine joins points on consecutive days. Points are squares so that a
// single day still shows.
func plotLine(img *image.RGBA, pts []point, xOf func(int) int, yOf func(float64) int, c color.RGBA, dashed bool) {
	phase := 0
	for i, p := range pts {
		x, y := xOf(p.day), yOf(p.v)
		fill(img, image.Rect(x-2, y-2, x+3, y+3), c)
		if i > 0 && pts[i-1].day+1 == p.day {
			phase = segment(img, xOf(pts[i-1].day), yOf(pts[i-1].v), x, y, c, dashed, phase)
		} else {
			phase = 0
		}
	}
}

// segment draws a 2-pixel line with Bresenham's algorithm and returns the
// dash phase to continue with.
func segment(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA, dashed bool, phase int) int {
	dx, dy := abs(x1-x0), -abs(y1-y0)
	sx, sy := sign(x1-x0), sign(y1-y0)
	e := dx + dy
	for {
		if !dashed || phase%dashPeriod < dashOn {
			fill(img, image.Rect(x0, y0, x0+2, y0+2), c)
		}
		phase++
		if x0 == x1 && y0 == y1 {
			return phase
		}
		e2 := 2 * e
		if e2 >= dy {
			e += dy
			x0 += sx
		}
		if e2 <= dx {
			e += dx
			y0 += sy
		}
	}
}

func abs(v int) int { return max(v, -v) }

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	}
	return 0
}

func fill(img *image.RGBA, r image.Rectangle, c color.RGBA) {
	r = r.Intersect(img.Bounds())
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			img.SetRGBA(x, y, c)
		}
	}
}

func hline(img *image.RGBA, x0, x1, y int, c color.RGBA) { fill(img, image.Rect(x0, y, x1+1, y+1), c) }
func vline(img *image.RGBA, x, y0, y1 int, c color.RGBA) { fill(img, image.Rect(x, y0, x+1, y1+1), c) }

// chartTicks returns round tick values from 0 up to at least max, at most
// five of them, as the dashboard chart does.
func chartTicks(max float64) []float64 {
	if !(max > 0) {
		return []float64{0, 1}
	}
	pow := math.Pow(10, math.Floor(math.Log10(max)))
	step := pow * 10
	for _, s := range []float64{1, 2, 2.5, 5, 10} {
		if s*pow*4 >= max {
			step = s * pow
			break
		}
	}
	var out []float64
	for v := 0.0; v < max+step*0.999; v += step {
		out = append(out, math.Round(v*1000)/1000)
	}
	return out
}

func formatTick(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// glyphs is a 5x7 bitmap font of the characters a tick or date label uses;
// bit 4 of a row is the leftmost pixel.
var glyphs = map[rune][glyphH]uint8{
	'0': {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E},
	'1': {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E},
	'2': {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F},
	'3': {0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E},
	'4': {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02},
	'5': {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E},
	'6': {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E},
	'7': {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
	'8': {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E},
	'9': {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C},
	'.': {0, 0, 0, 0, 0, 0x0C, 0x0C},
	'-': {0, 0, 0, 0, 0x1F, 0, 0},
}

func textWidth(s string) int { return len(s)*glyphAdvance - 1 }

func drawText(img *image.RGBA, x, y int, s string, c color.RGBA) {
	for _, r := range s {
		g := glyphs[r]
		for row := range glyphH {
			for col := range glyphW {
				if g[row]&(1<<(glyphW-1-col)) != 0 {
					img.SetRGBA(x+col, y+row, c)
				}
			}
		}
		x += glyphAdvance
	}
}
