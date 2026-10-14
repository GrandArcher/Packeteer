package history

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
)

// XLSXContentType is the media type of a workbook.
const XLSXContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

const (
	xmlHeader  = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"
	nsMain     = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
	nsRel      = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	nsPkgRel   = "http://schemas.openxmlformats.org/package/2006/relationships"
	relOffice  = nsRel + "/officeDocument"
	relSheet   = nsRel + "/worksheet"
	relStyles  = nsRel + "/styles"
	boldHeader = 1
)

// XLSX writes the report as a one-sheet workbook: a bold header row of
// column labels with units, then the same rows as CSV. Numbers are numeric
// cells and everything else is text, so a value that looks like a formula
// is never evaluated. It uses only the standard library.
func (r Report) XLSX(w io.Writer) error {
	zw := zip.NewWriter(w)
	files := []struct{ name, body string }{
		{"[Content_Types].xml", xmlHeader + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
			`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
			`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`},
		{"_rels/.rels", xmlHeader + `<Relationships xmlns="` + nsPkgRel + `"><Relationship Id="rId1" Type="` + relOffice + `" Target="xl/workbook.xml"/></Relationships>`},
		// Names come from the fixed catalog (12 bytes at most, no XML characters);
		// escape and cap them at 31 characters if they ever become user-defined.
		{"xl/workbook.xml", xmlHeader + `<workbook xmlns="` + nsMain + `" xmlns:r="` + nsRel + `"><sheets><sheet name="` + r.Name + `" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", xmlHeader + `<Relationships xmlns="` + nsPkgRel + `">` +
			`<Relationship Id="rId1" Type="` + relSheet + `" Target="worksheets/sheet1.xml"/>` +
			`<Relationship Id="rId2" Type="` + relStyles + `" Target="styles.xml"/></Relationships>`},
		{"xl/styles.xml", xmlHeader + `<styleSheet xmlns="` + nsMain + `">` +
			`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>` +
			`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
			`<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
			`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
			`<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
			`<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>`},
	}
	for _, f := range files {
		if err := writeZipFile(zw, f.name, f.body); err != nil {
			return err
		}
	}
	sw, err := zw.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		return err
	}
	if err := r.writeSheet(sw); err != nil {
		return err
	}
	return zw.Close()
}

func writeZipFile(zw *zip.Writer, name, body string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, body)
	return err
}

func (r Report) writeSheet(w io.Writer) error {
	if _, err := io.WriteString(w, xmlHeader+`<worksheet xmlns="`+nsMain+`"><sheetViews><sheetView workbookViewId="0">`+
		`<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetData>`); err != nil {
		return err
	}
	head := make([]string, len(r.Columns))
	for i, c := range r.Columns {
		head[i] = c.Label
		if c.Unit != "" {
			head[i] += " (" + c.Unit + ")"
		}
	}
	if err := writeRow(w, 1, head, nil); err != nil {
		return err
	}
	for i, line := range r.lines {
		if err := writeRow(w, i+2, line, r.Columns); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, `</sheetData></worksheet>`)
	return err
}

// writeRow writes one row. With cols nil it is the header: bold text.
func writeRow(w io.Writer, n int, cells []string, cols []Column) error {
	if _, err := fmt.Fprintf(w, `<row r="%d">`, n); err != nil {
		return err
	}
	for i, v := range cells {
		if v == "" {
			continue
		}
		ref := colName(i) + strconv.Itoa(n)
		numeric := false
		if cols != nil && cols[i].Type == TypeNumber {
			_, perr := strconv.ParseFloat(v, 64)
			numeric = perr == nil
		}
		var err error
		switch {
		case cols == nil:
			_, err = fmt.Fprintf(w, `<c r="%s" s="%d" t="inlineStr"><is><t>`, ref, boldHeader)
		case numeric:
			_, err = fmt.Fprintf(w, `<c r="%s"><v>`, ref)
		default:
			_, err = fmt.Fprintf(w, `<c r="%s" t="inlineStr"><is><t xml:space="preserve">`, ref)
		}
		if err != nil {
			return err
		}
		if err := xml.EscapeText(w, []byte(v)); err != nil {
			return err
		}
		end := `</t></is></c>`
		if numeric {
			end = `</v></c>`
		}
		if _, err := io.WriteString(w, end); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, `</row>`)
	return err
}

// colName is the spreadsheet column letters for a zero-based index.
func colName(i int) string {
	s := ""
	for i++; i > 0; i = (i - 1) / 26 {
		s = string(rune('A'+(i-1)%26)) + s
	}
	return s
}
