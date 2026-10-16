package pdf

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"

	xpdf "github.com/rom/xcrypto/scheme/pdf"
)

const (
	maxObjects = 500_000
	// maxObjNum bounds the object NUMBER we accept. The cross-reference table we
	// emit spans 0..maxObjNum, so an object carrying an implausibly large number
	// (far beyond maxObjects distinct objects) must not drive that loop — a
	// crafted "100000000000000000 0 obj" would otherwise make rebuild write an
	// exabyte-scale xref table (hang / OOM). Real PDFs number objects densely
	// from 1, so a number beyond the object-count ceiling is garbage.
	maxObjNum = maxObjects
)

var (
	reRootRef  = regexp.MustCompile(`/Root\s+(\d+\s+\d+\s+R)`)
	reLengthKV = regexp.MustCompile(`/Length\s+\d+`)
)

// rebuild decrypts every string and stream in the PDF and re-serializes a
// decrypted document with /Encrypt removed and a fresh cross-reference table.
// It is tolerant: it scans for objects and stream boundaries rather than relying
// on the original xref, and leaves anything it cannot confidently decrypt as-is.
func rebuild(data []byte, h *xpdf.Handler, key []byte) ([]byte, error) {
	encObjNum := encryptObjNum(data)
	rootRef := ""
	if m := reRootRef.FindSubmatch(data); m != nil {
		rootRef = string(m[1])
	}
	idArray := findArrayText(data, "/ID")

	type object struct {
		num, gen int
		body     []byte
	}
	var objs []object
	for _, loc := range reObjHdr.FindAllSubmatchIndex(data, -1) {
		if len(objs) >= maxObjects {
			break
		}
		num, _ := strconv.Atoi(string(data[loc[2]:loc[3]]))
		gen, _ := strconv.Atoi(string(data[loc[4]:loc[5]]))
		if num < 0 || num > maxObjNum {
			continue // implausible object number; would blow up the xref table
		}
		bodyStart := loc[1]
		rel := bytes.Index(data[bodyStart:], []byte("endobj"))
		if rel < 0 {
			continue
		}
		body := append([]byte(nil), data[bodyStart:bodyStart+rel]...)
		if num != encObjNum {
			body = decryptObject(body, h, key, num, gen)
		}
		objs = append(objs, object{num, gen, body})
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("pdf: no objects found to rebuild")
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	offsets := make(map[int]int)
	maxNum := 0
	for _, o := range objs {
		offsets[o.num] = buf.Len()
		if o.num > maxNum {
			maxNum = o.num
		}
		fmt.Fprintf(&buf, "%d %d obj", o.num, o.gen)
		buf.Write(o.body)
		buf.WriteString("endobj\n")
	}
	xrefOff := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", maxNum+1)
	for n := 1; n <= maxNum; n++ {
		if off, ok := offsets[n]; ok {
			fmt.Fprintf(&buf, "%010d 00000 n \n", off)
		} else {
			buf.WriteString("0000000000 65535 f \n")
		}
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d", maxNum+1)
	if rootRef != "" {
		buf.WriteString(" /Root " + rootRef)
	}
	if len(idArray) > 0 {
		buf.WriteString(" /ID ")
		buf.Write(idArray)
	}
	fmt.Fprintf(&buf, " >>\nstartxref\n%d\n%%%%EOF\n", xrefOff)
	return buf.Bytes(), nil
}

// decryptObject decrypts the strings in an object's dictionary and its stream
// data (if any), updating a direct /Length.
func decryptObject(body []byte, h *xpdf.Handler, key []byte, num, gen int) []byte {
	m := reStreamK.FindIndex(body)
	if m == nil {
		return decryptDictStrings(body, h, key, num, gen)
	}
	preEnd := m[0] + 1 // include the delimiter char before "stream"
	dataStart := m[1]  // after "stream\r?\n"
	rel := bytes.Index(body[dataStart:], []byte("endstream"))
	if rel < 0 {
		return decryptDictStrings(body, h, key, num, gen)
	}
	streamData := body[dataStart : dataStart+rel]
	// a single EOL immediately before endstream is not part of the data
	streamData = bytes.TrimSuffix(streamData, []byte("\r\n"))
	streamData = bytes.TrimSuffix(streamData, []byte("\n"))

	dec, err := h.DecryptData(key, num, gen, streamData)
	if err != nil {
		dec = streamData // leave as-is on failure
	}
	pre := decryptDictStrings(body[:preEnd], h, key, num, gen)
	pre = updateDirectLength(pre, len(dec))
	tail := body[dataStart+rel+len("endstream"):]

	var out bytes.Buffer
	out.Write(pre)
	out.WriteString("stream\n")
	out.Write(dec)
	out.WriteString("\nendstream")
	out.Write(tail)
	return out.Bytes()
}

// decryptDictStrings decrypts every literal/hex string in b (respecting << >>
// delimiters), re-emitting each as a hex string.
func decryptDictStrings(b []byte, h *xpdf.Handler, key []byte, num, gen int) []byte {
	var out []byte
	for pos := 0; pos < len(b); {
		c := b[pos]
		if c == '<' && pos+1 < len(b) && b[pos+1] == '<' {
			out = append(out, '<', '<')
			pos += 2
			continue
		}
		if c == '>' && pos+1 < len(b) && b[pos+1] == '>' {
			out = append(out, '>', '>')
			pos += 2
			continue
		}
		if c == '(' || (c == '<' && (pos+1 >= len(b) || b[pos+1] != '<')) {
			if s, next, ok := parseString(b, pos); ok {
				if dec, err := h.DecryptData(key, num, gen, s); err == nil {
					out = append(out, '<')
					out = append(out, []byte(hex.EncodeToString(dec))...)
					out = append(out, '>')
					pos = next
					continue
				}
			}
		}
		out = append(out, c)
		pos++
	}
	return out
}

func updateDirectLength(dict []byte, newLen int) []byte {
	loc := reLengthKV.FindIndex(dict)
	if loc == nil {
		return dict
	}
	// If it is actually an indirect reference (/Length N G R), leave it alone.
	after := dict[loc[1]:]
	if regexp.MustCompile(`^\s+\d+\s+R`).Match(after) {
		return dict
	}
	var out bytes.Buffer
	out.Write(dict[:loc[0]])
	fmt.Fprintf(&out, "/Length %d", newLen)
	out.Write(dict[loc[1]:])
	return out.Bytes()
}

func encryptObjNum(data []byte) int {
	ei := bytes.LastIndex(data, []byte("/Encrypt"))
	if ei < 0 {
		return -1
	}
	m := reRef.FindSubmatch(data[ei+len("/Encrypt"):])
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// findArrayText returns the verbatim "[ ... ]" that follows key, or nil.
func findArrayText(data []byte, key string) []byte {
	i := bytes.LastIndex(data, []byte(key))
	if i < 0 {
		return nil
	}
	rest := data[i+len(key):]
	open := bytes.IndexByte(rest, '[')
	if open < 0 || open > 8 {
		return nil
	}
	close := bytes.IndexByte(rest[open:], ']')
	if close < 0 {
		return nil
	}
	return rest[open : open+close+1]
}
