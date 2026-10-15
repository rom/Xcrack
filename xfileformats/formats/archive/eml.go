package archive

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"

	"github.com/rom/xfileformats"
)

const maxMIMEDepth = 16

type emlFormat struct{}

func (emlFormat) Name() string            { return "eml" }
func (emlFormat) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

// Detect recognizes RFC822/MIME email conservatively: a header line up front
// plus a MIME marker, so it does not claim arbitrary text.
func (emlFormat) Detect(p []byte) (float64, bool) {
	head := p
	if len(head) > 2048 {
		head = head[:2048]
	}
	// first line must look like a header "Name: value"
	nl := bytes.IndexByte(head, '\n')
	first := head
	if nl >= 0 {
		first = head[:nl]
	}
	if !looksLikeHeader(first) {
		return 0, false
	}
	low := strings.ToLower(string(head))
	if strings.Contains(low, "mime-version:") ||
		(strings.Contains(low, "content-type:") && (strings.Contains(low, "from:") || strings.Contains(low, "subject:") || strings.Contains(low, "boundary="))) {
		return 0.6, true
	}
	return 0, false
}

func looksLikeHeader(line []byte) bool {
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return false
	}
	for _, c := range line[:i] {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (emlFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	data, err := io.ReadAll(io.LimitReader(section(r, size), maxDecompressed))
	if err != nil {
		return nil, xfileformats.ErrMalformed
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, xfileformats.ErrMalformed
	}
	var entries []*xfileformats.Entry
	walkMIME(
		msg.Header.Get("Content-Type"),
		msg.Header.Get("Content-Transfer-Encoding"),
		"", msg.Body, &entries, 0)
	if len(entries) == 0 { // no parts parsed: hand back the raw body as one entry
		body, _ := io.ReadAll(io.LimitReader(msg.Body, maxDecompressed))
		entries = oneEntry("body.txt", int64(len(body)), func() (io.Reader, error) { return bytes.NewReader(body), nil })
	}
	return entries, nil
}

func walkMIME(ctype, cte, filename string, body io.Reader, entries *[]*xfileformats.Entry, depth int) {
	if len(*entries) >= maxEntries || depth > maxMIMEDepth {
		return
	}
	mediaType, params, _ := mime.ParseMediaType(ctype)
	if strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "" {
		mr := multipart.NewReader(body, params["boundary"])
		for len(*entries) < maxEntries {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			walkMIME(
				part.Header.Get("Content-Type"),
				part.Header.Get("Content-Transfer-Encoding"),
				part.FileName(),
				part, entries, depth+1)
		}
		return
	}
	// leaf part: decode the transfer encoding
	decoded, err := io.ReadAll(io.LimitReader(decodeCTE(cte, body), maxDecompressed))
	if err != nil {
		return
	}
	name := filename
	if name == "" {
		name = params["name"]
	}
	if name == "" {
		name = fmt.Sprintf("part-%d", len(*entries)+1)
	}
	name = sanitize(name)
	if name == "" {
		name = fmt.Sprintf("part-%d", len(*entries)+1)
	}
	*entries = append(*entries, &xfileformats.Entry{
		Path: name,
		Size: int64(len(decoded)),
		Open: func([]byte) (io.Reader, error) { return bytes.NewReader(decoded), nil },
	})
}

func decodeCTE(cte string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}
