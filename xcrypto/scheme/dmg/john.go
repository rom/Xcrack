package dmg

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// ErrFormat is returned by ParseJohn for input that is not a well-formed $dmg$
// line.
var ErrFormat = errors.New("dmg: not a $dmg$ hash line")

// ParseJohn parses a dmg2john `$dmg$` hash line into Params. Both header
// versions are supported:
//
//	$dmg$1*saltlen*salt*len*wrapped_aes*len*wrapped_hmac[*iterations]
//	$dmg$2*saltlen*salt*ivlen*iv*kbsize*keyblob*cno*datasize*chunk*scp[*zchunk][*iterations]
//
// A leading "name:" (dmg2john prepends the image filename) and a trailing
// ":..." (its optional comment/login tail) are both ignored.
func ParseJohn(line string) (Params, error) {
	i := strings.Index(line, "$dmg$")
	if i < 0 {
		return Params{}, ErrFormat
	}
	line = line[i:]
	if j := strings.IndexByte(line, ':'); j >= 0 {
		line = line[:j]
	}
	line = strings.TrimSpace(line)
	f := strings.Split(line[len("$dmg$"):], "*")
	if len(f) < 1 {
		return Params{}, ErrFormat
	}
	ver, err := strconv.Atoi(f[0])
	if err != nil {
		return Params{}, ErrFormat
	}
	switch ver {
	case 1:
		return parseV1(f)
	case 2:
		return parseV2(f)
	default:
		return Params{}, ErrFormat
	}
}

func parseV1(f []string) (Params, error) {
	// version, saltlen, salt, len1, key1, len2, key2 [, iterations]
	if len(f) < 7 {
		return Params{}, ErrFormat
	}
	salt, err := hexField(f[2])
	if err != nil {
		return Params{}, err
	}
	aesKey, err := hexField(f[4])
	if err != nil {
		return Params{}, err
	}
	hmacKey, err := hexField(f[6])
	if err != nil {
		return Params{}, err
	}
	p := Params{Version: 1, Salt: salt, WrappedAESKey: aesKey, WrappedHMACKey: hmacKey}
	if len(f) >= 8 {
		p.Iterations, _ = strconv.Atoi(f[7])
	}
	return p, nil
}

func parseV2(f []string) (Params, error) {
	// version, saltlen, salt, ivlen, iv, kbsize, keyblob, cno, datasize, chunk, scp [, zchunk] [, iterations]
	if len(f) < 11 {
		return Params{}, ErrFormat
	}
	salt, err := hexField(f[2])
	if err != nil {
		return Params{}, err
	}
	iv, err := hexField(f[4])
	if err != nil {
		return Params{}, err
	}
	keyblob, err := hexField(f[6])
	if err != nil {
		return Params{}, err
	}
	cno, err := strconv.Atoi(f[7])
	if err != nil {
		return Params{}, ErrFormat
	}
	chunk, err := hexField(f[9])
	if err != nil {
		return Params{}, err
	}
	p := Params{
		Version:          2,
		Salt:             salt,
		IV:               iv,
		EncryptedKeyblob: keyblob,
		ChunkNo:          uint32(cno),
		Chunk:            chunk,
	}
	// f[10] = scp; if scp==1, f[11] is a 4096-byte zchunk we don't need; the
	// iterations field (if any) is whatever trails. Find a final integer field.
	scp, _ := strconv.Atoi(f[10])
	rest := f[11:]
	if scp == 1 && len(rest) > 0 {
		rest = rest[1:] // skip zchunk
	}
	if len(rest) > 0 {
		p.Iterations, _ = strconv.Atoi(rest[0])
	}
	return p, nil
}

func hexField(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrFormat
	}
	return b, nil
}
