package apr1

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"strings"
)

const magic = "$apr1$"

// Source/References for core algorithm:
// http://www.cryptologie.net/article/126/bruteforce-apr1-hashes/
// http://svn.apache.org/viewvc/apr/apr-util/branches/1.3.x/crypto/apr_md5.c?view=co
// http://www.php.net/manual/en/function.crypt.php#73619
// http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
// Wikipedia

func Pack(order binary.ByteOrder, data interface{}) (string, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, order, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Repeats byte sequence in `hash` until output is `size` long
func repeatHash(hash [16]byte, size int) []byte {
	m := 1 + (size-1)/len(hash)
	r := []byte{}
	for i := 0; i < m; i++ {
		r = append(r, hash[:]...)
	}
	return r[:size]
}

func makeDigestA(password string, salt string, digestB [16]byte) []byte {
	pw_len := len(password)

	a_ctx := md5.New()
	a_ctx_update := a_ctx.Write
	a_ctx_update([]byte(password + magic + salt))
	a_ctx_update(repeatHash(digestB, pw_len))

	i := pw_len
	ch0 := []byte{password[0]}
	for ; i > 0; i >>= 1 {
		if (i & 1) == 1 {
			a_ctx_update([]byte{0x00})
		} else {
			a_ctx_update(ch0)
		}
	}
	return a_ctx.Sum(nil)
}

func makeDigestC(password string, salt string, digestA []byte) []byte {
	dc := make([]byte, len(digestA))
	copy(dc, digestA[:])

	for i := 0; i < 1000; i++ {
		t_ctx := md5.New()
		if (i & 1) == 1 {
			t_ctx.Write([]byte(password))
		} else {
			t_ctx.Write(dc)
		}

		if (i % 3) != 0 {
			t_ctx.Write([]byte(salt))
		}

		if (i % 7) != 0 {
			t_ctx.Write([]byte(password))
		}

		if (i & 1) == 1 {
			t_ctx.Write(dc)
		} else {
			t_ctx.Write([]byte(password))
		}

		dc = t_ctx.Sum(nil)
	}
	return dc
}

/// Re-impl apache's apr hash
func Encode(password string, salt string) string {

	// digest B
	digest_B := md5.Sum([]byte(password + salt + password))

	// digest A
	digest_A := makeDigestA(password, salt, digest_B)

	//digest C
	digest_C := makeDigestC(password, salt, digest_A)

	// transpose
	h := bytes.NewBufferString("")
	for i := 0; i < 5; i++ {
		k := i + 6
		j := i + 12
		if j == 16 {
			j = 5
		}
		s := h.String()
		h.Reset()
		h.WriteByte(digest_C[i])
		h.WriteByte(digest_C[k])
		h.WriteByte(digest_C[j])
		h.WriteString(s)
	}
	s := h.String()
	h.Reset()
	h.WriteByte(0x00)
	h.WriteByte(0x00)
	h.WriteByte(digest_C[11])
	h.WriteString(s)

	b64 := base64.StdEncoding.EncodeToString(h.Bytes())[2:]
	b64 = revString(b64)
	b64 = translate(b64)
	runtime.GC()
	return magic + salt + "$" + b64
}

func translate(s string) string {
	l := len(s)
	trns := make([]rune, l)
	for i, r := range s {
		trns[i] = translationDict[r]
	}
	return string(trns)
}

var translationDict = map[rune]rune{
	'A': '.',
	'B': '/',
	'C': '0',
	'D': '1',
	'E': '2',
	'F': '3',
	'G': '4',
	'H': '5',
	'I': '6',
	'J': '7',
	'K': '8',
	'L': '9',
	'M': 'A',
	'N': 'B',
	'O': 'C',
	'P': 'D',
	'Q': 'E',
	'R': 'F',
	'S': 'G',
	'T': 'H',
	'U': 'I',
	'V': 'J',
	'W': 'K',
	'X': 'L',
	'Y': 'M',
	'Z': 'N',
	'a': 'O',
	'b': 'P',
	'c': 'Q',
	'd': 'R',
	'e': 'S',
	'f': 'T',
	'g': 'U',
	'h': 'V',
	'i': 'W',
	'j': 'X',
	'k': 'Y',
	'l': 'Z',
	'm': 'a',
	'n': 'b',
	'o': 'c',
	'p': 'd',
	'q': 'e',
	'r': 'f',
	's': 'g',
	't': 'h',
	'u': 'i',
	'v': 'j',
	'w': 'k',
	'x': 'l',
	'y': 'm',
	'z': 'n',
	'0': 'o',
	'1': 'p',
	'2': 'q',
	'3': 'r',
	'4': 's',
	'5': 't',
	'6': 'u',
	'7': 'v',
	'8': 'w',
	'9': 'x',
	'+': 'y',
	'/': 'z',
}

func revString(s string) string {
	l := len(s)
	rev := make([]rune, l)
	for i, r := range s {
		rev[l-i-1] = r
	}
	return string(rev)
}