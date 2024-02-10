package random

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"log"
	"math/big"
	mathrand "math/rand"
	"sync"
	"time"
)

type SFRand interface {
	Int(min int, max int) int
	Bytes(n int) []byte
	Bool() bool
	Rune(pool []rune) rune
	String(length int, pool []rune) string
}

type randomizer struct {
	rnd *mathrand.Rand
	mtx sync.Mutex
}

func NewSFRand() SFRand {
	b := make([]byte, 8)
	_, err := cryptorand.Read(b)
	if err != nil {
		log.Printf(
			"failed to seed fallback math/rand package with cryptographically secure random number generator. Reason: %s\n",
			err.Error(),
		)
		return &randomizer{
			rnd: mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
		} // fallback to insecure seed by time
	}

	return &randomizer{rnd: mathrand.New(mathrand.NewSource(int64(binary.LittleEndian.Uint64(b))))}
}

// returns pseudo-random int between min and max, inclusive. It panics if max <= 0.
func (r *randomizer) Int(min int, max int) int {
	res, err := secureInt(min, max)
	if err != nil {
		log.Printf(
			"failed to use cryptographically secure random number generator for Int(%d, %d). Reason: %s",
			min,
			max,
			err.Error(),
		)
		r.mtx.Lock()
		defer r.mtx.Unlock()
		return r.rnd.Intn(max-min+1) + min
	}

	return res
}

// returns n pseudo-random bytes
func (r *randomizer) Bytes(n int) []byte {
	res, err := secureBytes(n)
	if err != nil { // fallback to math/rand
		log.Printf(
			"failed to use cryptographically secure random number generator for Bytes(%d). Reason: %s",
			n,
			err.Error(),
		)
		r.mtx.Lock()
		defer r.mtx.Unlock()
		b := make([]byte, n)
		// returned error can be safely ignored as it cannot be non-nil
		// ref https://golang.org/pkg/math/rand/#Read
		r.rnd.Read(b)
		return b
	}

	return res
}

// returns pseudo-random bool
func (r *randomizer) Bool() bool {
	return r.Int(0, 1) == 1
}

// returns single pseudo-random rune from pool
func (r *randomizer) Rune(pool []rune) rune {
	return pool[r.Int(0, len(pool)-1)]
}

// returns string of pseudo-random runes from pool
func (r *randomizer) String(length int, pool []rune) string {
	out := make([]rune, 0)
	for i := 0; i < length; i++ {
		out = append(out, r.Rune(pool))
	}
	return string(out)
}

// returns []rune of 0-9
func GetNumericPool() []rune {
	return []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
}

// returns []rune of a-z
func GetAlphabeticLowercasePool() []rune {
	return []rune{
		'a',
		'b',
		'c',
		'd',
		'e',
		'f',
		'g',
		'h',
		'i',
		'j',
		'k',
		'l',
		'm',
		'n',
		'o',
		'p',
		'q',
		'r',
		's',
		't',
		'u',
		'v',
		'w',
		'x',
		'y',
		'z',
	}
}

// returns []rune a-z A-Z
func GetAlphabeticPool() []rune {
	return []rune{
		'a',
		'b',
		'c',
		'd',
		'e',
		'f',
		'g',
		'h',
		'i',
		'j',
		'k',
		'l',
		'm',
		'n',
		'o',
		'p',
		'q',
		'r',
		's',
		't',
		'u',
		'v',
		'w',
		'x',
		'y',
		'z',
		'A',
		'B',
		'C',
		'D',
		'E',
		'F',
		'G',
		'H',
		'I',
		'J',
		'K',
		'L',
		'M',
		'N',
		'O',
		'P',
		'Q',
		'R',
		'S',
		'T',
		'U',
		'V',
		'W',
		'X',
		'Y',
		'Z',
	}
}

// returns []rune 0-9 a-z
func GetAlphaNumericLowercasePool() []rune {
	return []rune{
		'a',
		'b',
		'c',
		'd',
		'e',
		'f',
		'g',
		'h',
		'i',
		'j',
		'k',
		'l',
		'm',
		'n',
		'o',
		'p',
		'q',
		'r',
		's',
		't',
		'u',
		'v',
		'w',
		'x',
		'y',
		'z',
		'0',
		'1',
		'2',
		'3',
		'4',
		'5',
		'6',
		'7',
		'8',
		'9',
	}
}

// returns []rune 0-9 a-z A-Z
func GetAlphaNumericPool() []rune {
	return []rune{
		'a',
		'b',
		'c',
		'd',
		'e',
		'f',
		'g',
		'h',
		'i',
		'j',
		'k',
		'l',
		'm',
		'n',
		'o',
		'p',
		'q',
		'r',
		's',
		't',
		'u',
		'v',
		'w',
		'x',
		'y',
		'z',
		'0',
		'1',
		'2',
		'3',
		'4',
		'5',
		'6',
		'7',
		'8',
		'9',
		'A',
		'B',
		'C',
		'D',
		'E',
		'F',
		'G',
		'H',
		'I',
		'J',
		'K',
		'L',
		'M',
		'N',
		'O',
		'P',
		'Q',
		'R',
		'S',
		'T',
		'U',
		'V',
		'W',
		'X',
		'Y',
		'Z',
	}
}

// returns []rune 0-9 a-z A-Z $ - _ ! ( ) [ ] { } ~ + *
// intended for use in randomly generated tokens such as session ids or api keys
func GetTokenPool() []rune {
	return []rune{
		'a',
		'b',
		'c',
		'd',
		'e',
		'f',
		'g',
		'h',
		'i',
		'j',
		'k',
		'l',
		'm',
		'n',
		'o',
		'p',
		'q',
		'r',
		's',
		't',
		'u',
		'v',
		'w',
		'x',
		'y',
		'z',
		'0',
		'1',
		'2',
		'3',
		'4',
		'5',
		'6',
		'7',
		'8',
		'9',
		'A',
		'B',
		'C',
		'D',
		'E',
		'F',
		'G',
		'H',
		'I',
		'J',
		'K',
		'L',
		'M',
		'N',
		'O',
		'P',
		'Q',
		'R',
		'S',
		'T',
		'U',
		'V',
		'W',
		'X',
		'Y',
		'Z',
		'$',
		'-',
		'_',
		'!',
		'(',
		')',
		'[',
		']',
		'{',
		'}',
		'~',
		'+',
		'*',
	}
}

// returns []rune 1-9, a-z but with characters 1, i, l, 0, a, e, i, o, u removed to prevent ambiguous or offensive output
// useful for use in human-readable ids like shortened urls
func GetUnambiguousLowercasePool() []rune {
	return []rune{
		'b',
		'c',
		'd',
		'f',
		'g',
		'h',
		'j',
		'k',
		'm',
		'n',
		'p',
		'q',
		'r',
		's',
		't',
		'v',
		'w',
		'x',
		'y',
		'z',
		'2',
		'3',
		'4',
		'5',
		'6',
		'7',
		'8',
		'9',
	}
}

// returns []rune 1-9, a-z, A-Z but with characters 1, i, I, l, 0, a, e, i, o, u, A, E, I, O, U removed to prevent ambiguous or offensive output
// useful for use in human-readable ids like shortened urls
func GetUnambiguousPool() []rune {
	return []rune{
		'b',
		'c',
		'd',
		'f',
		'g',
		'h',
		'j',
		'k',
		'm',
		'n',
		'p',
		'q',
		'r',
		's',
		't',
		'v',
		'w',
		'x',
		'y',
		'z',
		'2',
		'3',
		'4',
		'5',
		'6',
		'7',
		'8',
		'9',
		'B',
		'C',
		'D',
		'F',
		'G',
		'H',
		'J',
		'K',
		'L',
		'M',
		'N',
		'P',
		'Q',
		'R',
		'S',
		'T',
		'V',
		'W',
		'X',
		'Y',
		'Z',
	}
}

// returns cryptographically secure int between min and max, inclusive
func secureInt(min int, max int) (int, error) {
	nBig, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()) + min, nil
}

// returns n cryptographically secure bytes
func secureBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := cryptorand.Read(b)
	if err != nil {
		return b, err
	}
	return b, nil
}
