package hashers

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strconv"
	"strings"
)

var (
	SHA1               = CrapPasswordHasher{configuration: &SHA1PasswordHasher{}}
	MD5                = CrapPasswordHasher{configuration: &MD5PasswordHasher{}}
	DJ_21_PBKDF2      = PBKDF2PasswordHasher{iterations: 120000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_21_PBKDF2_SHA1 = PBKDF2PasswordHasher{iterations: 120000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_20_PBKDF2      = PBKDF2PasswordHasher{iterations: 100000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_20_PBKDF2_SHA1 = PBKDF2PasswordHasher{iterations: 100000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_111_PBKDF2      = PBKDF2PasswordHasher{iterations: 36000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_111_PBKDF2_SHA1 = PBKDF2PasswordHasher{iterations: 36000, keylen: 20, configuration: &PBKDF2SHA1{}}
	//UnsaltedSHA1 = CrapPasswordHasher{configuration: &UnsaltedSHA1PasswordHasher{}}
	//UnsaltedMD5 = CrapPasswordHasher{configuration: &UnsaltedMD5PasswordHasher{}}
)

func GetRandomString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i, b2 := range b {
		b[i] = letters[b2%byte(len(letters))]
	}
	return string(b)
}

// All the hashers should have this.
type Hasher interface {
	Salt() string
	Verify(string, string) int
	Encode(string, string) (string, error)
	//MustUpdate()
	//SafeSummary()
}

// CrapPasswordHasher has an embedded Encoderer so that it can share the whole implementation except for the
// name and configuration (eg: need to swap out sha1.New() or md5.New()
type Encoderer interface {
	Encoder() func() hash.Hash
	Algorithm() string
	Salt() string
}

type SHA1PasswordHasher struct {
}

func (s *SHA1PasswordHasher) Encoder() func() hash.Hash {
	return sha1.New
}

func (s *SHA1PasswordHasher) Algorithm() string {
	return "sha1"
}
func (s *SHA1PasswordHasher) Salt() string {
	return GetRandomString(12)
}

type MD5PasswordHasher struct {
}

func (m *MD5PasswordHasher) Encoder() func() hash.Hash {
	return md5.New
}
func (m *MD5PasswordHasher) Algorithm() string {
	return "md5"
}
func (s *MD5PasswordHasher) Salt() string {
	return GetRandomString(12)
}

type CrapPasswordHasher struct {
	configuration Encoderer // lets us keep the main implementation but swap out sha1.New() for md5.New() etc.
}

func (h *CrapPasswordHasher) Salt() string {
	return h.configuration.Salt()
}

func (h *CrapPasswordHasher) Verify(password string, encoded string) int {
	split := strings.SplitN(encoded, "$", 3)
	alorithm := split[0]
	if alorithm != h.configuration.Algorithm() {
		return 0
	}
	encoded2, _ := h.Encode(password, split[1])
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(encoded2))
}

func (h *CrapPasswordHasher) Encode(password string, salt string) (string, error) {
	if strings.Contains(salt, "$") {
		return "", errors.New("$ in Salt")
	}
	hasher := h.configuration.Encoder()()
	hasher.Write([]byte(salt + password))
	hash := hex.EncodeToString(hasher.Sum(nil))

	all := h.configuration.Algorithm() + "$" + salt + "$" + hash
	return all, nil
}

type PBKDF2SHA256 struct{}

func (m *PBKDF2SHA256) Encoder() func() hash.Hash {
	return sha256.New
}
func (m *PBKDF2SHA256) Algorithm() string {
	return "pbkdf2_sha256"
}
func (s *PBKDF2SHA256) Salt() string {
	return GetRandomString(12)
}

type PBKDF2SHA1 struct{}

func (m *PBKDF2SHA1) Encoder() func() hash.Hash {
	return sha1.New
}
func (m *PBKDF2SHA1) Algorithm() string {
	return "pbkdf2_sha1"
}
func (s *PBKDF2SHA1) Salt() string {
	return GetRandomString(12)
}

type PBKDF2PasswordHasher struct {
	iterations    int
	keylen        int
	configuration Encoderer
}

func (h *PBKDF2PasswordHasher) Encode(password string, salt string, iterations int) (string, error) {
	if strings.Contains(salt, "$") {
		return "", errors.New("$ in Salt")
	}
	if iterations == 0 {
		iterations = h.iterations
	}
	hasher := h.configuration.Encoder()
	key := pbkdf2.Key([]byte(password), []byte(salt), iterations, h.keylen, hasher)
	hash := strings.TrimSpace(base64.StdEncoding.EncodeToString(key))
	all := h.configuration.Algorithm() + "$" + strconv.Itoa(iterations) + "$" + salt + "$" + hash
	return all, nil
}
func (h *PBKDF2PasswordHasher) Verify(password string, encoded string) int {
	split := strings.SplitN(encoded, "$", 4)
	algorithm := split[0]
	salt := split[2]
	_ = split[3] // hash
	if algorithm != h.configuration.Algorithm() {
		return 0
	}
	iterations, err := strconv.Atoi(split[1])
	if err != nil {
		return 0
	}
	encoded2, _ := h.Encode(password, salt, iterations)
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(encoded2))
}
