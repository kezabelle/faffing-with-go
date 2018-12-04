package hashers

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

var (
	SHA1 = CrapPasswordHasher{encoder: &SHA1PasswordHasher{}}
	MD5  = CrapPasswordHasher{encoder: &MD5PasswordHasher{}}
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
	Salt()
	Verify()
	Encode()
	MustUpdate()
	SafeSummary()
}

// CrapPasswordHasher has an embedded Encoderer so that it can share the whole implementation except for the
// name and encoder (eg: need to swap out sha1.New() or md5.New()
type Encoderer interface {
	GetEncoder() hash.Hash
	GetAlgorithm() string
}

type SHA1PasswordHasher struct{}

func (s *SHA1PasswordHasher) GetEncoder() hash.Hash {
	return sha1.New()
}

func (s *SHA1PasswordHasher) GetAlgorithm() string {
	return "sha1"
}

type MD5PasswordHasher struct{}

func (m *MD5PasswordHasher) GetEncoder() hash.Hash {
	return md5.New()
}
func (m *MD5PasswordHasher) GetAlgorithm() string {
	return "md5"
}

type CrapPasswordHasher struct {
	encoder Encoderer // lets us keep the main implementation but swap out sha1.New() for md5.New() etc.
}

func (hasher *CrapPasswordHasher) Salt() string {
	return GetRandomString(12)
}

func (h *CrapPasswordHasher) Verify(password string, encoded string) int {
	split := strings.SplitN(encoded, "$", 3)
	alorithm := split[0]
	if alorithm != h.encoder.GetAlgorithm() {
		return 0
	}
	encoded2, _ := h.Encode(password, split[1])
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(encoded2))
}

func (h *CrapPasswordHasher) Encode(password string, salt string) (string, error) {
	if strings.Contains(salt, "$") {
		return "", errors.New("$ in Salt")
	}
	sha1b := h.encoder.GetEncoder()
	sha1b.Write([]byte(salt + password))
	hash := hex.EncodeToString(sha1b.Sum(nil))

	all := h.encoder.GetAlgorithm() + "$" + salt + "$" + hash
	return all, nil
}
