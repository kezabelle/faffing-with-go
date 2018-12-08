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
	"github.com/matthewhartstonge/argon2"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strconv"
	"strings"
)

var (
	SHA1               = CrapPasswordHasher{&SHA1PasswordHasher{}}
	MD5                = CrapPasswordHasher{&MD5PasswordHasher{}}
	DJ_21_PBKDF2       = PBKDF2PasswordHasher{iterations: 120000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_21_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 120000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_20_PBKDF2       = PBKDF2PasswordHasher{iterations: 100000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_20_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 100000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_111_PBKDF2      = PBKDF2PasswordHasher{iterations: 36000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_111_PBKDF2_SHA1 = PBKDF2PasswordHasher{iterations: 36000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_18_PBKDF2       = PBKDF2PasswordHasher{iterations: 20000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_18_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 20000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_14_PBKDF2       = PBKDF2PasswordHasher{iterations: 10000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_14_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 10000, keylen: 20, configuration: &PBKDF2SHA1{}}
	//UnsaltedSHA1 = CrapPasswordHasher{configuration: &UnsaltedSHA1PasswordHasher{}}
	//UnsaltedMD5 = CrapPasswordHasher{configuration: &UnsaltedMD5PasswordHasher{}}

)

// Interface checks
var _ Hasher = (*CrapPasswordHasher)(nil)
var _ Hasher = (*PBKDF2PasswordHasher)(nil)
var _ Hasher = (*Argon2PasswordHasher)(nil)

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
	//Salt() string
	Verify(string, string) int
	Encode(string, string) (string, error)
	//ShouldUpdate() bool
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
	Encoderer // lets us keep the main implementation but swap out sha1.New() for md5.New() etc.
}

//func (h *CrapPasswordHasher) Salt() string {
//	return h.configuration.Salt()
//}

func (h *CrapPasswordHasher) Verify(password string, encoded string) int {
	split := strings.SplitN(encoded, "$", 3)
	alorithm := split[0]
	if alorithm != h.Algorithm() {
		return 0
	}
	encoded2, _ := h.Encode(password, split[1])
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(encoded2))
}

func (h *CrapPasswordHasher) Encode(password string, salt string) (string, error) {
	if strings.Contains(salt, "$") {
		return "", errors.New("$ in Salt")
	}
	hasher := h.Encoder()()
	hasher.Write([]byte(salt + password))
	hash := hex.EncodeToString(hasher.Sum(nil))

	all := h.Algorithm() + "$" + salt + "$" + hash
	return all, nil
}
func (h *CrapPasswordHasher) ShouldUpdate(encoded string) bool {
	return false
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

func (h *PBKDF2PasswordHasher) Encode(password string, salt string) (string, error) {
	return h.EncodeIterations(password, salt, h.iterations)
}

func (h *PBKDF2PasswordHasher) EncodeIterations(password string, salt string, iterations int) (string, error) {
	if strings.Contains(salt, "$") {
		return "", errors.New("$ in Salt")
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
	encoded2, _ := h.EncodeIterations(password, salt, iterations)
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(encoded2))
}

func (h *PBKDF2PasswordHasher) ShouldUpdate(encoded string) bool {
	split := strings.SplitN(encoded, "$", 4)
	iterations, err := strconv.Atoi(split[1])
	if err != nil {
		return true
	}
	return iterations != h.iterations
}

//type BCryptPasswordHasher struct {
//}
//func (h *BCryptPasswordHasher) Salt() (string) {
//  // Example from BCryptSHA256PasswordHasher().salt() = $2b$12$nTBSvTeELovV9.lPZLBCtu / $2b$12$zf8jrSLSgnPhy..1H090he
//	return "???"
//}
//func (h *BCryptPasswordHasher) Encode(password string, salt string) (string, error) {
//	return "", nil
//}
//func (h *BCryptPasswordHasher) Verify(password string, encoded string) int {
//	return 0
//}
//func (h *BCryptPasswordHasher) ShouldUpdate(encoded string) bool {
//	return false
//}

var argon2config = argon2.Config{
	HashLength:  16,
	SaltLength:  16,
	TimeCost:    2,
	MemoryCost:  512,
	Parallelism: 2,
	Mode:        argon2.ModeArgon2i,
	Version:     argon2.Version13,
}

type Argon2PasswordHasher struct {
}

func (h *Argon2PasswordHasher) Salt() (string) {
	return GetRandomString(12)
}
func (h *Argon2PasswordHasher) Encode(password string, salt string) (string, error) {
	r, _ := argon2config.Hash([]byte(password), []byte(salt))
	result := r.Encode()
	return "argon2" + string(result), nil
}

func (h *Argon2PasswordHasher) Verify(password string, encoded string) int {
	split := strings.SplitN(encoded, "$", 2)
	algorithm := split[0]
	if algorithm != "argon2" {
		return 0
	}
	res, _ := argon2.VerifyEncoded([]byte(password), []byte("$"+split[1]))
	if res == false {
		return 0
	}
	return 1
}

//
//func (h *Argon2PasswordHasher) ShouldUpdate(encoded string) bool {
//	return false
//}
