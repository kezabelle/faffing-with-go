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
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strconv"
	"strings"
)

var (
	BCrypt             = BCryptPasswordHasher{&bcryptNoSHA{}}
	BCryptSHA256       = BCryptPasswordHasher{&bcryptSHA256{}}
	Argon2             = Argon2PasswordHasher{}
	SHA1               = CrapPasswordHasher{&sha1PasswordHasher{}}
	MD5                = CrapPasswordHasher{&md5PasswordHasher{}}
	DJ_21_PBKDF2       = PBKDF2PasswordHasher{iterations: 120000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_21_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 120000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_20_PBKDF2       = PBKDF2PasswordHasher{iterations: 100000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_20_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 100000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_111_PBKDF2      = PBKDF2PasswordHasher{iterations: 36000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_111_PBKDF2_SHA1 = PBKDF2PasswordHasher{iterations: 36000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_110_PBKDF2      = PBKDF2PasswordHasher{iterations: 30000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_110_PBKDF2_SHA1 = PBKDF2PasswordHasher{iterations: 30000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_19_PBKDF2       = PBKDF2PasswordHasher{iterations: 24000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_19_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 24000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_18_PBKDF2       = PBKDF2PasswordHasher{iterations: 20000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_18_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 20000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_17_PBKDF2       = PBKDF2PasswordHasher{iterations: 15000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_17_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 15000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_16_PBKDF2       = PBKDF2PasswordHasher{iterations: 12000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_16_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 12000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_15_PBKDF2       = PBKDF2PasswordHasher{iterations: 10000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_15_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 10000, keylen: 20, configuration: &PBKDF2SHA1{}}
	DJ_14_PBKDF2       = PBKDF2PasswordHasher{iterations: 10000, keylen: 32, configuration: &PBKDF2SHA256{}}
	DJ_14_PBKDF2_SHA1  = PBKDF2PasswordHasher{iterations: 10000, keylen: 20, configuration: &PBKDF2SHA1{}}
	//UnsaltedSHA1 = CrapPasswordHasher{configuration: &UnsaltedSHA1PasswordHasher{}}
	//UnsaltedMD5 = CrapPasswordHasher{configuration: &UnsaltedMD5PasswordHasher{}}

)

// Interface checks
var _ Hasher = (*CrapPasswordHasher)(nil)
var _ Hasher = (*PBKDF2PasswordHasher)(nil)
var _ Hasher = (*Argon2PasswordHasher)(nil)
var _ Hasher = (*BCryptPasswordHasher)(nil)

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
	ShouldUpdate(string) bool
	//SafeSummary()
}

// CrapPasswordHasher has an embedded Encoderer so that it can share the whole implementation except for the
// name and configuration (eg: need to swap out sha1.New() or md5.New()
type Encoderer interface {
	Encoder() func() hash.Hash
	Algorithm() string
	Salt() string
}

type sha1PasswordHasher struct {
}

func (s *sha1PasswordHasher) Encoder() func() hash.Hash {
	return sha1.New
}

func (s *sha1PasswordHasher) Algorithm() string {
	return "sha1"
}
func (s *sha1PasswordHasher) Salt() string {
	return GetRandomString(12)
}

type md5PasswordHasher struct {
}

func (m *md5PasswordHasher) Encoder() func() hash.Hash {
	return md5.New
}
func (m *md5PasswordHasher) Algorithm() string {
	return "md5"
}
func (s *md5PasswordHasher) Salt() string {
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

func (h *PBKDF2PasswordHasher) Salt() string {
	return h.configuration.Salt()
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

type BCrypter interface {
	WrapPassword(string) string
	Algorithm() string
}

type bcryptSHA256 struct{}

func (m *bcryptSHA256) WrapPassword(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hash := hex.EncodeToString(hasher.Sum(nil))
	return hash
}
func (m *bcryptSHA256) Algorithm() string {
	return "bcrypt_sha256"
}

type bcryptNoSHA struct{}

func (m *bcryptNoSHA) WrapPassword(password string) string {
	return password
}
func (m *bcryptNoSHA) Algorithm() string {
	return "bcrypt"
}

type BCryptPasswordHasher struct {
	BCrypter
}

func (h *BCryptPasswordHasher) Salt() string {
	return ""
}
func (h *BCryptPasswordHasher) Encode(password string, salt string) (string, error) {
	password = h.WrapPassword(password)
	result, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return h.Algorithm() + "$" + string(result), err
}
func (h *BCryptPasswordHasher) Verify(password string, encoded string) int {
	split := strings.SplitN(encoded, "$", 2)
	if split[0] != h.Algorithm() {
		return 0
	}
	password = h.WrapPassword(password)
	result := bcrypt.CompareHashAndPassword([]byte(split[1]), []byte(password))
	if result == nil {
		return 1
	}
	return 0
}

func (h *BCryptPasswordHasher) ShouldUpdate(encoded string) bool {
	split := strings.SplitN(encoded, "$", 5)
	rounds, err := strconv.Atoi(split[4])
	if err != nil {
		return false
	}
	return rounds != 12
}

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

func (h *Argon2PasswordHasher) Salt() string {
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

func (h *Argon2PasswordHasher) ShouldUpdate(encoded string) bool {
	// TODO: implement as below
	//def must_update(self, encoded):
	//	(algorithm, variety, version, time_cost, memory_cost, parallelism,
	//		salt, data) = self._decode(encoded)
	//	assert algorithm == self.algorithm
	//	argon2 = self._load_library()
	//	return (
	//		argon2.low_level.ARGON2_VERSION != version or
	//	self.time_cost != time_cost or
	//	self.memory_cost != memory_cost or
	//	self.parallelism != parallelism
	//	)
	return false
}
