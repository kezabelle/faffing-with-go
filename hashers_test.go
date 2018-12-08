package hashers

import (
	"testing"
)

func TestGetRandomString(t *testing.T) {
	GetRandomString(12)
}

type CrapHashable struct {
	name          string
	encoded_value string
	hasher        CrapPasswordHasher
}
type PDBKDF2 struct {
	name          string
	encoded_value string
	hasher        PBKDF2PasswordHasher
}

var hashables = []CrapHashable{
	{"SHA1", "sha1$woof$0b65bc32d57d63ecfbd8b0b4303fe09ffc5d566f", SHA1},
	{"MD5", "md5$woof$222feadb26d048c8ea411406b33d0b94", MD5},
}
var pbkdf2s = []PDBKDF2{
	{"Django 2.1 PBKDF2, SHA256", "pbkdf2_sha256$120000$woof$Ee/zXaKZovWIxnH/wtgd0mKaNSFZ+N4qOuA4DQcUfgo=", DJ_21_PBKDF2},
	{"Django 2.1 PBKDF2, SHA1", "pbkdf2_sha1$120000$woof$7NmnJANma4wvUOQSF0ax5qLnppw=", DJ_21_PBKDF2_SHA1},
	{"Django 2.0 PBKDF2, SHA256", "pbkdf2_sha256$100000$woof$7TWxWgPy7z0sRvnc2REV2RsXIJJCYXutfoZdXGoSVAY=", DJ_20_PBKDF2},
	{"Django 2.0 PBKDF2, SHA1", "pbkdf2_sha1$100000$woof$9QE012mIl6gN+jWZafzcB4oNHNA=", DJ_20_PBKDF2_SHA1},
	{"Django 1.11 (LTS) PBKDF2, SHA256", "pbkdf2_sha256$36000$woof$gOvAuiZY5KyuxBOyLOs5+tovjqb6wEHQsWM0mvRxmNo=", DJ_111_PBKDF2},
	{"Django 1.11 (LTS) PBKDF2, SHA1", "pbkdf2_sha1$36000$woof$zcBBwbvZBLdlZyu1uHNmrzlnya4=", DJ_111_PBKDF2_SHA1},
	{"Django 1.8 (LTS) PBKDF2, SHA256", "pbkdf2_sha256$20000$woof$sJSaMkbt/6mvDBI2khnDNFSwbA8NPmYy/8Ig+s0AsvI=", DJ_18_PBKDF2},
	{"Django 1.8 (LTS) PBKDF2, SHA1", "pbkdf2_sha1$20000$woof$X2uxrUctGmCY9TF5Hcw/UT06Z2Q=", DJ_18_PBKDF2_SHA1},
	{"Django 1.4 (LTS) PBKDF2, SHA256", "pbkdf2_sha256$10000$woof$73V59XxoyKp7dkPM5mlaNu4LqK8s9Lkmbvo6GBanCI8=", DJ_14_PBKDF2},
	{"Django 1.4 (LTS) PBKDF2, SHA1", "pbkdf2_sha1$10000$woof$QB91axouI/E12QORKgNkHAF8o0Y=", DJ_14_PBKDF2_SHA1},
}


func TestCrapPasswordHasher_Encode(t *testing.T) {
	for _, hashable := range hashables {
		t.Run(hashable.name, func(t *testing.T) {
			encoded, _ := hashable.hasher.Encode("test", "woof")
			expected := hashable.encoded_value
			if encoded != expected {
				t.Errorf("Expected %s, got %s", expected, encoded)
			}
		})
	}
}

func TestCrapPasswordHasher_Verify(t *testing.T) {
	for _, hashable := range hashables {
		t.Run(hashable.name, func(t *testing.T) {
			t.Run("Match", func(t *testing.T) {
				result := hashable.hasher.Verify("test", hashable.encoded_value)
				if result == 0 {
					t.Error("Verifying encoded password didn't work")
				}
			})
			t.Run("Doesn't match", func(t *testing.T) {
				result := hashable.hasher.Verify("test2", hashable.encoded_value)
				if result != 0 {
					t.Error("Verifying encoded password didn't work")
				}
			})
		})
	}
}

func TestPBKDF2PasswordHasher_Encode(t *testing.T) {
	for _, hashable := range pbkdf2s {
		t.Run(hashable.name, func(t *testing.T) {
			encoded, _ := hashable.hasher.Encode("test", "woof")
			expected := hashable.encoded_value
			if encoded != expected {
				t.Errorf("Expected %s, got %s", expected, encoded)
			}
		})
	}
}

func TestPBKDF2PasswordHasher_Verify(t *testing.T) {
	for _, hashable := range pbkdf2s {
		t.Run(hashable.name, func(t *testing.T) {
			t.Run("Match", func(t *testing.T) {
				result := hashable.hasher.Verify("test", hashable.encoded_value)
				if result == 0 {
					t.Error("Verifying encoded password didn't work")
				}
			})
			t.Run("Doesn't match", func(t *testing.T) {
				result := hashable.hasher.Verify("test2", hashable.encoded_value)
				if result != 0 {
					t.Error("Verifying encoded password didn't work")
				}
			})
		})
	}
}