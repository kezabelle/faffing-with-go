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

func TestArgon2PasswordHasher_Encode(t *testing.T) {
	encoded, _ := Argon2.Encode("test", "woofwoofwoof")
	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$d29vZndvb2Z3b29m$NadkcmUilrgla3/+HH78Ew"
	if encoded != expected {
		t.Errorf("Expected %s, got %s", expected, encoded)
	}
}

func TestArgon2PasswordHasher_Verify(t *testing.T) {
	encoded, _ := Argon2.Encode("test", "woofwoofwoof")
	t.Run("Match", func(t *testing.T) {
		result := Argon2.Verify("test", encoded)
		if result == 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	t.Run("Doesn't match", func(t *testing.T) {
		result := Argon2.Verify("test2", encoded)
		if result != 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
}

func TestBCryptPasswordHasher_Encode_Verify(t *testing.T) {
	encoded1, _ := BCrypt.Encode("test", "woofwoofwoof")
	t.Run("Encoded by this lib", func(t *testing.T) {
		result := BCrypt.Verify("test", encoded1)
		if result == 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	encoded2 := "bcrypt$$2a$12$2RR.Z2TDNjO6GhMSfuh/ReVtTA9F4czUYlRWZIZ8NnLXC9iWHh3K6"
	encoded3 := "bcrypt$$2b$12$6oJ78FYHcl05aSm4QElRBOGvtnIlmCjl0QVYmqPzQg2QhUNIMHeZe"
	t.Run("Match 2A", func(t *testing.T) {
		result := BCrypt.Verify("test", encoded2)
		if result == 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	t.Run("Match 2B", func(t *testing.T) {
		result := BCrypt.Verify("test", encoded3)
		if result == 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	t.Run("Doesn't match 2A", func(t *testing.T) {
		result := BCrypt.Verify("test2", encoded2)
		if result != 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	t.Run("Doesn't match 2B", func(t *testing.T) {
		result := BCrypt.Verify("test2", encoded3)
		if result != 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
}

func TestBCryptSHA256PasswordHasher_Encode_Verify(t *testing.T) {
	encoded1, _ := BCryptSHA256.Encode("test", "woofwoofwoof")
	print(encoded1)
	t.Run("Encoded by this lib", func(t *testing.T) {
		result := BCryptSHA256.Verify("test", encoded1)
		if result == 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	encoded2 := "bcrypt_sha256$$2a$12$Qso5qvyoqT3oHxTxMsFegOyZwlbR2T3UptVB.DGKE5ho5yWyqttHe"
	encoded3 := "bcrypt_sha256$$2b$12$PpQIsCsElwF9xdT/dhH7Je0tb/xW0MctV.Yvd/zH3vicM5ZAOP85i"
	t.Run("Match 2A", func(t *testing.T) {
		result := BCryptSHA256.Verify("test", encoded2)
		if result == 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	t.Run("Match 2B", func(t *testing.T) {
		result := BCryptSHA256.Verify("test", encoded3)
		if result == 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	t.Run("Doesn't match 2A", func(t *testing.T) {
		result := BCryptSHA256.Verify("test2", encoded2)
		if result != 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
	t.Run("Doesn't match 2B", func(t *testing.T) {
		result := BCryptSHA256.Verify("test2", encoded3)
		if result != 0 {
			t.Error("Verifying encoded password didn't work")
		}
	})
}
