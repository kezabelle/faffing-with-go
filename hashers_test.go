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

var hashables = []CrapHashable{
	{"SHA1", "sha1$woof$0b65bc32d57d63ecfbd8b0b4303fe09ffc5d566f", SHA1},
	{"MD5", "md5$woof$222feadb26d048c8ea411406b33d0b94", MD5},
}

func TestCrapPasswordHasher_Encode(t *testing.T) {
	for _, hashable := range hashables {
		t.Run(hashable.name, func(t *testing.T) {
			encoded, _ := hashable.hasher.Encode("test", "woof")
			expected := hashable.encoded_value
			if encoded != expected {
				t.Errorf("Expected %s, got %s", encoded, expected)
			}
		})
	}
}

func TestCrapPasswordHasher_Verify(t *testing.T) {
	for _, hashable := range hashables {
		t.Run(hashable.name, func(t *testing.T) {
			t.Run("Match", func(t *testing.T) {
				result := hashable.hasher.Verify("test", hashable.encoded_value);
				if result == 0 {
					t.Error("Verifying encoded password didn't work")
				}
			})
			t.Run("Doesn't match", func(t *testing.T) {
				result := hashable.hasher.Verify("test2", hashable.encoded_value);
				if result != 0 {
					t.Error("Verifying encoded password didn't work")
				}
			})
		})
	}
}
