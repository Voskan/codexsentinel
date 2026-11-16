package deps

import (
	"math"
	"testing"
)

func TestShannonEntropyUsesRunes(t *testing.T) {
	if got := shannonEntropy("пр"); math.Abs(got-1) > 1e-9 {
		t.Fatalf("entropy of two distinct runes = %v, want 1", got)
	}
}

func TestSecretWordsAreNotSafe(t *testing.T) {
	for _, v := range []string{"prod-secret-9f8a7b6c5d4e3f2a1b0c", "password=Zk3!qP9#vL"} {
		if isSafeEntropyPattern(v, nil) {
			t.Errorf("%q treated as safe", v)
		}
	}
}
