package auth

import (
	"testing"
	"time"
)

func TestDummyCheckPasswordAlwaysFails(t *testing.T) {
	for _, pw := range []string{"", "hunter2", "correct horse battery staple"} {
		if DummyCheckPassword(pw) {
			t.Fatalf("DummyCheckPassword(%q) returned true", pw)
		}
	}
}

// The decoy comparison must cost roughly what a real one costs, otherwise the
// no-such-user branch is still distinguishable by latency. Comparing the two
// durations directly would be flaky on a loaded CI box, so this asserts the far
// weaker property that actually matters: the decoy is not orders of magnitude
// cheaper than a genuine bcrypt verification.
func TestDummyCheckPasswordCostsLikeRealVerification(t *testing.T) {
	hash, err := HashPassword("a-real-password")
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	CheckPassword(hash, "wrong-password")
	real := time.Since(start)

	start = time.Now()
	DummyCheckPassword("wrong-password")
	decoy := time.Since(start)

	if decoy < real/4 {
		t.Fatalf("decoy verification took %v vs %v for a real one; unknown users are distinguishable by latency", decoy, real)
	}
}
