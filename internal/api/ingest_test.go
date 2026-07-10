package api

import "testing"

func TestAcceptsIngestToken(t *testing.T) {
	// Comma-separated list with surrounding spaces: both are accepted (rotation window).
	a := &API{IngestToken: "new-tok , old-tok"}
	cases := []struct {
		tok  string
		want bool
	}{
		{"new-tok", true},
		{"old-tok", true},
		{"nope", false},
		{"", false},
		{"new-tok,old-tok", false}, // the raw list is not itself a valid token
	}
	for _, c := range cases {
		if got := a.acceptsIngestToken(c.tok); got != c.want {
			t.Errorf("acceptsIngestToken(%q) = %v, want %v", c.tok, got, c.want)
		}
	}

	// No ingest token configured: nothing is accepted.
	if (&API{}).acceptsIngestToken("anything") {
		t.Error("empty IngestToken must reject all tokens")
	}
}
