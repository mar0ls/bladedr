package api

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

// TestMain silences the structured access log so it doesn't clutter test output.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
