package main

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"bladedr/internal/store"
)

func obs(id string) *store.Observation { return &store.Observation{ID: id, RuleID: id} }

func TestEventBufferDrainsOnSuccess(t *testing.T) {
	b := &eventBuffer{}
	for i := 0; i < 3; i++ {
		b.add(obs(strconv.Itoa(i)))
	}
	sent := 0
	b.flush(time.Now(), func(batch []*store.Observation) error { sent += len(batch); return nil })
	if sent != 3 {
		t.Fatalf("sent %d, want 3", sent)
	}
	if len(b.pending) != 0 {
		t.Fatalf("pending not drained: %d", len(b.pending))
	}
}

func TestEventBufferKeepsEventsAndBacksOffOnFailure(t *testing.T) {
	b := &eventBuffer{}
	b.add(obs("a"))
	now := time.Now()
	calls := 0
	down := func([]*store.Observation) error { calls++; return errors.New("server down") }

	b.flush(now, down)
	if calls != 1 || len(b.pending) != 1 {
		t.Fatalf("first failure: calls=%d pending=%d, want 1/1", calls, len(b.pending))
	}
	if !b.nextTry.After(now) {
		t.Fatal("backoff not armed after failure")
	}
	// While backing off, flush must not attempt another send.
	b.flush(now.Add(time.Second), down)
	if calls != 1 {
		t.Fatalf("retried during backoff (calls=%d)", calls)
	}
	// Past the backoff window it retries.
	b.flush(b.nextTry.Add(time.Millisecond), down)
	if calls != 2 {
		t.Fatalf("did not retry after backoff (calls=%d)", calls)
	}
}

func TestEventBufferRecoversAfterOutage(t *testing.T) {
	b := &eventBuffer{}
	b.add(obs("a"))
	now := time.Now()
	b.flush(now, func([]*store.Observation) error { return errors.New("down") })
	b.flush(b.nextTry.Add(time.Millisecond), func([]*store.Observation) error { return nil })
	if len(b.pending) != 0 {
		t.Fatalf("pending not drained after recovery: %d", len(b.pending))
	}
	if b.failStreak != 0 || !b.nextTry.IsZero() {
		t.Fatalf("failStreak/nextTry not reset: %d %v", b.failStreak, b.nextTry)
	}
}

func TestEventBufferChunksBacklog(t *testing.T) {
	b := &eventBuffer{}
	total := maxPostBatch*2 + 10
	for i := 0; i < total; i++ {
		b.add(obs(strconv.Itoa(i)))
	}
	var sizes []int
	b.flush(time.Now(), func(batch []*store.Observation) error {
		sizes = append(sizes, len(batch))
		return nil
	})
	sum := 0
	for _, s := range sizes {
		if s > maxPostBatch {
			t.Fatalf("chunk of %d exceeds maxPostBatch %d", s, maxPostBatch)
		}
		sum += s
	}
	if sum != total || len(b.pending) != 0 {
		t.Fatalf("drained %d in %d chunks, %d left; want %d/0", sum, len(sizes), len(b.pending), total)
	}
}

func TestEventBufferCapsAndDropsOldest(t *testing.T) {
	b := &eventBuffer{}
	for i := 0; i < maxBufferedEvents+50; i++ {
		b.add(obs(strconv.Itoa(i)))
	}
	if len(b.pending) != maxBufferedEvents {
		t.Fatalf("buffer len %d, want cap %d", len(b.pending), maxBufferedEvents)
	}
	if b.dropped != 50 {
		t.Fatalf("dropped %d, want 50", b.dropped)
	}
	if b.pending[0].ID != "50" {
		t.Fatalf("oldest not dropped: front is %q, want \"50\"", b.pending[0].ID)
	}
}
