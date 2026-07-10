package main

import (
	"time"

	"bladedr/internal/store"
)

const (
	maxBufferedEvents = 10000            // cap so a long server outage can't OOM the sensor
	maxPostBatch      = 500              // events per POST when draining a backlog
	postBackoffBase   = 2 * time.Second  // first retry delay after a failed send
	postBackoffMax    = 60 * time.Second // retry-delay ceiling
)

// eventBuffer holds observations the server hasn't accepted yet. It rides out
// transient outages by keeping unsent events (bounded — oldest dropped past the cap),
// draining them in chunks, and backing off between failed attempts instead of
// hammering a down server. Not durable: a sensor restart loses the buffer.
type eventBuffer struct {
	pending    []*store.Observation
	dropped    int // events discarded at the cap since the last report
	failStreak int
	nextTry    time.Time
}

// add appends an event, dropping the oldest once the buffer is at capacity.
func (b *eventBuffer) add(o *store.Observation) {
	b.pending = append(b.pending, o)
	if over := len(b.pending) - maxBufferedEvents; over > 0 {
		b.pending = append(b.pending[:0], b.pending[over:]...)
		b.dropped += over
	}
}

// flush sends buffered events in chunks. It stops early (keeping the remainder for a
// later call) when send fails, and applies an exponential backoff so repeated
// failures don't spin. now is injected so the backoff is testable.
func (b *eventBuffer) flush(now time.Time, send func([]*store.Observation) error) {
	if len(b.pending) == 0 || now.Before(b.nextTry) {
		return
	}
	for len(b.pending) > 0 {
		n := min(len(b.pending), maxPostBatch)
		if err := send(b.pending[:n]); err != nil {
			b.failStreak++
			b.nextTry = now.Add(min(postBackoffBase<<min(b.failStreak-1, 5), postBackoffMax))
			return
		}
		b.pending = append(b.pending[:0], b.pending[n:]...) // drop the sent chunk, reuse the array
	}
	b.failStreak = 0
	b.nextTry = time.Time{}
}
