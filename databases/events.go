package databases

import (
	"context"
	"iter"
	"slices"

	"github.com/orbitdb/go-orbitdb/oplog"
)

// EventsType is the type name of Events databases.
const EventsType = "events"

// Events is an immutable, append-only event log.
type Events struct {
	*Database
}

// EventEntry is an event and the hash of the entry that holds it.
type EventEntry struct {
	Hash  string
	Value any
}

// NewEvents opens an Events database.
func NewEvents(ctx context.Context, p Params) (*Events, error) {
	db, err := New(ctx, p)
	if err != nil {
		return nil, err
	}
	return &Events{Database: db}, nil
}

// Type returns EventsType.
func (*Events) Type() string { return EventsType }

// Add appends value and returns the hash of its entry.
func (e *Events) Add(ctx context.Context, value any) (string, error) {
	return e.AddOperation(ctx, Operation{Op: "ADD", Key: nil, Value: value}.payload())
}

// Get returns the event stored in the entry with the given hash.
func (e *Events) Get(ctx context.Context, hash string) (any, error) {
	entry, err := e.log.Get(ctx, hash)
	if err != nil {
		return nil, err
	}
	op, _ := ParseOperation(entry.Payload)
	return op.Value, nil
}

// Iterator yields events, newest first, optionally limited to a range of
// entry hashes (see oplog.IteratorOptions).
func (e *Events) Iterator(ctx context.Context, opts oplog.IteratorOptions) iter.Seq2[EventEntry, error] {
	return func(yield func(EventEntry, error) bool) {
		for entry, err := range e.log.Iterator(ctx, opts) {
			if err != nil {
				yield(EventEntry{}, err)
				return
			}
			op, _ := ParseOperation(entry.Payload)
			if !yield(EventEntry{Hash: entry.Hash, Value: op.Value}, nil) {
				return
			}
		}
	}
}

// All returns every event, oldest first.
func (e *Events) All(ctx context.Context) ([]EventEntry, error) {
	var out []EventEntry
	for ev, err := range e.Iterator(ctx, oplog.IteratorOptions{}) {
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	slices.Reverse(out)
	return out, nil
}
