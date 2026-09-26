package oplog

import "strings"

// Clock is a Lamport clock. ID is the public key of the writer that
// produced the entry, Time its logical time.
type Clock struct {
	ID   string
	Time int64
}

// NewClock returns a clock with the given id and time.
func NewClock(id string, time int64) Clock {
	return Clock{ID: id, Time: time}
}

// CompareClocks orders clocks by time and, for concurrent clocks with
// different ids, by id. The result is negative when a is less than b and
// positive when it is greater; it is zero only when a and b are the same
// clock.
func CompareClocks(a, b Clock) int {
	dist := a.Time - b.Time
	if dist == 0 && a.ID != b.ID {
		return strings.Compare(a.ID, b.ID)
	}
	switch {
	case dist < 0:
		return -1
	case dist > 0:
		return 1
	}
	return 0
}

// TickClock returns c advanced by one.
func TickClock(c Clock) Clock {
	return Clock{ID: c.ID, Time: c.Time + 1}
}
