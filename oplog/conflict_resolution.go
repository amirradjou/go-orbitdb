package oplog

import "strings"

// SortFn orders two entries, returning a negative number when a sorts
// before b (is older) and a positive number when it sorts after. Log uses it
// to order heads and traversal; the default is LastWriteWins.
type SortFn func(a, b *Entry) int

// LastWriteWins orders entries by clock time, then by clock id. Entries with
// identical clocks compare equal and keep their relative order.
func LastWriteWins(a, b *Entry) int {
	first := func(*Entry, *Entry) int { return 0 }
	sortByID := func(a, b *Entry) int { return SortByClockID(a, b, first) }
	return SortByClocks(a, b, sortByID)
}

// SortByClocks orders entries by clock and calls resolveConflict for
// entries with identical clocks.
func SortByClocks(a, b *Entry, resolveConflict SortFn) int {
	if diff := CompareClocks(a.Clock, b.Clock); diff != 0 {
		return diff
	}
	return resolveConflict(a, b)
}

// SortByClockID orders entries by clock id and calls resolveConflict for
// entries with the same clock id.
func SortByClockID(a, b *Entry, resolveConflict SortFn) int {
	if a.Clock.ID == b.Clock.ID {
		return resolveConflict(a, b)
	}
	return strings.Compare(a.Clock.ID, b.Clock.ID)
}
