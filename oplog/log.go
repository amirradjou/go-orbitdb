// Package oplog implements OrbitDB's operation log: an append-only,
// signed Merkle-CRDT of entries.
//
// It is a port of src/oplog in @orbitdb/core 4. Entries are byte-compatible
// with the JavaScript implementation, and the algorithms that decide entry
// contents (heads, references, traversal order, conflict resolution) follow
// it exactly, so a Go and a JavaScript peer appending the same operations
// produce the same hashes.
package oplog

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/storage"
)

// Options configures NewLog.
type Options struct {
	// LogID identifies the log; entries of other logs cannot be joined.
	// Defaults to the current Unix time in milliseconds.
	LogID string
	// LogHeads, if set, replaces the persisted heads.
	LogHeads []*Entry
	// AccessController decides who may write. Defaults to AllowAll.
	AccessController AccessController
	// EntryStorage holds entry blocks, IndexStorage records which entries
	// are part of the log and HeadsStorage the current heads. Each
	// defaults to a MemoryStorage.
	EntryStorage storage.Storage
	HeadsStorage storage.Storage
	IndexStorage storage.Storage
	// SortFn orders concurrent entries. Defaults to LastWriteWins.
	SortFn SortFn
	// Encryption turns on entry and/or payload encryption.
	Encryption Encryption
}

// AppendOptions configures Log.Append.
type AppendOptions struct {
	// ReferencesCount is how many entries beyond the heads the new entry
	// refers to, so readers can skip ahead when traversing.
	ReferencesCount int
}

// IteratorOptions selects a range of entries for Log.Iterator. Ranges are
// given by entry hash and follow the traversal order (newest first).
type IteratorOptions struct {
	// Amount limits the number of entries. Zero or negative means all.
	Amount int
	// GT and GTE end the iteration at an entry, excluding or including it.
	GT, GTE string
	// LT and LTE start the iteration at an entry, excluding or including
	// it.
	LT, LTE string
}

// Log is an append-only log of signed entries.
type Log struct {
	id         string
	identity   *identitytypes.Identity
	access     AccessController
	store      *oplogStore
	sortFn     SortFn
	encryption Encryption

	// mu serialises Append and JoinEntry, which read the heads and then
	// replace them.
	mu sync.Mutex
}

// NewLog creates a log that appends as identity.
func NewLog(ctx context.Context, identity *identitytypes.Identity, opts Options) (*Log, error) {
	if identity == nil {
		return nil, errors.New("identity is required")
	}
	id := opts.LogID
	if id == "" {
		id = strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	access := opts.AccessController
	if access == nil {
		access = AllowAll()
	}
	sortFn := opts.SortFn
	if sortFn == nil {
		sortFn = LastWriteWins
	}
	store := &oplogStore{
		entries:    orMemory(opts.EntryStorage),
		index:      orMemory(opts.IndexStorage),
		heads:      &heads{storage: orMemory(opts.HeadsStorage)},
		encryption: opts.Encryption,
	}
	if opts.LogHeads != nil {
		refs := make([]headRef, len(opts.LogHeads))
		for i, e := range opts.LogHeads {
			refs[i] = refOf(e)
		}
		if err := store.heads.set(ctx, refs); err != nil {
			return nil, err
		}
	}
	return &Log{
		id:         id,
		identity:   identity,
		access:     access,
		store:      store,
		sortFn:     sortFn,
		encryption: opts.Encryption,
	}, nil
}

func orMemory(s storage.Storage) storage.Storage {
	if s == nil {
		return storage.NewMemoryStorage()
	}
	return s
}

// ID returns the log id.
func (l *Log) ID() string { return l.id }

// Identity returns the identity the log appends as.
func (l *Log) Identity() *identitytypes.Identity { return l.identity }

// AccessController returns the log's access controller.
func (l *Log) AccessController() AccessController { return l.access }

// Storage returns the storage holding the log's entry blocks.
func (l *Log) Storage() storage.Storage { return l.store.entries }

// Encryption returns the log's encryption settings.
func (l *Log) Encryption() Encryption { return l.encryption }

// Clock returns the log's clock: the writer's public key at the latest time
// among the heads.
func (l *Log) Clock(ctx context.Context) (Clock, error) {
	heads, err := l.Heads(ctx)
	if err != nil {
		return Clock{}, err
	}
	return l.clockOf(heads), nil
}

func (l *Log) clockOf(heads []*Entry) Clock {
	var maxTime int64
	for _, h := range heads {
		maxTime = max(maxTime, h.Clock.Time)
	}
	return NewClock(l.identity.PublicKey, maxTime)
}

// Heads returns the current heads, latest first.
func (l *Log) Heads(ctx context.Context) ([]*Entry, error) {
	heads, err := l.store.currentHeads(ctx)
	if err != nil {
		return nil, err
	}
	l.sort(heads)
	slices.Reverse(heads)
	return heads, nil
}

// sort orders entries by sortFn. It is stable, like Array.prototype.sort,
// so entries that compare equal keep their order.
func (l *Log) sort(entries []*Entry) {
	slices.SortStableFunc(entries, func(a, b *Entry) int { return l.sortFn(a, b) })
}

// Values returns every entry in the log, oldest first.
func (l *Log) Values(ctx context.Context) ([]*Entry, error) {
	var out []*Entry
	for e, err := range l.Traverse(ctx, nil, nil) {
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	slices.Reverse(out)
	return out, nil
}

// Get returns the entry with the given hash. It returns an error wrapping
// storage.ErrNotFound if the entry is not stored.
func (l *Log) Get(ctx context.Context, hash string) (*Entry, error) {
	if hash == "" {
		return nil, errors.New("hash is required")
	}
	return l.store.get(ctx, hash)
}

// Has reports whether the entry with the given hash is part of the log.
func (l *Log) Has(ctx context.Context, hash string) (bool, error) {
	return l.store.has(ctx, hash)
}

// Append signs payload into a new entry on top of the current heads and
// makes it the only head.
func (l *Log) Append(ctx context.Context, payload any, opts AppendOptions) (*Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	heads, err := l.Heads(ctx)
	if err != nil {
		return nil, err
	}
	next := make([]string, len(heads))
	for i, h := range heads {
		next[i] = h.Hash
	}
	refs, err := l.references(ctx, heads, opts.ReferencesCount+len(heads))
	if err != nil {
		return nil, err
	}
	clock := TickClock(l.clockOf(heads))
	entry, err := CreateEntry(ctx, l.identity, l.id, payload, EntryOptions{
		Clock:          &clock,
		Next:           next,
		Refs:           refs,
		EncryptPayload: l.encryption.Data,
	})
	if err != nil {
		return nil, err
	}
	ok, err := l.access.CanAppend(ctx, entry)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("could not append entry: key %q is not allowed to write to the log", l.identity.Hash)
	}
	if err := l.store.setHead(ctx, entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// references returns up to amount hashes reachable from heads, skipping the
// heads themselves (the new entry's Next already points to them).
//
// @orbitdb/core slices its result with refs.slice(heads.length + 1, amount)
// after its traversal has popped one head off the same array, so it skips
// exactly len(heads) entries; that is what this does.
func (l *Log) references(ctx context.Context, heads []*Entry, amount int) ([]string, error) {
	var refs []string
	stop := func(*Entry) (bool, error) { return len(refs) >= amount && amount != -1, nil }
	for e, err := range l.Traverse(ctx, heads, stop) {
		if err != nil {
			return nil, err
		}
		refs = append(refs, e.Hash)
	}
	start := len(heads)
	if start == 0 {
		start = 1
	}
	end := amount
	if end < 0 {
		end += len(refs)
	}
	end = min(end, len(refs))
	if start >= end {
		return []string{}, nil
	}
	return refs[start:end], nil
}

// Join merges other into this log: other's entry blocks are copied into
// this log's entry storage and each of its heads is joined.
func (l *Log) Join(ctx context.Context, other *Log) error {
	if other == nil {
		return errors.New("log instance not defined")
	}
	if err := l.store.entries.Merge(ctx, other.Storage()); err != nil {
		return err
	}
	heads, err := other.Heads(ctx)
	if err != nil {
		return err
	}
	for _, h := range heads {
		if _, err := l.JoinEntry(ctx, h); err != nil {
			return err
		}
	}
	return nil
}

// JoinEntry adds an entry received from a peer, together with every
// ancestor the log does not have yet. Each new entry must belong to the log,
// pass the access controller and carry a valid signature. Ancestors are read
// from the entry storage, which fetches them from peers when it is backed
// by IPFS. It reports whether the log changed.
func (l *Log) JoinEntry(ctx context.Context, entry *Entry) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry == nil || entry.Hash == "" {
		return false, errors.New("entry has no hash; it must be decoded or stored first")
	}
	if has, err := l.Has(ctx, entry.Hash); err != nil || has {
		return false, err
	}
	if entry.block != nil {
		// Verify exactly what will be stored, even if the caller changed
		// fields of the decoded entry.
		var err error
		if entry, err = DecodeEntry(ctx, entry.block, l.encryption); err != nil {
			return false, err
		}
	}
	if err := l.verifyEntry(ctx, entry); err != nil {
		return false, err
	}

	heads, err := l.Heads(ctx)
	if err != nil {
		return false, err
	}
	isHead := make(map[string]bool, len(heads))
	for _, h := range heads {
		isHead[h.Hash] = true
	}

	toAdd := newOrderedSet(entry.Hash)
	toGet := newOrderedSet(append(slices.Clone(entry.Next), entry.Refs...)...)
	connectedHeads := newOrderedSet()

	for toGet.len() > 0 {
		for _, hash := range toGet.values() {
			e, err := l.store.get(ctx, hash)
			if err != nil {
				return false, fmt.Errorf("join %s: fetch %s: %w", entry.Hash, hash, err)
			}
			toGet.remove(hash)
			if err := l.verifyEntry(ctx, e); err != nil {
				return false, err
			}
			toAdd.add(e.Hash)
			for _, h := range append(slices.Clone(e.Next), e.Refs...) {
				inLog, err := l.Has(ctx, h)
				if err != nil {
					return false, err
				}
				if !inLog && !toAdd.has(h) {
					toGet.add(h)
				} else if isHead[h] {
					connectedHeads.add(h)
				}
			}
		}
	}

	if err := l.store.addHead(ctx, entry); err != nil {
		return false, err
	}
	if err := l.store.addVerified(ctx, toAdd.values()); err != nil {
		return false, err
	}
	if err := l.store.removeHeads(ctx, connectedHeads.values()); err != nil {
		return false, err
	}
	return true, nil
}

func (l *Log) verifyEntry(ctx context.Context, e *Entry) error {
	if e.ID != l.id {
		return fmt.Errorf("entry's id (%s) doesn't match the log's id (%s)", e.ID, l.id)
	}
	ok, err := l.access.CanAppend(ctx, e)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("could not append entry: key %q is not allowed to write to the log", e.Identity)
	}
	valid, err := VerifyEntry(e)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("could not validate signature for entry %q", e.Hash)
	}
	return nil
}

// Traverse walks the log from roots (the current heads when nil), yielding
// each reachable entry once, latest first according to the sort function.
// If shouldStop is set it is called after each yielded entry and ends the
// walk when it returns true. Entries missing from storage are skipped.
func (l *Log) Traverse(ctx context.Context, roots []*Entry, shouldStop func(*Entry) (bool, error)) iter.Seq2[*Entry, error] {
	return func(yield func(*Entry, error) bool) {
		if roots == nil {
			heads, err := l.Heads(ctx)
			if err != nil {
				yield(nil, err)
				return
			}
			roots = heads
		}
		// The prefetching below mirrors @orbitdb/core's traverse exactly:
		// which entries are on the stack at each step decides the order of
		// concurrent entries, and that order decides the refs of new
		// entries, so it has to match for hashes to match.
		stack := slices.Clone(roots)
		traversed := make(map[string]bool)
		fetched := make(map[string]bool)
		notIndexed := func(h string) bool { return !traversed[h] && !fetched[h] }
		var toFetch []string

		for len(stack) > 0 {
			l.sort(stack)
			entry := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if traversed[entry.Hash] {
				continue
			}
			if !yield(entry, nil) {
				return
			}
			if shouldStop != nil {
				done, err := shouldStop(entry)
				if err != nil {
					yield(nil, err)
					return
				}
				if done {
					return
				}
			}
			traversed[entry.Hash] = true
			fetched[entry.Hash] = true

			toFetch = slices.DeleteFunc(append(toFetch, entry.Next...), func(h string) bool { return !notIndexed(h) })
			var nexts []*Entry
			for _, h := range toFetch {
				if !notIndexed(h) {
					continue
				}
				fetched[h] = true
				e, err := l.store.get(ctx, h)
				if errors.Is(err, storage.ErrNotFound) {
					continue
				}
				if err != nil {
					yield(nil, err)
					return
				}
				nexts = append(nexts, e)
			}
			toFetch = toFetch[:0]
			seen := make(map[string]bool)
			for _, e := range nexts {
				for _, h := range e.Next {
					if !seen[h] && notIndexed(h) {
						seen[h] = true
						toFetch = append(toFetch, h)
					}
				}
			}
			stack = append(nexts, stack...)
		}
	}
}

// Iterator yields the entries selected by opts, latest first.
func (l *Log) Iterator(ctx context.Context, opts IteratorOptions) iter.Seq2[*Entry, error] {
	return func(yield func(*Entry, error) bool) {
		amount := opts.Amount
		if amount <= 0 {
			amount = -1
		}
		getOptional := func(hash string) (*Entry, error) {
			e, err := l.Get(ctx, hash)
			if errors.Is(err, storage.ErrNotFound) {
				return nil, nil
			}
			return e, err
		}

		var start []*Entry
		switch {
		case opts.LT != "":
			e, err := l.Get(ctx, opts.LT)
			if err != nil {
				yield(nil, err)
				return
			}
			for _, h := range e.Next {
				n, err := getOptional(h)
				if err != nil {
					yield(nil, err)
					return
				}
				if n != nil {
					start = append(start, n)
				}
			}
		case opts.LTE != "":
			e, err := getOptional(opts.LTE)
			if err != nil {
				yield(nil, err)
				return
			}
			if e != nil {
				start = []*Entry{e}
			}
		default:
			heads, err := l.Heads(ctx)
			if err != nil {
				yield(nil, err)
				return
			}
			start = heads
		}
		if start == nil {
			start = []*Entry{}
		}

		var end *Entry
		if endHash := cmpOr(opts.GT, opts.GTE); endHash != "" {
			var err error
			if end, err = getOptional(endHash); err != nil {
				yield(nil, err)
				return
			}
		}

		amountToIterate := amount
		if end != nil {
			amountToIterate = -1
		}
		count := 0
		stop := func(e *Entry) (bool, error) {
			count++
			if amountToIterate != -1 && count >= amountToIterate {
				return true, nil
			}
			return end != nil && IsEqual(e, end), nil
		}

		// With an end but no start, traversal has to run all the way to the
		// end, and the amount entries closest to it are the ones wanted.
		useBuffer := end != nil && amount != -1 && opts.LT == "" && opts.LTE == ""
		var buffer []*Entry

		for e, err := range l.Traverse(ctx, start, stop) {
			if err != nil {
				yield(nil, err)
				return
			}
			if opts.GT != "" && IsEqual(e, end) {
				continue
			}
			if useBuffer {
				buffer = append(buffer, e)
				continue
			}
			if !yield(e, nil) {
				return
			}
		}
		if useBuffer {
			for _, e := range buffer[max(0, len(buffer)-amount):] {
				if !yield(e, nil) {
					return
				}
			}
		}
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Clear removes every entry, head and index record.
func (l *Log) Clear(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.store.clear(ctx)
}

// Close waits for a pending Append or JoinEntry and closes the storages.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.store.close()
}

// orderedSet is an insertion-ordered set of strings, like a JS Set.
type orderedSet struct {
	index map[string]int
	items []string
}

func newOrderedSet(items ...string) *orderedSet {
	s := &orderedSet{index: make(map[string]int)}
	for _, it := range items {
		s.add(it)
	}
	return s
}

func (s *orderedSet) add(v string) {
	if _, ok := s.index[v]; !ok {
		s.index[v] = len(s.items)
		s.items = append(s.items, v)
	}
}

func (s *orderedSet) has(v string) bool {
	_, ok := s.index[v]
	return ok
}

func (s *orderedSet) remove(v string) {
	if _, ok := s.index[v]; !ok {
		return
	}
	delete(s.index, v)
	s.items = slices.DeleteFunc(s.items, func(x string) bool { return x == v })
	for i, it := range s.items {
		s.index[it] = i
	}
}

func (s *orderedSet) len() int { return len(s.items) }

func (s *orderedSet) values() []string { return slices.Clone(s.items) }
