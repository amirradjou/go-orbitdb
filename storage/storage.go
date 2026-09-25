// Package storage provides the key/value storage backends OrbitDB uses for
// log entries, heads, indexes, keys and identities.
//
// It mirrors src/storage in @orbitdb/core: MemoryStorage, LRUStorage,
// LevelStorage, IPFSBlockStorage and ComposedStorage all implement Storage,
// so any of them can be plugged in wherever a database or log accepts one.
package storage

import (
	"context"
	"errors"
	"iter"
)

// ErrNotFound is returned by Get when a key is not present.
var ErrNotFound = errors.New("storage: key not found")

// Pair is a single key/value record yielded by Storage.Iterator.
type Pair struct {
	Key   string
	Value []byte
}

// IteratorOptions controls Storage.Iterator.
type IteratorOptions struct {
	// Amount limits the number of pairs yielded. Zero or negative means no
	// limit.
	Amount int
	// Reverse iterates in descending key order. Backends without a key order
	// (LRU, IPFS) ignore it.
	Reverse bool
}

// Storage is a byte-oriented key/value store.
//
// Implementations must be safe for concurrent use.
type Storage interface {
	// Put stores value under key, replacing any existing value.
	Put(ctx context.Context, key string, value []byte) error

	// Get returns the value stored under key, or an error wrapping
	// ErrNotFound if there is none.
	Get(ctx context.Context, key string) ([]byte, error)

	// Del removes key. Removing a missing key is not an error.
	Del(ctx context.Context, key string) error

	// Iterator yields every stored pair. If the backend fails mid-way it
	// yields a zero Pair with the error and stops.
	Iterator(ctx context.Context, opts IteratorOptions) iter.Seq2[Pair, error]

	// Merge copies every pair of other into this storage.
	Merge(ctx context.Context, other Storage) error

	// Clear removes every pair.
	Clear(ctx context.Context) error

	// Close releases the resources held by the storage.
	Close() error
}

// Persister is implemented by storages that can make a stored value durable
// beyond their normal retention, e.g. IPFSBlockStorage pins the block.
type Persister interface {
	Persist(ctx context.Context, key string) error
}

// mergeInto copies every pair yielded by src into dst.
func mergeInto(ctx context.Context, dst, src Storage) error {
	if src == nil {
		return nil
	}
	for p, err := range src.Iterator(ctx, IteratorOptions{}) {
		if err != nil {
			return err
		}
		if err := dst.Put(ctx, p.Key, p.Value); err != nil {
			return err
		}
	}
	return nil
}

// limit returns the number of pairs to yield out of n given an Amount option.
func limit(amount, n int) int {
	if amount > 0 && amount < n {
		return amount
	}
	return n
}
