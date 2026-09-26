package storage

import (
	"context"
	"fmt"
	"iter"
	"slices"

	lru "github.com/hashicorp/golang-lru/v2"
)

// DefaultLRUSize is the capacity used when NewLRUStorage is given size <= 0.
const DefaultLRUSize = 1000000

// LRUStorage keeps the most recently used pairs in memory, evicting the least
// recently used one once it holds size pairs. It is used as the cache layer
// in front of slower storages.
type LRUStorage struct {
	cache *lru.Cache[string, []byte]
}

// NewLRUStorage returns an LRUStorage holding at most size pairs.
func NewLRUStorage(size int) (*LRUStorage, error) {
	if size <= 0 {
		size = DefaultLRUSize
	}
	cache, err := lru.New[string, []byte](size)
	if err != nil {
		return nil, err
	}
	return &LRUStorage{cache: cache}, nil
}

// Put implements Storage.
func (s *LRUStorage) Put(_ context.Context, key string, value []byte) error {
	s.cache.Add(key, value)
	return nil
}

// Get implements Storage.
func (s *LRUStorage) Get(_ context.Context, key string) ([]byte, error) {
	value, ok := s.cache.Get(key)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return value, nil
}

// Del implements Storage.
func (s *LRUStorage) Del(_ context.Context, key string) error {
	s.cache.Remove(key)
	return nil
}

// Iterator implements Storage. Pairs are yielded from the least to the most
// recently used; Reverse flips that order. Iterating does not change
// recency.
func (s *LRUStorage) Iterator(_ context.Context, opts IteratorOptions) iter.Seq2[Pair, error] {
	return func(yield func(Pair, error) bool) {
		keys := s.cache.Keys()
		if opts.Reverse {
			slices.Reverse(keys)
		}
		yielded := 0
		for _, k := range keys {
			if opts.Amount > 0 && yielded >= opts.Amount {
				return
			}
			v, ok := s.cache.Peek(k)
			if !ok {
				continue // evicted since Keys() was taken
			}
			yielded++
			if !yield(Pair{Key: k, Value: v}, nil) {
				return
			}
		}
	}
}

// Merge implements Storage.
func (s *LRUStorage) Merge(ctx context.Context, other Storage) error {
	return mergeInto(ctx, s, other)
}

// Clear implements Storage.
func (s *LRUStorage) Clear(context.Context) error {
	s.cache.Purge()
	return nil
}

// Close implements Storage. It is a no-op.
func (s *LRUStorage) Close() error { return nil }
