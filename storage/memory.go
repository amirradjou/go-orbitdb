package storage

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"sync"
)

// MemoryStorage keeps pairs in a map. It is the default storage for logs
// that are not given one.
type MemoryStorage struct {
	mu     sync.RWMutex
	memory map[string][]byte
}

// NewMemoryStorage returns an empty MemoryStorage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{memory: make(map[string][]byte)}
}

// Put implements Storage.
func (s *MemoryStorage) Put(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memory[key] = value
	return nil
}

// Get implements Storage.
func (s *MemoryStorage) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.memory[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return value, nil
}

// Del implements Storage.
func (s *MemoryStorage) Del(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.memory, key)
	return nil
}

// Iterator implements Storage. Pairs are yielded in key order from a
// snapshot taken when iteration starts, so the storage may be modified
// while iterating.
func (s *MemoryStorage) Iterator(_ context.Context, opts IteratorOptions) iter.Seq2[Pair, error] {
	return func(yield func(Pair, error) bool) {
		s.mu.RLock()
		pairs := make([]Pair, 0, len(s.memory))
		for k, v := range s.memory {
			pairs = append(pairs, Pair{Key: k, Value: v})
		}
		s.mu.RUnlock()

		slices.SortFunc(pairs, func(a, b Pair) int {
			if opts.Reverse {
				a, b = b, a
			}
			switch {
			case a.Key < b.Key:
				return -1
			case a.Key > b.Key:
				return 1
			}
			return 0
		})
		for _, p := range pairs[:limit(opts.Amount, len(pairs))] {
			if !yield(p, nil) {
				return
			}
		}
	}
}

// Merge implements Storage.
func (s *MemoryStorage) Merge(ctx context.Context, other Storage) error {
	return mergeInto(ctx, s, other)
}

// Clear implements Storage.
func (s *MemoryStorage) Clear(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memory = make(map[string][]byte)
	return nil
}

// Close implements Storage. It is a no-op.
func (s *MemoryStorage) Close() error { return nil }
