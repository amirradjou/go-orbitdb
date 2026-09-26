package storage

import (
	"context"
	"errors"
	"iter"
)

// ComposedStorage layers two storages, typically a fast cache (LRU) in front
// of a durable or remote one (Level, IPFS). Writes go to both; reads try the
// first and fall back to the second, copying a hit back into the first.
type ComposedStorage struct {
	first, second Storage
}

// NewComposedStorage composes first (checked first on reads) with second.
func NewComposedStorage(first, second Storage) *ComposedStorage {
	return &ComposedStorage{first: first, second: second}
}

// Put implements Storage.
func (s *ComposedStorage) Put(ctx context.Context, key string, value []byte) error {
	if err := s.first.Put(ctx, key, value); err != nil {
		return err
	}
	return s.second.Put(ctx, key, value)
}

// Get implements Storage.
func (s *ComposedStorage) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := s.first.Get(ctx, key)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	value, err = s.second.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if err := s.first.Put(ctx, key, value); err != nil {
		return nil, err
	}
	return value, nil
}

// Del implements Storage.
func (s *ComposedStorage) Del(ctx context.Context, key string) error {
	if err := s.first.Del(ctx, key); err != nil {
		return err
	}
	return s.second.Del(ctx, key)
}

// Iterator implements Storage. It yields the pairs of the first storage and
// then those of the second whose keys have not been seen yet. opts is passed
// to both, so Amount bounds each storage separately, as in @orbitdb/core.
func (s *ComposedStorage) Iterator(ctx context.Context, opts IteratorOptions) iter.Seq2[Pair, error] {
	return func(yield func(Pair, error) bool) {
		seen := make(map[string]struct{})
		for _, st := range []Storage{s.first, s.second} {
			for p, err := range st.Iterator(ctx, opts) {
				if err != nil {
					yield(Pair{}, err)
					return
				}
				if _, dup := seen[p.Key]; dup {
					continue
				}
				seen[p.Key] = struct{}{}
				if !yield(p, nil) {
					return
				}
			}
		}
	}
}

// Merge implements Storage. Like @orbitdb/core it merges in both directions:
// afterwards this storage and other each hold the union of both.
func (s *ComposedStorage) Merge(ctx context.Context, other Storage) error {
	if other == nil {
		return nil
	}
	for _, step := range []func() error{
		func() error { return s.first.Merge(ctx, other) },
		func() error { return s.second.Merge(ctx, other) },
		func() error { return other.Merge(ctx, s.first) },
		func() error { return other.Merge(ctx, s.second) },
	} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// Persist implements Persister by persisting key in whichever layers
// support it.
func (s *ComposedStorage) Persist(ctx context.Context, key string) error {
	for _, st := range []Storage{s.first, s.second} {
		if p, ok := st.(Persister); ok {
			if err := p.Persist(ctx, key); err != nil {
				return err
			}
		}
	}
	return nil
}

// Clear implements Storage.
func (s *ComposedStorage) Clear(ctx context.Context) error {
	if err := s.first.Clear(ctx); err != nil {
		return err
	}
	return s.second.Clear(ctx)
}

// Close implements Storage. Both layers are closed even if the first fails.
func (s *ComposedStorage) Close() error {
	return errors.Join(s.first.Close(), s.second.Close())
}
