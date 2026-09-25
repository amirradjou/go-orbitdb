package storage

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// backends returns a fresh instance of every ordered, enumerable backend.
func backends(t *testing.T) map[string]Storage {
	t.Helper()
	lru, err := NewLRUStorage(100)
	require.NoError(t, err)
	level, err := NewLevelStorage(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = level.Close() })
	cacheLRU, err := NewLRUStorage(100)
	require.NoError(t, err)
	return map[string]Storage{
		"memory":   NewMemoryStorage(),
		"lru":      lru,
		"level":    level,
		"composed": NewComposedStorage(cacheLRU, NewMemoryStorage()),
	}
}

func collect(t *testing.T, s Storage, opts IteratorOptions) []Pair {
	t.Helper()
	var out []Pair
	for p, err := range s.Iterator(context.Background(), opts) {
		require.NoError(t, err)
		out = append(out, p)
	}
	return out
}

func keys(pairs []Pair) []string {
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.Key
	}
	return out
}

func TestStorageConformance(t *testing.T) {
	ctx := context.Background()
	for name, s := range backends(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, s.Put(ctx, "key1", []byte("value1")))
			v, err := s.Get(ctx, "key1")
			require.NoError(t, err)
			require.Equal(t, []byte("value1"), v)

			_, err = s.Get(ctx, "missing")
			require.ErrorIs(t, err, ErrNotFound)

			require.NoError(t, s.Put(ctx, "key1", []byte("value2")))
			v, err = s.Get(ctx, "key1")
			require.NoError(t, err)
			require.Equal(t, []byte("value2"), v, "put overwrites")

			require.NoError(t, s.Del(ctx, "key1"))
			_, err = s.Get(ctx, "key1")
			require.ErrorIs(t, err, ErrNotFound)
			require.NoError(t, s.Del(ctx, "key1"), "deleting a missing key is not an error")

			// Values are bytes, not strings: invalid UTF-8 must survive.
			binary := []byte{0x00, 0xff, 0xfe, 0x80}
			require.NoError(t, s.Put(ctx, "bin", binary))
			v, err = s.Get(ctx, "bin")
			require.NoError(t, err)
			require.Equal(t, binary, v)
			got := collect(t, s, IteratorOptions{})
			require.Len(t, got, 1)
			require.Equal(t, binary, got[0].Value)

			require.NoError(t, s.Clear(ctx))
			require.Empty(t, collect(t, s, IteratorOptions{}))
		})
	}
}

func TestStorageIteratorOrderAndAmount(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]Storage{
		"memory": NewMemoryStorage(),
		"level":  backends(t)["level"],
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"b", "d", "a", "c"} {
				require.NoError(t, s.Put(ctx, k, []byte(k)))
			}
			require.Equal(t, []string{"a", "b", "c", "d"}, keys(collect(t, s, IteratorOptions{})))
			require.Equal(t, []string{"d", "c", "b", "a"}, keys(collect(t, s, IteratorOptions{Reverse: true})))
			require.Equal(t, []string{"d", "c"}, keys(collect(t, s, IteratorOptions{Reverse: true, Amount: 2})))
			require.Equal(t, []string{"a"}, keys(collect(t, s, IteratorOptions{Amount: 1})))

			// Breaking out of the loop early must not leak or panic.
			for range s.Iterator(ctx, IteratorOptions{}) {
				break
			}
		})
	}
}

func TestStorageMerge(t *testing.T) {
	ctx := context.Background()
	for name, s := range backends(t) {
		t.Run(name, func(t *testing.T) {
			other := NewMemoryStorage()
			require.NoError(t, other.Put(ctx, "x", []byte("1")))
			require.NoError(t, other.Put(ctx, "y", []byte("2")))
			require.NoError(t, s.Put(ctx, "z", []byte("3")))
			require.NoError(t, s.Merge(ctx, other))
			for _, k := range []string{"x", "y", "z"} {
				_, err := s.Get(ctx, k)
				require.NoError(t, err, k)
			}
			require.NoError(t, s.Merge(ctx, nil))
		})
	}
}

func TestLRUStorageEvicts(t *testing.T) {
	ctx := context.Background()
	s, err := NewLRUStorage(2)
	require.NoError(t, err)
	require.NoError(t, s.Put(ctx, "a", []byte("1")))
	require.NoError(t, s.Put(ctx, "b", []byte("2")))
	_, err = s.Get(ctx, "a") // a is now the most recently used
	require.NoError(t, err)
	require.NoError(t, s.Put(ctx, "c", []byte("3")))

	_, err = s.Get(ctx, "b")
	require.ErrorIs(t, err, ErrNotFound, "least recently used key is evicted")
	require.Equal(t, []string{"a", "c"}, keys(collect(t, s, IteratorOptions{})))
}

func TestLevelStoragePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := NewLevelStorage(dir)
	require.NoError(t, err)
	require.NoError(t, s.Put(ctx, "k", []byte("v")))
	require.NoError(t, s.Close())

	s, err = NewLevelStorage(dir)
	require.NoError(t, err)
	defer s.Close()
	v, err := s.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("v"), v)
}

func TestComposedStorageReadThrough(t *testing.T) {
	ctx := context.Background()
	cache, err := NewLRUStorage(10)
	require.NoError(t, err)
	backing := NewMemoryStorage()
	s := NewComposedStorage(cache, backing)

	require.NoError(t, backing.Put(ctx, "k", []byte("v")))
	_, err = cache.Get(ctx, "k")
	require.ErrorIs(t, err, ErrNotFound)

	v, err := s.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("v"), v)
	v, err = cache.Get(ctx, "k")
	require.NoError(t, err, "a hit in the second layer is copied into the first")
	require.Equal(t, []byte("v"), v)

	// Keys present in both layers are yielded once.
	require.NoError(t, s.Put(ctx, "j", []byte("w")))
	require.ElementsMatch(t, []string{"j", "k"}, keys(collect(t, s, IteratorOptions{})))
}

func TestComposedStorageMergesBothWays(t *testing.T) {
	ctx := context.Background()
	a := NewComposedStorage(NewMemoryStorage(), NewMemoryStorage())
	b := NewMemoryStorage()
	require.NoError(t, a.Put(ctx, "from-a", []byte("1")))
	require.NoError(t, b.Put(ctx, "from-b", []byte("2")))
	require.NoError(t, a.Merge(ctx, b))
	for _, s := range []Storage{a, b} {
		require.ElementsMatch(t, []string{"from-a", "from-b"}, keys(collect(t, s, IteratorOptions{})))
	}
}

type failingStorage struct{ *MemoryStorage }

var errBoom = errors.New("boom")

func (failingStorage) Get(context.Context, string) ([]byte, error) { return nil, errBoom }

func TestComposedStoragePropagatesRealErrors(t *testing.T) {
	s := NewComposedStorage(failingStorage{NewMemoryStorage()}, NewMemoryStorage())
	_, err := s.Get(context.Background(), "k")
	require.ErrorIs(t, err, errBoom, "only ErrNotFound falls through to the second layer")
}

func TestMemoryStorageConcurrentIterateAndPut(t *testing.T) {
	// The old implementation ranged over the live map from a goroutine and
	// crashed with "concurrent map iteration and map write" under load.
	ctx := context.Background()
	s := NewMemoryStorage()
	for i := range 100 {
		require.NoError(t, s.Put(ctx, fmt.Sprint(i), []byte("v")))
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 1000 {
			_ = s.Put(ctx, fmt.Sprint("w", i), []byte("v"))
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			for range s.Iterator(ctx, IteratorOptions{}) {
			}
		}
	}()
	wg.Wait()
	require.True(t, slices.Contains(keys(collect(t, s, IteratorOptions{})), "w999"))
}
