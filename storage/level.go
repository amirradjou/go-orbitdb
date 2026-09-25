package storage

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// DefaultLevelPath is the directory used when NewLevelStorage is given "".
const DefaultLevelPath = "./level"

// LevelStorage persists pairs in a LevelDB database on disk. The on-disk
// format is plain LevelDB, so a keystore written by the JavaScript
// implementation can be opened directly.
type LevelStorage struct {
	db *leveldb.DB
}

// NewLevelStorage opens (creating if needed) the LevelDB database at path.
func NewLevelStorage(path string) (*LevelStorage, error) {
	if path == "" {
		path = DefaultLevelPath
	}
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open level storage %q: %w", path, err)
	}
	return &LevelStorage{db: db}, nil
}

// Put implements Storage.
func (s *LevelStorage) Put(_ context.Context, key string, value []byte) error {
	return s.db.Put([]byte(key), value, nil)
}

// Get implements Storage.
func (s *LevelStorage) Get(_ context.Context, key string) ([]byte, error) {
	value, err := s.db.Get([]byte(key), nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return value, err
}

// Del implements Storage.
func (s *LevelStorage) Del(_ context.Context, key string) error {
	return s.db.Delete([]byte(key), nil)
}

// Iterator implements Storage. Pairs are yielded in key order, or descending
// key order when opts.Reverse is set.
func (s *LevelStorage) Iterator(_ context.Context, opts IteratorOptions) iter.Seq2[Pair, error] {
	return func(yield func(Pair, error) bool) {
		it := s.db.NewIterator(&util.Range{}, nil)
		defer it.Release()

		first, next := it.First, it.Next
		if opts.Reverse {
			first, next = it.Last, it.Prev
		}
		yielded := 0
		for ok := first(); ok; ok = next() {
			if opts.Amount > 0 && yielded >= opts.Amount {
				return
			}
			// The iterator reuses its buffers, so copy before handing out.
			p := Pair{Key: string(it.Key()), Value: append([]byte(nil), it.Value()...)}
			yielded++
			if !yield(p, nil) {
				return
			}
		}
		if err := it.Error(); err != nil {
			yield(Pair{}, err)
		}
	}
}

// Merge implements Storage.
func (s *LevelStorage) Merge(ctx context.Context, other Storage) error {
	if other == nil {
		return nil
	}
	batch := new(leveldb.Batch)
	for p, err := range other.Iterator(ctx, IteratorOptions{}) {
		if err != nil {
			return err
		}
		batch.Put([]byte(p.Key), p.Value)
	}
	return s.db.Write(batch, nil)
}

// Clear implements Storage.
func (s *LevelStorage) Clear(context.Context) error {
	it := s.db.NewIterator(&util.Range{}, nil)
	defer it.Release()
	batch := new(leveldb.Batch)
	for it.Next() {
		batch.Delete(append([]byte(nil), it.Key()...))
	}
	if err := it.Error(); err != nil {
		return err
	}
	return s.db.Write(batch, nil)
}

// Close implements Storage.
func (s *LevelStorage) Close() error {
	return s.db.Close()
}
