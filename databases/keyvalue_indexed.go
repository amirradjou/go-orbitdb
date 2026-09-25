package databases

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"path/filepath"

	"github.com/amirradjou/go-orbitdb/internal/block"
	"github.com/amirradjou/go-orbitdb/oplog"
	"github.com/amirradjou/go-orbitdb/storage"
)

// KeyValueIndexed is a KeyValue database that keeps the latest value of
// every key in a LevelDB index, so reads do not walk the log. Its type name
// is KeyValueType: it is a drop-in replacement, opened with
// orbitdb.WithDatabase(databases.KeyValueIndexedFactory).
type KeyValueIndexed struct {
	*KeyValue
	index   storage.Storage // key -> indexed record
	indexed storage.Storage // entry hash -> indexed marker
}

// KeyValueIndexedFactory opens KeyValueIndexed databases.
func KeyValueIndexedFactory(ctx context.Context, p Params) (Store, error) {
	return NewKeyValueIndexed(ctx, p)
}

// NewKeyValueIndexed opens a KeyValueIndexed database. The index lives in
// Directory/<address>/_index.
func NewKeyValueIndexed(ctx context.Context, p Params) (*KeyValueIndexed, error) {
	dir := p.Directory
	if dir == "" {
		dir = DefaultDirectory
	}
	dir = filepath.Join(dir, filepath.FromSlash(p.Address), "_index")
	index, err := storage.NewLevelStorage(dir)
	if err != nil {
		return nil, err
	}
	indexed, err := storage.NewLevelStorage(filepath.Join(dir, "_indexedEntries"))
	if err != nil {
		_ = index.Close()
		return nil, err
	}
	kvi := &KeyValueIndexed{index: index, indexed: indexed}

	userOnUpdate := p.OnUpdate
	p.OnUpdate = func(ctx context.Context, log *oplog.Log, entry *oplog.Entry) error {
		if err := kvi.update(ctx, log, entry); err != nil {
			return err
		}
		if userOnUpdate != nil {
			return userOnUpdate(ctx, log, entry)
		}
		return nil
	}
	kv, err := NewKeyValue(ctx, p)
	if err != nil {
		_ = index.Close()
		_ = indexed.Close()
		return nil, err
	}
	kvi.KeyValue = kv
	return kvi, nil
}

// update indexes the entries the log gained with entry. It walks back from
// the heads until entry and every entry it points to are indexed; the first
// operation seen for a key (the latest) decides its value.
func (kvi *KeyValueIndexed) update(ctx context.Context, log *oplog.Log, latest *oplog.Entry) error {
	isIndexed := func(hash string) (bool, error) {
		_, err := kvi.indexed.Get(ctx, hash)
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	}
	keys := make(map[string]bool)
	toBeIndexed := make(map[string]bool)
	stop := func(e *oplog.Entry) (bool, error) {
		for _, h := range e.Next {
			ok, err := isIndexed(h)
			if err != nil {
				return false, err
			}
			if !ok {
				toBeIndexed[h] = true
			}
		}
		ok, err := isIndexed(latest.Hash)
		return ok && len(toBeIndexed) == 0, err
	}
	for e, err := range log.Traverse(ctx, nil, stop) {
		if err != nil {
			return err
		}
		done, err := isIndexed(e.Hash)
		if err != nil {
			return err
		}
		if done {
			continue
		}
		op, ok := ParseOperation(e.Payload)
		key, isKey := keyString(op.Key)
		if ok && isKey && !keys[key] {
			switch op.Op {
			case "PUT":
				keys[key] = true
				_, record, err := block.Encode(map[string]any{"hash": e.Hash, "key": op.Key, "value": op.Value})
				if err != nil {
					return err
				}
				if err := kvi.index.Put(ctx, key, record); err != nil {
					return err
				}
				if err := kvi.indexed.Put(ctx, e.Hash, []byte{1}); err != nil {
					return err
				}
			case "DEL":
				keys[key] = true
				if err := kvi.index.Del(ctx, key); err != nil {
					return err
				}
				if err := kvi.indexed.Put(ctx, e.Hash, []byte{1}); err != nil {
					return err
				}
			}
		}
		delete(toBeIndexed, e.Hash)
	}
	return nil
}

func decodeRecord(data []byte) (KeyValueEntry, error) {
	v, err := block.Decode(data)
	if err != nil {
		return KeyValueEntry{}, err
	}
	m, err := block.Map(v)
	if err != nil {
		return KeyValueEntry{}, err
	}
	key, _ := keyString(m["key"])
	hash, _ := m["hash"].(string)
	return KeyValueEntry{Key: key, Value: m["value"], Hash: hash}, nil
}

// Get returns the value of key from the index, or an error wrapping
// ErrNotFound.
func (kvi *KeyValueIndexed) Get(ctx context.Context, key string) (any, error) {
	data, err := kvi.index.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	if err != nil {
		return nil, err
	}
	rec, err := decodeRecord(data)
	if err != nil {
		return nil, err
	}
	return rec.Value, nil
}

// Iterator yields every key and its value from the index, in descending key
// order. amount limits the number of keys; zero or negative means all.
func (kvi *KeyValueIndexed) Iterator(ctx context.Context, amount int) iter.Seq2[KeyValueEntry, error] {
	return func(yield func(KeyValueEntry, error) bool) {
		for p, err := range kvi.index.Iterator(ctx, storage.IteratorOptions{Amount: amount, Reverse: true}) {
			if err != nil {
				yield(KeyValueEntry{}, err)
				return
			}
			rec, err := decodeRecord(p.Value)
			if !yield(rec, err) || err != nil {
				return
			}
		}
	}
}

// All returns every key and its value, in ascending key order.
func (kvi *KeyValueIndexed) All(ctx context.Context) ([]KeyValueEntry, error) {
	return collectReversed(kvi.Iterator(ctx, 0))
}

// Close closes the database and its index.
func (kvi *KeyValueIndexed) Close() error {
	return errors.Join(kvi.KeyValue.Close(), kvi.index.Close(), kvi.indexed.Close())
}

// Drop drops the database and clears its index.
func (kvi *KeyValueIndexed) Drop(ctx context.Context) error {
	return errors.Join(kvi.KeyValue.Drop(ctx), kvi.index.Clear(ctx), kvi.indexed.Clear(ctx))
}
