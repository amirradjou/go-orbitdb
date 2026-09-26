package databases

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
)

// KeyValueType is the type name of KeyValue databases.
const KeyValueType = "keyvalue"

// KeyValue is a key/value store. Reads walk the log from the heads, so the
// latest write to a key wins; KeyValueIndexed keeps an index instead.
type KeyValue struct {
	*Database
}

// KeyValueEntry is a key, its value and the hash of the entry that set it.
type KeyValueEntry struct {
	Key   string
	Value any
	Hash  string
}

// NewKeyValue opens a KeyValue database.
func NewKeyValue(ctx context.Context, p Params) (*KeyValue, error) {
	db, err := New(ctx, p)
	if err != nil {
		return nil, err
	}
	return &KeyValue{Database: db}, nil
}

// Type returns KeyValueType.
func (*KeyValue) Type() string { return KeyValueType }

// Put sets key to value and returns the hash of the entry.
func (kv *KeyValue) Put(ctx context.Context, key string, value any) (string, error) {
	if key == "" {
		return "", errors.New("key is required")
	}
	return kv.AddOperation(ctx, Operation{Op: "PUT", Key: key, Value: value}.payload())
}

// Set is an alias for Put.
func (kv *KeyValue) Set(ctx context.Context, key string, value any) (string, error) {
	return kv.Put(ctx, key, value)
}

// Del deletes key and returns the hash of the entry.
func (kv *KeyValue) Del(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", errors.New("key is required")
	}
	return kv.AddOperation(ctx, Operation{Op: "DEL", Key: key, Value: nil}.payload())
}

// Get returns the value of key, or an error wrapping ErrNotFound if the key
// was never set or was deleted.
func (kv *KeyValue) Get(ctx context.Context, key string) (any, error) {
	for entry, err := range kv.log.Traverse(ctx, nil, nil) {
		if err != nil {
			return nil, err
		}
		op, ok := ParseOperation(entry.Payload)
		if !ok {
			continue
		}
		if k, _ := op.Key.(string); k != key {
			continue
		}
		switch op.Op {
		case "PUT":
			return op.Value, nil
		case "DEL":
			return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
}

// Iterator yields the current value of every key, most recently written
// first. amount limits the number of keys; zero or negative means all.
func (kv *KeyValue) Iterator(ctx context.Context, amount int) iter.Seq2[KeyValueEntry, error] {
	return func(yield func(KeyValueEntry, error) bool) {
		seen := make(map[string]bool)
		count := 0
		for entry, err := range kv.log.Traverse(ctx, nil, nil) {
			if err != nil {
				yield(KeyValueEntry{}, err)
				return
			}
			op, ok := ParseOperation(entry.Payload)
			if !ok {
				continue
			}
			key, ok := keyString(op.Key)
			if !ok || seen[key] {
				continue
			}
			switch op.Op {
			case "PUT":
				seen[key] = true
				count++
				if !yield(KeyValueEntry{Key: key, Value: op.Value, Hash: entry.Hash}, nil) {
					return
				}
			case "DEL":
				seen[key] = true
			}
			if amount > 0 && count >= amount {
				return
			}
		}
	}
}

// All returns every key and its current value, least recently written
// first.
func (kv *KeyValue) All(ctx context.Context) ([]KeyValueEntry, error) {
	return collectReversed(kv.Iterator(ctx, 0))
}

func collectReversed[T any](seq iter.Seq2[T, error]) ([]T, error) {
	var out []T
	for v, err := range seq {
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	slices.Reverse(out)
	return out, nil
}
