package databases

import (
	"context"
	"fmt"
	"iter"

	"github.com/amirradjou/go-orbitdb/internal/block"
	"github.com/amirradjou/go-orbitdb/oplog"
)

// DocumentsType is the type name of Documents databases.
const DocumentsType = "documents"

// DefaultIndexBy is the document field Documents uses as the key.
const DefaultIndexBy = "_id"

// DocumentsOptions configures a Documents database.
type DocumentsOptions struct {
	// IndexBy is the field holding each document's key. Defaults to
	// DefaultIndexBy.
	IndexBy string
}

// Documents stores documents (maps, or structs that encode to maps) keyed
// by one of their fields.
type Documents struct {
	*Database
	indexBy string
}

// Document is a stored document, its key and the hash of the entry that
// stored it.
type Document struct {
	Key   string
	Value map[string]any
	Hash  string
}

// DocumentsFactory returns a Factory for Documents databases with opts.
func DocumentsFactory(opts DocumentsOptions) Factory {
	return func(ctx context.Context, p Params) (Store, error) {
		return NewDocuments(ctx, p, opts)
	}
}

// NewDocuments opens a Documents database.
func NewDocuments(ctx context.Context, p Params, opts DocumentsOptions) (*Documents, error) {
	db, err := New(ctx, p)
	if err != nil {
		return nil, err
	}
	indexBy := opts.IndexBy
	if indexBy == "" {
		indexBy = DefaultIndexBy
	}
	return &Documents{Database: db, indexBy: indexBy}, nil
}

// Type returns DocumentsType.
func (*Documents) Type() string { return DocumentsType }

// IndexBy returns the key field.
func (d *Documents) IndexBy() string { return d.indexBy }

// Put stores doc under the value of its IndexBy field and returns the hash
// of the entry. doc may be a map or a struct (encoded through its JSON
// form).
func (d *Documents) Put(ctx context.Context, doc any) (string, error) {
	m, err := toDocument(doc)
	if err != nil {
		return "", err
	}
	key := m[d.indexBy]
	if isFalsy(key) {
		return "", fmt.Errorf("the provided document doesn't contain field %q", d.indexBy)
	}
	return d.AddOperation(ctx, Operation{Op: "PUT", Key: key, Value: m}.payload())
}

// Del deletes the document with the given key.
func (d *Documents) Del(ctx context.Context, key string) (string, error) {
	doc, err := d.get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("no document with key %q in the database: %w", key, err)
	}
	return d.AddOperation(ctx, Operation{Op: "DEL", Key: doc.rawKey, Value: nil}.payload())
}

// Get returns the document with the given key, or an error wrapping
// ErrNotFound. A document stored under a numeric key by another peer is
// found by the number's decimal form.
func (d *Documents) Get(ctx context.Context, key string) (*Document, error) {
	doc, err := d.get(ctx, key)
	if err != nil {
		return nil, err
	}
	return &doc.Document, nil
}

func (d *Documents) get(ctx context.Context, key string) (*documentWithKey, error) {
	for doc, err := range d.iterate(ctx, 0) {
		if err != nil {
			return nil, err
		}
		if doc.Key == key {
			return &doc, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
}

// Query returns the documents for which match returns true, most recently
// written first.
func (d *Documents) Query(ctx context.Context, match func(doc map[string]any) bool) ([]map[string]any, error) {
	var out []map[string]any
	for doc, err := range d.iterate(ctx, 0) {
		if err != nil {
			return nil, err
		}
		if match(doc.Value) {
			out = append(out, doc.Value)
		}
	}
	return out, nil
}

// Iterator yields the current version of every document, most recently
// written first. amount limits the number of documents; zero or negative
// means all.
func (d *Documents) Iterator(ctx context.Context, amount int) iter.Seq2[Document, error] {
	return func(yield func(Document, error) bool) {
		for doc, err := range d.iterate(ctx, amount) {
			if !yield(doc.Document, err) || err != nil {
				return
			}
		}
	}
}

// All returns every document, least recently written first.
func (d *Documents) All(ctx context.Context) ([]Document, error) {
	return collectReversed(d.Iterator(ctx, 0))
}

// documentWithKey keeps the key as it was stored, which may be a number.
type documentWithKey struct {
	Document
	rawKey any
}

func (d *Documents) iterate(ctx context.Context, amount int) iter.Seq2[documentWithKey, error] {
	return func(yield func(documentWithKey, error) bool) {
		seen := make(map[string]bool)
		count := 0
		for entry, err := range d.log.Iterator(ctx, oplog.IteratorOptions{}) {
			if err != nil {
				yield(documentWithKey{}, err)
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
				value, _ := op.Value.(map[string]any)
				count++
				doc := documentWithKey{Document: Document{Key: key, Value: value, Hash: entry.Hash}, rawKey: op.Key}
				if !yield(doc, nil) {
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

// toDocument converts doc to the map it is stored as.
func toDocument(doc any) (map[string]any, error) {
	if m, ok := doc.(map[string]any); ok {
		return m, nil
	}
	_, data, err := block.Encode(doc)
	if err != nil {
		return nil, err
	}
	v, err := block.Decode(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("a document must encode to a map, got %T", v)
	}
	return m, nil
}

// isFalsy mirrors JavaScript truthiness for the key check in put.
func isFalsy(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case bool:
		return !x
	case int:
		return x == 0
	case int64:
		return x == 0
	case float64:
		return x == 0
	}
	return false
}
