package oplog

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/amirradjou/go-orbitdb/storage"
)

// headsKey is the key the heads list is stored under.
const headsKey = "heads"

// headRef is how a head is persisted: its hash and the hashes it points to.
// The JSON form, [{"hash":...,"next":[...]}], matches @orbitdb/core.
type headRef struct {
	Hash string   `json:"hash"`
	Next []string `json:"next"`
}

func refOf(e *Entry) headRef {
	return headRef{Hash: e.Hash, Next: nonNil(e.Next)}
}

// heads persists the log's current heads.
type heads struct {
	storage storage.Storage
}

func (h *heads) all(ctx context.Context) ([]headRef, error) {
	data, err := h.storage.Get(ctx, headsKey)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var refs []headRef
	if err := json.Unmarshal(data, &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

// set replaces the heads with the heads among refs.
func (h *heads) set(ctx context.Context, refs []headRef) error {
	data, err := json.Marshal(findHeads(refs))
	if err != nil {
		return err
	}
	return h.storage.Put(ctx, headsKey, data)
}

// add adds ref and drops the heads it points to.
func (h *heads) add(ctx context.Context, ref headRef) error {
	current, err := h.all(ctx)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(current, func(r headRef) bool { return r.Hash == ref.Hash }) {
		return nil
	}
	return h.set(ctx, append(current, ref))
}

func (h *heads) remove(ctx context.Context, hash string) error {
	current, err := h.all(ctx)
	if err != nil {
		return err
	}
	return h.set(ctx, slices.DeleteFunc(current, func(r headRef) bool { return r.Hash == hash }))
}

// findHeads returns the refs no other ref points to, in their given order.
func findHeads(refs []headRef) []headRef {
	pointedTo := make(map[string]bool)
	for _, r := range refs {
		for _, n := range r.Next {
			pointedTo[n] = true
		}
	}
	out := make([]headRef, 0, len(refs))
	seen := make(map[string]bool)
	for _, r := range refs {
		if !pointedTo[r.Hash] && !seen[r.Hash] {
			seen[r.Hash] = true
			out = append(out, r)
		}
	}
	return out
}

// FindHeads returns the entries no other entry in entries points to with
// its Next field, in their given order.
func FindHeads(entries []*Entry) []*Entry {
	pointedTo := make(map[string]bool)
	for _, e := range entries {
		for _, n := range e.Next {
			pointedTo[n] = true
		}
	}
	var out []*Entry
	for _, e := range entries {
		if !pointedTo[e.Hash] {
			out = append(out, e)
		}
	}
	return out
}
