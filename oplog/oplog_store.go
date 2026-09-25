package oplog

import (
	"context"
	"errors"
	"fmt"

	"github.com/orbitdb/go-orbitdb/storage"
)

// oplogStore keeps a log's entries, its index of which entries belong to
// the log, and its heads. It mirrors src/oplog/oplog-store.js.
type oplogStore struct {
	entries    storage.Storage
	index      storage.Storage
	heads      *heads
	encryption Encryption
}

func (s *oplogStore) get(ctx context.Context, hash string) (*Entry, error) {
	data, err := s.entries.Get(ctx, hash)
	if err != nil {
		return nil, err
	}
	entry, err := DecodeEntry(ctx, data, s.encryption)
	if err != nil {
		return nil, err
	}
	if entry.Hash != hash {
		return nil, fmt.Errorf("oplog: storage returned %s for %s", entry.Hash, hash)
	}
	return entry, nil
}

func (s *oplogStore) has(ctx context.Context, hash string) (bool, error) {
	_, err := s.index.Get(ctx, hash)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *oplogStore) currentHeads(ctx context.Context) ([]*Entry, error) {
	refs, err := s.heads.all(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Entry, 0, len(refs))
	for _, r := range refs {
		e, err := s.get(ctx, r.Hash)
		if err != nil {
			return nil, fmt.Errorf("oplog: head %s: %w", r.Hash, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// put stores entry's block and sets entry.Hash. An entry that was decoded
// (or stored before) is written with its original bytes, so it keeps its
// hash; a new entry is encoded.
func (s *oplogStore) put(ctx context.Context, entry *Entry) error {
	hash, data := entry.Hash, entry.block
	if hash == "" || data == nil {
		var err error
		if hash, data, err = EncodeEntry(ctx, entry, s.encryption); err != nil {
			return err
		}
	}
	if err := s.entries.Put(ctx, hash, data); err != nil {
		return err
	}
	entry.Hash, entry.block = hash, data
	return nil
}

// setHead stores and indexes an appended entry and makes it the only head.
func (s *oplogStore) setHead(ctx context.Context, entry *Entry) error {
	if err := s.put(ctx, entry); err != nil {
		return err
	}
	if err := s.index.Put(ctx, entry.Hash, []byte{1}); err != nil {
		return err
	}
	return s.heads.set(ctx, []headRef{refOf(entry)})
}

// addHead stores a joined entry and adds it to the heads.
func (s *oplogStore) addHead(ctx context.Context, entry *Entry) error {
	if err := s.put(ctx, entry); err != nil {
		return err
	}
	return s.heads.add(ctx, refOf(entry))
}

func (s *oplogStore) removeHeads(ctx context.Context, hashes []string) error {
	for _, h := range hashes {
		if err := s.heads.remove(ctx, h); err != nil {
			return err
		}
	}
	return nil
}

// addVerified indexes verified entries and persists (pins) them.
func (s *oplogStore) addVerified(ctx context.Context, hashes []string) error {
	persister, _ := s.entries.(storage.Persister)
	for _, h := range hashes {
		if err := s.index.Put(ctx, h, []byte{1}); err != nil {
			return err
		}
		if persister != nil {
			if err := persister.Persist(ctx, h); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *oplogStore) clear(ctx context.Context) error {
	return errors.Join(s.index.Clear(ctx), s.heads.storage.Clear(ctx), s.entries.Clear(ctx))
}

func (s *oplogStore) close() error {
	return errors.Join(s.index.Close(), s.heads.storage.Close(), s.entries.Close())
}
