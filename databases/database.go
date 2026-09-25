// Package databases implements the OrbitDB database types on top of the
// operation log: Events (an append-only event log), KeyValue,
// KeyValueIndexed and Documents.
//
// It mirrors src/database.js and src/databases in @orbitdb/core 4.
// Operations are stored as the same {op, key, value} payloads, so a
// database written by one implementation reads the same in the other.
package databases

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/ipfs"
	"github.com/amirradjou/go-orbitdb/oplog"
	"github.com/amirradjou/go-orbitdb/storage"
	"github.com/amirradjou/go-orbitdb/syncutils"
)

const (
	// DefaultReferencesCount is how many older entries each new entry
	// refers to, beyond the heads.
	DefaultReferencesCount = 16
	// DefaultDirectory is where databases keep their files.
	DefaultDirectory = "./orbitdb"

	cacheSize = 1000
)

// ErrNotFound is returned when a key, document or event does not exist.
var ErrNotFound = errors.New("databases: not found")

// Params configures a database. OrbitDB.Open fills it; it is exported for
// custom database types and for using a database without OrbitDB.
type Params struct {
	// IPFS provides block storage and networking. Required unless every
	// storage is given and sync is disabled.
	IPFS *ipfs.Node
	// Identity writes to the database. Required.
	Identity *identitytypes.Identity
	// Address is the database address; it is also the log id and the sync
	// topic. Required.
	Address string
	Name    string
	// AccessController decides who may write. Defaults to anyone.
	AccessController oplog.AccessController
	// Directory holds the database files, under Directory/<address>.
	// Defaults to DefaultDirectory.
	Directory string
	// Meta is the manifest metadata.
	Meta any
	// EntryStorage defaults to an LRU cache over IPFS block storage;
	// HeadsStorage and IndexStorage to an LRU cache over LevelDB in
	// Directory.
	HeadsStorage storage.Storage
	EntryStorage storage.Storage
	IndexStorage storage.Storage
	// ReferencesCount is passed to Log.Append. Zero means
	// DefaultReferencesCount; negative means no references.
	ReferencesCount int
	// DisableAutoSync leaves sync stopped until Sync().Start() is called.
	DisableAutoSync bool
	// OnUpdate is called, before EventUpdate is emitted, for every entry
	// appended or joined.
	OnUpdate func(ctx context.Context, log *oplog.Log, entry *oplog.Entry) error
	// OnClose is called once the database has closed.
	OnClose func()
	// Encryption turns on entry and/or payload encryption.
	Encryption oplog.Encryption
}

// Database is the base every database type builds on: an operation log, the
// sync protocol replicating it and an event stream.
type Database struct {
	address  string
	name     string
	identity *identitytypes.Identity
	meta     any
	log      *oplog.Log
	sync     *syncutils.Sync
	events   *Emitter
	access   oplog.AccessController

	referencesCount int
	onUpdate        func(context.Context, *oplog.Log, *oplog.Entry) error
	onClose         func()

	// mu serialises operations, like the p-queue of @orbitdb/core.
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// New opens the base database. Database types call it and add their
// operations on top.
func New(ctx context.Context, p Params) (*Database, error) {
	if p.Identity == nil {
		return nil, errors.New("databases: an identity is required")
	}
	if p.Address == "" {
		return nil, errors.New("databases: an address is required")
	}
	dir := p.Directory
	if dir == "" {
		dir = DefaultDirectory
	}
	dir = filepath.Join(dir, filepath.FromSlash(p.Address))

	refs := p.ReferencesCount
	switch {
	case refs == 0:
		refs = DefaultReferencesCount
	case refs < 0:
		refs = 0
	}

	var err error
	entries := p.EntryStorage
	if entries == nil {
		if p.IPFS == nil {
			return nil, errors.New("databases: IPFS is required for the default entry storage")
		}
		if entries, err = cachedIPFS(p.IPFS); err != nil {
			return nil, err
		}
	}
	heads := p.HeadsStorage
	if heads == nil {
		if heads, err = cachedLevel(filepath.Join(dir, "log", "_heads")); err != nil {
			return nil, err
		}
	}
	index := p.IndexStorage
	if index == nil {
		if index, err = cachedLevel(filepath.Join(dir, "log", "_index")); err != nil {
			_ = heads.Close()
			return nil, err
		}
	}

	log, err := oplog.NewLog(ctx, p.Identity, oplog.Options{
		LogID:            p.Address,
		AccessController: p.AccessController,
		EntryStorage:     entries,
		HeadsStorage:     heads,
		IndexStorage:     index,
		Encryption:       p.Encryption,
	})
	if err != nil {
		return nil, err
	}

	db := &Database{
		address:         p.Address,
		name:            p.Name,
		identity:        p.Identity,
		meta:            p.Meta,
		log:             log,
		events:          newEmitter(),
		access:          p.AccessController,
		referencesCount: refs,
		onUpdate:        p.OnUpdate,
		onClose:         p.OnClose,
	}
	if p.IPFS == nil {
		if !p.DisableAutoSync {
			_ = log.Close()
			return nil, errors.New("databases: IPFS is required to sync")
		}
		return db, nil
	}
	db.sync, err = syncutils.New(syncutils.Options{
		Host:     p.IPFS.Host,
		PubSub:   p.IPFS.PubSub,
		Log:      log,
		OnSynced: db.applyOperation,
		OnJoin: func(id peer.ID, heads []*oplog.Entry) {
			db.events.emit(Event{Type: EventJoin, Peer: id, Heads: heads})
		},
		OnLeave: func(id peer.ID) {
			db.events.emit(Event{Type: EventLeave, Peer: id})
		},
		OnError: func(err error) {
			db.events.emit(Event{Type: EventError, Err: err})
		},
		DisableAutoStart: p.DisableAutoSync,
	})
	if err != nil {
		_ = log.Close()
		return nil, err
	}
	return db, nil
}

func cachedIPFS(node *ipfs.Node) (storage.Storage, error) {
	blocks, err := storage.NewIPFSBlockStorage(node.Blocks, storage.IPFSBlockStorageOptions{Pinner: node.Pins})
	if err != nil {
		return nil, err
	}
	return cached(blocks)
}

func cachedLevel(path string) (storage.Storage, error) {
	level, err := storage.NewLevelStorage(path)
	if err != nil {
		return nil, err
	}
	return cached(level)
}

func cached(s storage.Storage) (storage.Storage, error) {
	lru, err := storage.NewLRUStorage(cacheSize)
	if err != nil {
		return nil, err
	}
	return storage.NewComposedStorage(lru, s), nil
}

// Address returns the database address.
func (db *Database) Address() string { return db.address }

// Name returns the database name.
func (db *Database) Name() string { return db.name }

// Identity returns the identity the database writes as.
func (db *Database) Identity() *identitytypes.Identity { return db.identity }

// Meta returns the manifest metadata.
func (db *Database) Meta() any { return db.meta }

// Log returns the operation log.
func (db *Database) Log() *oplog.Log { return db.log }

// Sync returns the sync protocol instance, or nil if the database has no
// IPFS node.
func (db *Database) Sync() *syncutils.Sync { return db.sync }

// Peers returns the peers currently replicating the database.
func (db *Database) Peers() []peer.ID {
	if db.sync == nil {
		return nil
	}
	return db.sync.Peers()
}

// Events returns the database's event emitter.
func (db *Database) Events() *Emitter { return db.events }

// AccessController returns the access controller.
func (db *Database) AccessController() oplog.AccessController { return db.access }

// AddOperation appends op to the log, announces it to peers and emits
// EventUpdate. It returns the new entry's hash.
func (db *Database) AddOperation(ctx context.Context, op any) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	entry, err := db.log.Append(ctx, op, oplog.AppendOptions{ReferencesCount: db.referencesCount})
	if err != nil {
		return "", err
	}
	if db.sync != nil {
		if err := db.sync.Add(ctx, entry); err != nil {
			// The entry is stored; peers will still get it at the next
			// heads exchange.
			db.events.emit(Event{Type: EventError, Err: fmt.Errorf("announce %s: %w", entry.Hash, err)})
		}
	}
	if db.onUpdate != nil {
		if err := db.onUpdate(ctx, db.log, entry); err != nil {
			return "", err
		}
	}
	db.events.emit(Event{Type: EventUpdate, Entry: entry})
	return entry.Hash, nil
}

// applyOperation joins an entry received from a peer.
func (db *Database) applyOperation(ctx context.Context, entry *oplog.Entry) {
	db.mu.Lock()
	defer db.mu.Unlock()
	updated, err := db.log.JoinEntry(ctx, entry)
	if err != nil {
		db.events.emit(Event{Type: EventError, Err: err})
		return
	}
	if !updated {
		return
	}
	if db.onUpdate != nil {
		if err := db.onUpdate(ctx, db.log, entry); err != nil {
			db.events.emit(Event{Type: EventError, Err: err})
			return
		}
	}
	db.events.emit(Event{Type: EventUpdate, Entry: entry})
}

// Close stops syncing, closes the log and its storages and emits
// EventClose. Closing twice is a no-op.
func (db *Database) Close() error {
	db.closeOnce.Do(func() {
		var errs []error
		if db.sync != nil {
			errs = append(errs, db.sync.Stop())
		}
		db.mu.Lock()
		errs = append(errs, db.log.Close())
		if c, ok := db.access.(interface{ Close() error }); ok {
			errs = append(errs, c.Close())
		}
		db.mu.Unlock()
		db.closeErr = errors.Join(errs...)
		db.events.emit(Event{Type: EventClose})
		db.events.close()
		if db.onClose != nil {
			db.onClose()
		}
	})
	return db.closeErr
}

// Drop removes every entry of the database (locally) and emits EventDrop.
func (db *Database) Drop(ctx context.Context) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := db.log.Clear(ctx); err != nil {
		return err
	}
	if d, ok := db.access.(interface{ Drop(context.Context) error }); ok {
		if err := d.Drop(ctx); err != nil {
			return err
		}
	}
	db.events.emit(Event{Type: EventDrop})
	return nil
}
