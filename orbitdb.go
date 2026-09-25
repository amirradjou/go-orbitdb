// Package orbitdb is a Go implementation of OrbitDB, a serverless,
// peer-to-peer database built on IPFS and libp2p.
//
// It is a port of @orbitdb/core 4 and interoperates with it: identities,
// log entries, manifests, access controllers and the sync protocol are
// byte-compatible, so Go and JavaScript peers can open and replicate the
// same databases.
//
//	node, _ := ipfs.New(ctx, ipfs.Options{})
//	odb, _ := orbitdb.New(ctx, orbitdb.Options{IPFS: node})
//	defer odb.Stop()
//
//	kv, _ := odb.OpenKeyValue(ctx, "settings")
//	kv.Put(ctx, "theme", "dark")
//	fmt.Println(kv.Address()) // share this with peers
//
// A peer that opens the same address replicates the database.
package orbitdb

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/amirradjou/go-orbitdb/accesscontrollers"
	"github.com/amirradjou/go-orbitdb/databases"
	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/identities/providers"
	"github.com/amirradjou/go-orbitdb/ipfs"
	"github.com/amirradjou/go-orbitdb/keystore"
	"github.com/amirradjou/go-orbitdb/oplog"
	"github.com/amirradjou/go-orbitdb/storage"
)

// DefaultDatabaseType is the type Open creates when none is given.
const DefaultDatabaseType = databases.EventsType

// Options configures New.
type Options struct {
	// IPFS is the node databases store blocks on and sync over. Required.
	IPFS *ipfs.Node
	// ID is the id the identity is created for. Defaults to a random id.
	ID string
	// Identity is used as is instead of creating one. It must have been
	// created by Identities (so its key is in the keystore).
	Identity *identitytypes.Identity
	// IdentityProvider creates the identity instead of the default
	// publickey provider.
	IdentityProvider providers.Provider
	// Identities is used instead of creating one over a keystore in
	// Directory/keystore.
	Identities *identities.Identities
	// Directory holds the keystore and the databases' local state.
	// Defaults to "./orbitdb".
	Directory string
}

// OrbitDB opens and manages databases.
type OrbitDB struct {
	id         string
	ipfs       *ipfs.Node
	directory  string
	keystore   *keystore.KeyStore
	identities *identities.Identities
	identity   *identitytypes.Identity
	manifests  *manifestStore

	mu      sync.Mutex
	dbs     map[string]databases.Store
	opening map[string]*sync.Mutex
}

// New creates an OrbitDB instance.
func New(ctx context.Context, opts Options) (*OrbitDB, error) {
	if opts.IPFS == nil {
		return nil, errors.New("IPFS instance is a required argument")
	}
	id := opts.ID
	if id == "" {
		id = createID(32)
	}
	dir := opts.Directory
	if dir == "" {
		dir = databases.DefaultDirectory
	}

	blocks, err := storage.NewIPFSBlockStorage(opts.IPFS.Blocks, storage.IPFSBlockStorageOptions{Pinner: opts.IPFS.Pins})
	if err != nil {
		return nil, err
	}

	ids := opts.Identities
	var ks *keystore.KeyStore
	if ids != nil {
		ks = ids.Keystore()
	} else {
		if ks, err = keystore.New(keystore.Options{Path: filepath.Join(dir, "keystore")}); err != nil {
			return nil, err
		}
		identityStorage, err := lruOver(blocks, 1000)
		if err != nil {
			return nil, err
		}
		if ids, err = identities.New(identities.Options{Keystore: ks, Storage: identityStorage}); err != nil {
			return nil, err
		}
	}

	identity := opts.Identity
	if identity == nil {
		identity, err = ids.CreateIdentity(ctx, identities.CreateOptions{ID: id, Provider: opts.IdentityProvider})
		if err != nil {
			return nil, fmt.Errorf("create identity: %w", err)
		}
	}

	manifestStorage, err := lruOver(blocks, 100000)
	if err != nil {
		return nil, err
	}
	return &OrbitDB{
		id:         id,
		ipfs:       opts.IPFS,
		directory:  dir,
		keystore:   ks,
		identities: ids,
		identity:   identity,
		manifests:  &manifestStore{storage: manifestStorage},
		dbs:        make(map[string]databases.Store),
		opening:    make(map[string]*sync.Mutex),
	}, nil
}

func lruOver(s storage.Storage, size int) (storage.Storage, error) {
	lru, err := storage.NewLRUStorage(size)
	if err != nil {
		return nil, err
	}
	return storage.NewComposedStorage(lru, s), nil
}

// createID returns a random alphanumeric id, like utils/create-id.js.
func createID(n int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// ID returns the id the identity was created for.
func (o *OrbitDB) ID() string { return o.id }

// Identity returns the identity databases are written as.
func (o *OrbitDB) Identity() *identitytypes.Identity { return o.identity }

// Identities returns the identities manager.
func (o *OrbitDB) Identities() *identities.Identities { return o.identities }

// Keystore returns the keystore.
func (o *OrbitDB) Keystore() *keystore.KeyStore { return o.keystore }

// IPFS returns the IPFS node.
func (o *OrbitDB) IPFS() *ipfs.Node { return o.ipfs }

// PeerID returns the libp2p peer id of the node.
func (o *OrbitDB) PeerID() peer.ID { return o.ipfs.Host.ID() }

// Directory returns the directory local state is kept in.
func (o *OrbitDB) Directory() string { return o.directory }

// OpenOption configures Open.
type OpenOption func(*openConfig)

type openConfig struct {
	typ              string
	meta             any
	sync             bool
	database         databases.Factory
	accessController accesscontrollers.Factory
	headsStorage     storage.Storage
	entryStorage     storage.Storage
	indexStorage     storage.Storage
	referencesCount  int
	encryption       oplog.Encryption
}

// WithType sets the database type ("events", "keyvalue", "documents" or a
// registered custom type). It applies when creating a database; an
// existing database keeps the type in its manifest unless this is set.
func WithType(typ string) OpenOption { return func(c *openConfig) { c.typ = typ } }

// WithMeta sets the manifest metadata of a new database.
func WithMeta(meta any) OpenOption { return func(c *openConfig) { c.meta = meta } }

// WithSync turns automatic syncing on (the default) or off.
func WithSync(enabled bool) OpenOption { return func(c *openConfig) { c.sync = enabled } }

// WithDatabase opens the database with factory instead of the one
// registered for its type, e.g. databases.KeyValueIndexedFactory.
func WithDatabase(factory databases.Factory) OpenOption {
	return func(c *openConfig) { c.database = factory }
}

// WithAccessController sets the access controller of a new database.
// Defaults to accesscontrollers.IPFS with the local identity as sole
// writer. An existing database uses the controller in its manifest.
func WithAccessController(factory accesscontrollers.Factory) OpenOption {
	return func(c *openConfig) { c.accessController = factory }
}

// WithHeadsStorage, WithEntryStorage and WithIndexStorage replace the
// database's default storages.
func WithHeadsStorage(s storage.Storage) OpenOption {
	return func(c *openConfig) { c.headsStorage = s }
}

// WithEntryStorage replaces the default entry storage.
func WithEntryStorage(s storage.Storage) OpenOption {
	return func(c *openConfig) { c.entryStorage = s }
}

// WithIndexStorage replaces the default index storage.
func WithIndexStorage(s storage.Storage) OpenOption {
	return func(c *openConfig) { c.indexStorage = s }
}

// WithReferencesCount sets how many older entries each new entry refers
// to; see databases.Params.ReferencesCount.
func WithReferencesCount(n int) OpenOption {
	return func(c *openConfig) { c.referencesCount = n }
}

// WithEncryption encrypts entries and/or payloads. Every peer must use the
// same encryption to read the database.
func WithEncryption(e oplog.Encryption) OpenOption {
	return func(c *openConfig) { c.encryption = e }
}

// Open opens the database at address, or creates a database named address
// if it is not an OrbitDB address. Opening an open database returns the
// same instance.
func (o *OrbitDB) Open(ctx context.Context, address string, opts ...OpenOption) (databases.Store, error) {
	cfg := openConfig{sync: true}
	for _, opt := range opts {
		opt(&cfg)
	}
	if db := o.cached(address); db != nil {
		return db, nil
	}

	var (
		name     string
		meta     any
		typ      = cfg.typ
		acParams = accesscontrollers.Params{
			Identity:     o.identity,
			Identities:   o.identities,
			IPFS:         o.ipfs,
			OpenKeyValue: o.openKeyValue,
		}
		access accesscontrollers.AccessController
		err    error
	)
	if IsValidAddress(address) {
		addr, err := ParseAddress(address)
		if err != nil {
			return nil, err
		}
		manifest, err := o.manifests.get(ctx, addr.Hash)
		if err != nil {
			return nil, err
		}
		factory, err := accesscontrollers.GetAccessController(accesscontrollers.TypeOf(manifest.AccessController))
		if err != nil {
			return nil, err
		}
		acParams.Address = manifest.AccessController
		if access, err = factory(ctx, acParams); err != nil {
			return nil, fmt.Errorf("load access controller: %w", err)
		}
		name, meta, address = manifest.Name, manifest.Meta, addr.String()
		if typ == "" {
			typ = manifest.Type
		}
	} else {
		if typ == "" {
			typ = DefaultDatabaseType
		}
		factory := cfg.accessController
		if factory == nil {
			factory = accesscontrollers.IPFS(accesscontrollers.IPFSOptions{})
		}
		acParams.Name = address
		if access, err = factory(ctx, acParams); err != nil {
			return nil, fmt.Errorf("create access controller: %w", err)
		}
		hash, err := o.manifests.create(ctx, Manifest{Name: address, Type: typ, AccessController: access.Address(), Meta: cfg.meta})
		if err != nil {
			return nil, err
		}
		name, meta, address = address, cfg.meta, Address{Hash: hash}.String()
	}

	lock := o.lockAddress(address)
	lock.Lock()
	defer lock.Unlock()
	if db := o.cached(address); db != nil {
		return db, nil
	}

	factory := cfg.database
	if factory == nil {
		if factory, err = databases.GetDatabaseType(typ); err != nil {
			return nil, err
		}
	}
	db, err := factory(ctx, databases.Params{
		IPFS:             o.ipfs,
		Identity:         o.identity,
		Address:          address,
		Name:             name,
		AccessController: access,
		Directory:        o.directory,
		Meta:             meta,
		HeadsStorage:     cfg.headsStorage,
		EntryStorage:     cfg.entryStorage,
		IndexStorage:     cfg.indexStorage,
		ReferencesCount:  cfg.referencesCount,
		DisableAutoSync:  !cfg.sync,
		Encryption:       cfg.encryption,
		OnClose:          func() { o.forget(address) },
	})
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.dbs[address] = db
	o.mu.Unlock()
	return db, nil
}

func (o *OrbitDB) cached(address string) databases.Store {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.dbs[address]
}

func (o *OrbitDB) forget(address string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.dbs, address)
}

func (o *OrbitDB) lockAddress(address string) *sync.Mutex {
	o.mu.Lock()
	defer o.mu.Unlock()
	l, ok := o.opening[address]
	if !ok {
		l = new(sync.Mutex)
		o.opening[address] = l
	}
	return l
}

func (o *OrbitDB) openKeyValue(ctx context.Context, address string, access accesscontrollers.Factory) (*databases.KeyValue, error) {
	return OpenAs[*databases.KeyValue](ctx, o, address, WithType(databases.KeyValueType), WithAccessController(access))
}

// OpenAs opens a database and returns it as type T, e.g.
// OpenAs[*databases.KeyValue].
func OpenAs[T databases.Store](ctx context.Context, o *OrbitDB, address string, opts ...OpenOption) (T, error) {
	var zero T
	store, err := o.Open(ctx, address, opts...)
	if err != nil {
		return zero, err
	}
	db, ok := store.(T)
	if !ok {
		return zero, fmt.Errorf("database %s is a %T (type %q), not a %T", store.Address(), store, store.Type(), zero)
	}
	return db, nil
}

// OpenEvents opens or creates an events database.
func (o *OrbitDB) OpenEvents(ctx context.Context, address string, opts ...OpenOption) (*databases.Events, error) {
	return OpenAs[*databases.Events](ctx, o, address, append([]OpenOption{WithType(databases.EventsType)}, opts...)...)
}

// OpenKeyValue opens or creates a keyvalue database.
func (o *OrbitDB) OpenKeyValue(ctx context.Context, address string, opts ...OpenOption) (*databases.KeyValue, error) {
	return OpenAs[*databases.KeyValue](ctx, o, address, append([]OpenOption{WithType(databases.KeyValueType)}, opts...)...)
}

// OpenKeyValueIndexed opens or creates a keyvalue database with a local
// index.
func (o *OrbitDB) OpenKeyValueIndexed(ctx context.Context, address string, opts ...OpenOption) (*databases.KeyValueIndexed, error) {
	return OpenAs[*databases.KeyValueIndexed](ctx, o, address,
		append([]OpenOption{WithType(databases.KeyValueType), WithDatabase(databases.KeyValueIndexedFactory)}, opts...)...)
}

// OpenDocuments opens or creates a documents database. To index documents by
// a field other than "_id", pass
// WithDatabase(databases.DocumentsFactory(databases.DocumentsOptions{IndexBy: field})).
func (o *OrbitDB) OpenDocuments(ctx context.Context, address string, opts ...OpenOption) (*databases.Documents, error) {
	return OpenAs[*databases.Documents](ctx, o, address, append([]OpenOption{WithType(databases.DocumentsType)}, opts...)...)
}

// Stop closes every open database, the keystore and the manifest store.
// It does not close the IPFS node.
func (o *OrbitDB) Stop() error {
	o.mu.Lock()
	open := make([]databases.Store, 0, len(o.dbs))
	for _, db := range o.dbs {
		open = append(open, db)
	}
	o.mu.Unlock()

	var errs []error
	for _, db := range open {
		errs = append(errs, db.Close())
	}
	if o.keystore != nil {
		errs = append(errs, o.keystore.Close())
	}
	errs = append(errs, o.manifests.close())
	return errors.Join(errs...)
}
