// Package accesscontrollers decides who may write to a database.
//
// It mirrors src/access-controllers in @orbitdb/core 4. An access
// controller has an address that goes into the database manifest, so every
// peer that opens the database enforces the same rules:
//
//   - "ipfs": an immutable write list stored as an IPFS block,
//     /ipfs/<hash> of {type: "ipfs", write: [...]}. "*" lets anyone write.
//   - "orbitdb": a mutable list kept in a KeyValue database of its own,
//     whose admins can grant and revoke write access.
package accesscontrollers

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/amirradjou/go-orbitdb/databases"
	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/ipfs"
	"github.com/amirradjou/go-orbitdb/oplog"
	"github.com/amirradjou/go-orbitdb/storage"
)

// AccessController is an oplog.AccessController with an address.
type AccessController interface {
	oplog.AccessController
	// Type is the access controller type, e.g. "ipfs".
	Type() string
	// Address is stored in the database manifest.
	Address() string
}

// Params is what a Factory gets from OrbitDB.
type Params struct {
	// Identity is the local identity, the default sole writer.
	Identity *identitytypes.Identity
	// Identities resolves and verifies writer identities.
	Identities *identities.Identities
	// IPFS stores access controller blocks.
	IPFS *ipfs.Node
	// Address is set when opening an existing database: the access
	// controller address from its manifest.
	Address string
	// Name is the database name when creating a database.
	Name string
	// OpenKeyValue opens a KeyValue database whose writes are controlled
	// by access. The "orbitdb" access controller stores its list in one.
	OpenKeyValue func(ctx context.Context, address string, access Factory) (*databases.KeyValue, error)
}

// Factory creates a new access controller, or loads the one at
// Params.Address.
type Factory func(ctx context.Context, p Params) (AccessController, error)

var (
	mu       sync.RWMutex
	registry = map[string]Factory{
		IPFSType:    IPFS(IPFSOptions{}),
		OrbitDBType: OrbitDB(OrbitDBOptions{}),
	}
)

// UseAccessController registers the factory used to load access controllers
// of type typ from a manifest.
func UseAccessController(typ string, f Factory) error {
	if typ == "" {
		return errors.New("access controller does not contain required field 'type'")
	}
	if f == nil {
		return fmt.Errorf("access controller %q has no factory", typ)
	}
	mu.Lock()
	defer mu.Unlock()
	registry[typ] = f
	return nil
}

// GetAccessController returns the factory registered for typ.
func GetAccessController(typ string) (Factory, error) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := registry[typ]
	if !ok {
		return nil, fmt.Errorf("access controller type %q is not supported", typ)
	}
	return f, nil
}

// TypeOf returns the type part of an access controller address,
// e.g. "ipfs" for "/ipfs/zdpu...".
func TypeOf(address string) string {
	parts := strings.SplitN(address, "/", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// writerAllowed resolves the entry's writer identity and checks that it is
// listed (or the list has "*"), that the key that signed the entry is that
// identity's key, and that the identity itself verifies.
func writerAllowed(ctx context.Context, ids *identities.Identities, entry *oplog.Entry, allowed func(id string) (bool, error)) (bool, error) {
	writer, err := ids.GetIdentity(ctx, entry.Identity)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// The signature is checked against entry.Key, and entry.Identity is not
	// covered by it, so the two must be bound here.
	if writer.PublicKey != entry.Key {
		return false, nil
	}
	ok, err := allowed(writer.ID)
	if err != nil || !ok {
		return false, err
	}
	return ids.VerifyIdentity(ctx, writer)
}

func contains(list []string, id string) bool {
	return slices.Contains(list, id) || slices.Contains(list, "*")
}
