package accesscontrollers

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"

	"github.com/amirradjou/go-orbitdb/databases"
	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/oplog"
)

// OrbitDBType is the type of OrbitDB access controllers.
const OrbitDBType = "orbitdb"

// Capabilities of an OrbitDB access controller.
const (
	CapabilityWrite = "write"
	CapabilityAdmin = "admin"
)

// OrbitDBOptions configures OrbitDB.
type OrbitDBOptions struct {
	// Write lists the identity ids that administer the list; they may also
	// write. Defaults to the local identity.
	Write []string
}

// OrbitDBAccessController keeps capabilities (lists of identity ids per
// capability) in a KeyValue database, so they can change over time. Grants
// and revocations are writes to that database, so only its writers (the
// Write list it was created with) can make them.
type OrbitDBAccessController struct {
	db         *databases.KeyValue
	write      []string
	identities *identities.Identities
}

// OrbitDB returns a factory for OrbitDB access controllers.
func OrbitDB(opts OrbitDBOptions) Factory {
	return func(ctx context.Context, p Params) (AccessController, error) {
		if p.Identities == nil {
			return nil, errors.New("accesscontrollers: identities are required")
		}
		if p.OpenKeyValue == nil {
			return nil, errors.New("accesscontrollers: the orbitdb access controller needs OrbitDB to open its database")
		}
		address := p.Address
		if address == "" {
			address = p.Name
		}
		if address == "" {
			address = createID(64)
		}
		write := opts.Write
		if write == nil {
			if p.Identity == nil {
				return nil, errors.New("accesscontrollers: a write list or an identity is required")
			}
			write = []string{p.Identity.ID}
		}
		db, err := p.OpenKeyValue(ctx, address, IPFS(IPFSOptions{Write: write}))
		if err != nil {
			return nil, err
		}
		return &OrbitDBAccessController{db: db, write: write, identities: p.Identities}, nil
	}
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

// Type implements AccessController.
func (*OrbitDBAccessController) Type() string { return OrbitDBType }

// Address implements AccessController. It is the address of the
// capabilities database.
func (a *OrbitDBAccessController) Address() string { return a.db.Address() }

// Database returns the KeyValue database holding the capabilities.
func (a *OrbitDBAccessController) Database() *databases.KeyValue { return a.db }

// Events returns the event emitter of the capabilities database.
func (a *OrbitDBAccessController) Events() *databases.Emitter { return a.db.Events() }

// CanAppend implements oplog.AccessController: writers and admins may write.
func (a *OrbitDBAccessController) CanAppend(ctx context.Context, entry *oplog.Entry) (bool, error) {
	return writerAllowed(ctx, a.identities, entry, func(id string) (bool, error) {
		for _, c := range []string{CapabilityWrite, CapabilityAdmin} {
			ok, err := a.HasCapability(ctx, c, id)
			if err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	})
}

// Capabilities returns every capability and the ids that have it. The
// writers of the capabilities database are always admins.
func (a *OrbitDBAccessController) Capabilities(ctx context.Context) (map[string][]string, error) {
	caps := make(map[string][]string)
	for kv, err := range a.db.Iterator(ctx, 0) {
		if err != nil {
			return nil, err
		}
		caps[kv.Key] = toStrings(kv.Value)
	}
	admins := caps[CapabilityAdmin]
	if ac, ok := a.db.AccessController().(*IPFSAccessController); ok {
		admins = append(admins, ac.Write()...)
	}
	caps[CapabilityAdmin] = admins
	for k, ids := range caps {
		caps[k] = dedupe(ids)
	}
	return caps, nil
}

// Get returns the ids with capability.
func (a *OrbitDBAccessController) Get(ctx context.Context, capability string) ([]string, error) {
	caps, err := a.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	return caps[capability], nil
}

// HasCapability reports whether id (or "*") has capability.
func (a *OrbitDBAccessController) HasCapability(ctx context.Context, capability, id string) (bool, error) {
	ids, err := a.Get(ctx, capability)
	if err != nil {
		return false, err
	}
	return contains(ids, id), nil
}

// Grant gives id capability.
func (a *OrbitDBAccessController) Grant(ctx context.Context, capability, id string) error {
	current, err := a.stored(ctx, capability)
	if err != nil {
		return err
	}
	_, err = a.db.Put(ctx, capability, toAny(dedupe(append(current, id))))
	return err
}

// Revoke removes capability from id.
func (a *OrbitDBAccessController) Revoke(ctx context.Context, capability, id string) error {
	current, err := a.stored(ctx, capability)
	if err != nil {
		return err
	}
	remaining := slices.DeleteFunc(current, func(s string) bool { return s == id })
	if len(remaining) > 0 {
		_, err = a.db.Put(ctx, capability, toAny(remaining))
	} else {
		_, err = a.db.Del(ctx, capability)
	}
	return err
}

func (a *OrbitDBAccessController) stored(ctx context.Context, capability string) ([]string, error) {
	v, err := a.db.Get(ctx, capability)
	if errors.Is(err, databases.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toStrings(v), nil
}

// Close closes the capabilities database.
func (a *OrbitDBAccessController) Close() error { return a.db.Close() }

// Drop drops the capabilities database.
func (a *OrbitDBAccessController) Drop(ctx context.Context) error { return a.db.Drop(ctx) }

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toAny(ids []string) []any {
	out := make([]any, len(ids))
	for i, s := range ids {
		out[i] = s
	}
	return out
}

func dedupe(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
