package orbitdb_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	orbitdb "github.com/amirradjou/go-orbitdb"
	"github.com/amirradjou/go-orbitdb/accesscontrollers"
	"github.com/amirradjou/go-orbitdb/databases"
	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/internal/testutil"
	"github.com/amirradjou/go-orbitdb/ipfs"
	"github.com/amirradjou/go-orbitdb/oplog"
)

func newOrbitDB(t *testing.T, id string) *orbitdb.OrbitDB {
	t.Helper()
	ctx := context.Background()
	node, err := ipfs.New(ctx, ipfs.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	odb, err := orbitdb.New(ctx, orbitdb.Options{IPFS: node, ID: id, Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = odb.Stop() })
	return odb
}

func connect(t *testing.T, a, b *orbitdb.OrbitDB) {
	t.Helper()
	require.NoError(t, b.IPFS().Connect(context.Background(), a.IPFS().AddrInfo()))
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 30*time.Second, 50*time.Millisecond)
}

func TestAddressVectors(t *testing.T) {
	for _, v := range testutil.JSVectors(t).Addresses {
		require.Equal(t, v.Valid, orbitdb.IsValidAddress(v.Address), v.Address)
		addr, err := orbitdb.ParseAddress(v.Address)
		if !v.Valid {
			require.Error(t, err, v.Address)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, *v.String, addr.String(), v.Address)
	}
}

func TestOpenCreatesJavaScriptCompatibleManifest(t *testing.T) {
	ctx := context.Background()
	odb := newOrbitDB(t, "userA")
	// Recreate the JS vector: the manifest of a keyvalue database "mydb"
	// whose access controller lets only userA write. userA's identity id
	// comes from the key the JS fixture has for "userA".
	ids, err := identities.New(identities.Options{Keystore: testutil.Keystore(t)})
	require.NoError(t, err)
	userA, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "userA"})
	require.NoError(t, err)

	var want testutil.ManifestVector
	for _, m := range testutil.JSVectors(t).Manifests {
		if m.Name == "mydb" && len(m.Write) == 1 && m.Write[0] == userA.ID {
			want = m
		}
	}
	require.NotEmpty(t, want.Address)

	db, err := odb.OpenKeyValue(ctx, "mydb", orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{userA.ID}})))
	require.NoError(t, err)
	require.Equal(t, want.Address, db.Address(), "Go derives the same address as JS for the same manifest")
	require.Equal(t, "mydb", db.Name())

	for _, m := range testutil.JSVectors(t).Manifests {
		if m.Meta == nil {
			continue
		}
		db, err := odb.OpenDocuments(ctx, m.Name, orbitdb.WithMeta(m.Meta), orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: m.Write})))
		require.NoError(t, err)
		require.Equal(t, m.Address, db.Address(), "manifest with meta %v", m.Meta)
		require.NoError(t, db.Close())
	}
}

func TestOpen(t *testing.T) {
	ctx := context.Background()
	odb := newOrbitDB(t, "alice")
	require.Equal(t, "alice", odb.ID())
	require.NotEmpty(t, odb.PeerID())

	store, err := odb.Open(ctx, "log")
	require.NoError(t, err)
	require.Equal(t, databases.EventsType, store.Type(), "events is the default type")
	require.True(t, orbitdb.IsValidAddress(store.Address()))

	again, err := odb.Open(ctx, "log")
	require.NoError(t, err)
	require.Same(t, store, again, "opening an open database by name returns it")
	byAddress, err := odb.Open(ctx, store.Address())
	require.NoError(t, err)
	require.Same(t, store, byAddress)

	events := store.(*databases.Events)
	_, err = events.Add(ctx, "hello")
	require.NoError(t, err)
	require.NoError(t, store.Close())

	reopened, err := odb.OpenEvents(ctx, store.Address())
	require.NoError(t, err)
	require.NotSame(t, store, reopened, "a closed database is opened afresh")
	all, err := reopened.All(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)

	_, err = orbitdb.OpenAs[*databases.KeyValue](ctx, odb, reopened.Address())
	require.ErrorContains(t, err, "not a *databases.KeyValue")
	_, err = odb.Open(ctx, "x", orbitdb.WithType("nope"))
	require.ErrorContains(t, err, "unsupported database type")

	meta := map[string]any{"description": "with meta"}
	withMeta, err := odb.OpenKeyValue(ctx, "meta", orbitdb.WithMeta(meta))
	require.NoError(t, err)
	require.Equal(t, meta, withMeta.Meta())

	indexed, err := odb.OpenKeyValueIndexed(ctx, "indexed")
	require.NoError(t, err)
	_, err = indexed.Put(ctx, "k", "v")
	require.NoError(t, err)
	v, err := indexed.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, "v", v)

	_, err = orbitdb.New(ctx, orbitdb.Options{})
	require.Error(t, err)
}

func TestReplicateKeyValue(t *testing.T) {
	ctx := context.Background()
	a, b := newOrbitDB(t, "a"), newOrbitDB(t, "b")
	connect(t, a, b)

	dbA, err := a.OpenKeyValue(ctx, "shared", orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{"*"}})))
	require.NoError(t, err)
	for i := range 20 {
		_, err := dbA.Put(ctx, fmt.Sprint("key", i), i)
		require.NoError(t, err)
	}

	// b knows only the address: the manifest, access controller, heads,
	// ancestors and a's identity all come over the network.
	dbB, err := b.OpenKeyValue(ctx, dbA.Address())
	require.NoError(t, err)
	require.Equal(t, "shared", dbB.Name())
	waitFor(t, func() bool {
		all, err := dbB.All(ctx)
		return err == nil && len(all) == 20
	})

	_, err = dbB.Put(ctx, "from-b", "hi")
	require.NoError(t, err)
	waitFor(t, func() bool {
		v, err := dbA.Get(ctx, "from-b")
		return err == nil && v == "hi"
	})
}

func TestWriteAccessIsEnforcedAcrossPeers(t *testing.T) {
	ctx := context.Background()
	a, b := newOrbitDB(t, "a"), newOrbitDB(t, "b")
	connect(t, a, b)

	dbA, err := a.OpenEvents(ctx, "a-only")
	require.NoError(t, err)
	_, err = dbA.Add(ctx, "from a")
	require.NoError(t, err)

	dbB, err := b.OpenEvents(ctx, dbA.Address())
	require.NoError(t, err)
	waitFor(t, func() bool {
		all, err := dbB.All(ctx)
		return err == nil && len(all) == 1
	})
	_, err = dbB.Add(ctx, "from b")
	require.ErrorContains(t, err, "not allowed to write", "b is not in the write list")
}

func TestOrbitDBAccessControllerGrantAndRevoke(t *testing.T) {
	ctx := context.Background()
	a, b := newOrbitDB(t, "a"), newOrbitDB(t, "b")
	connect(t, a, b)

	dbA, err := a.OpenEvents(ctx, "managed", orbitdb.WithAccessController(accesscontrollers.OrbitDB(accesscontrollers.OrbitDBOptions{})))
	require.NoError(t, err)
	ac := dbA.AccessController().(*accesscontrollers.OrbitDBAccessController)
	require.True(t, orbitdb.IsValidAddress(ac.Address()), "the access controller is itself a database")

	admins, err := ac.Get(ctx, accesscontrollers.CapabilityAdmin)
	require.NoError(t, err)
	require.Equal(t, []string{a.Identity().ID}, admins)

	dbB, err := b.OpenEvents(ctx, dbA.Address())
	require.NoError(t, err)
	_, err = dbB.Add(ctx, "too early")
	require.ErrorContains(t, err, "not allowed to write")

	require.NoError(t, ac.Grant(ctx, accesscontrollers.CapabilityWrite, b.Identity().ID))
	acB := dbB.AccessController().(*accesscontrollers.OrbitDBAccessController)
	waitFor(t, func() bool {
		ok, err := acB.HasCapability(ctx, accesscontrollers.CapabilityWrite, b.Identity().ID)
		return err == nil && ok
	})
	_, err = dbB.Add(ctx, "granted")
	require.NoError(t, err)
	waitFor(t, func() bool {
		all, err := dbA.All(ctx)
		return err == nil && len(all) == 1 && all[0].Value == "granted"
	})

	caps, err := ac.Capabilities(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{b.Identity().ID}, caps[accesscontrollers.CapabilityWrite])

	require.NoError(t, ac.Revoke(ctx, accesscontrollers.CapabilityWrite, b.Identity().ID))
	ok, err := ac.HasCapability(ctx, accesscontrollers.CapabilityWrite, b.Identity().ID)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestForgedEntryFromPeerIsRejected(t *testing.T) {
	ctx := context.Background()
	a, b := newOrbitDB(t, "a"), newOrbitDB(t, "b")
	connect(t, a, b)
	dbA, err := a.OpenEvents(ctx, "guarded")
	require.NoError(t, err)
	_, err = dbA.Add(ctx, "legit")
	require.NoError(t, err)
	sub := dbA.Events().Subscribe()
	defer sub.Close()

	// b replicates the database, then forges an entry claiming to be a.
	dbB, err := b.OpenEvents(ctx, dbA.Address(), orbitdb.WithSync(false))
	require.NoError(t, err)
	heads, err := dbA.Log().Heads(ctx)
	require.NoError(t, err)
	forged, err := oplog.CreateEntry(ctx, b.Identity(), dbA.Address(), map[string]any{"op": "ADD", "key": nil, "value": "forged"},
		oplog.EntryOptions{Next: []string{heads[0].Hash}, Clock: &oplog.Clock{ID: b.Identity().PublicKey, Time: 2}})
	require.NoError(t, err)
	forged.Identity = a.Identity().Hash
	hash, data, err := oplog.EncodeEntry(ctx, forged, oplog.Encryption{})
	require.NoError(t, err)
	require.NoError(t, dbB.Log().Storage().Put(ctx, hash, data))
	forged.Hash = hash
	require.NoError(t, dbB.Sync().Start())
	require.NoError(t, dbB.Sync().Add(ctx, forged))

	deadline := time.After(30 * time.Second)
	for {
		select {
		case ev := <-sub.Events():
			if ev.Type == databases.EventError {
				require.ErrorContains(t, ev.Err, "not allowed to write")
				all, err := dbA.All(ctx)
				require.NoError(t, err)
				require.Len(t, all, 1, "the forged entry was not joined")
				return
			}
			require.NotEqual(t, databases.EventUpdate, ev.Type, "forged entry accepted")
		case <-deadline:
			t.Fatal("the forged entry was neither rejected nor accepted")
		}
	}
}

type xorCipher struct{ key byte }

func (c xorCipher) Encrypt(_ context.Context, b []byte) ([]byte, error) { return c.apply(b), nil }
func (c xorCipher) Decrypt(_ context.Context, b []byte) ([]byte, error) { return c.apply(b), nil }
func (c xorCipher) apply(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = v ^ c.key
	}
	return out
}

func TestEncryptedReplication(t *testing.T) {
	ctx := context.Background()
	a, b := newOrbitDB(t, "a"), newOrbitDB(t, "b")
	connect(t, a, b)
	enc := orbitdb.WithEncryption(oplog.Encryption{Data: xorCipher{0x42}, Replication: xorCipher{0x17}})
	anyone := orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{"*"}}))

	dbA, err := a.OpenKeyValue(ctx, "secret", enc, anyone)
	require.NoError(t, err)
	hash, err := dbA.Put(ctx, "k", "top secret")
	require.NoError(t, err)
	raw, err := dbA.Log().Storage().Get(ctx, hash)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "top secret", "the stored block is encrypted")

	dbB, err := b.OpenKeyValue(ctx, dbA.Address(), enc)
	require.NoError(t, err)
	waitFor(t, func() bool {
		v, err := dbB.Get(ctx, "k")
		return err == nil && v == "top secret"
	})
}

func TestStopClosesDatabases(t *testing.T) {
	ctx := context.Background()
	node, err := ipfs.New(ctx, ipfs.Options{})
	require.NoError(t, err)
	defer node.Close()
	odb, err := orbitdb.New(ctx, orbitdb.Options{IPFS: node, Directory: t.TempDir()})
	require.NoError(t, err)
	require.Len(t, odb.ID(), 32, "a random id is generated")
	db, err := odb.OpenEvents(ctx, "x")
	require.NoError(t, err)
	sub := db.Events().Subscribe()
	require.NoError(t, odb.Stop())
	var last databases.Event
	for ev := range sub.Events() {
		last = ev
	}
	require.Equal(t, databases.EventClose, last.Type)
}

func TestWithSyncDisabled(t *testing.T) {
	ctx := context.Background()
	a, b := newOrbitDB(t, "a"), newOrbitDB(t, "b")
	connect(t, a, b)
	anyone := orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{"*"}}))
	dbA, err := a.OpenEvents(ctx, "manual", anyone)
	require.NoError(t, err)
	_, err = dbA.Add(ctx, "one")
	require.NoError(t, err)
	dbB, err := b.OpenEvents(ctx, dbA.Address(), orbitdb.WithSync(false))
	require.NoError(t, err)
	time.Sleep(time.Second)
	all, err := dbB.All(ctx)
	require.NoError(t, err)
	require.Empty(t, all, "nothing replicates until sync starts")
	require.NoError(t, dbB.Sync().Start())
	waitFor(t, func() bool {
		all, err := dbB.All(ctx)
		return err == nil && len(all) == 1
	})
}

func TestCustomDatabaseType(t *testing.T) {
	ctx := context.Background()
	odb := newOrbitDB(t, "a")
	require.NoError(t, databases.UseDatabaseType("counter", func(ctx context.Context, p databases.Params) (databases.Store, error) {
		return databases.NewEvents(ctx, p)
	}))
	store, err := odb.Open(ctx, "hits", orbitdb.WithType("counter"))
	require.NoError(t, err)
	_, ok := store.(*databases.Events)
	require.True(t, ok)
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err = odb.Open(short, "/orbitdb/zdpuAuK3BHpS7NvMBivynypqciYCuy2UW77XYBPUYRnLjnw13")
	require.ErrorIs(t, err, context.DeadlineExceeded, "an address nobody serves cannot be opened")
}
