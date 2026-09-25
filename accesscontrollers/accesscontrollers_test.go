package accesscontrollers_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/amirradjou/go-orbitdb/accesscontrollers"
	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/internal/testutil"
	"github.com/amirradjou/go-orbitdb/oplog"
	"github.com/amirradjou/go-orbitdb/storage"
)

func setup(t *testing.T) (*identities.Identities, map[string]*identitytypes.Identity) {
	t.Helper()
	ids, err := identities.New(identities.Options{Keystore: testutil.Keystore(t)})
	require.NoError(t, err)
	users := map[string]*identitytypes.Identity{}
	for _, name := range []string{"userA", "userB", "userC"} {
		users[name], err = ids.CreateIdentity(context.Background(), identities.CreateOptions{ID: name})
		require.NoError(t, err)
	}
	return ids, users
}

func TestIPFSAccessControllerMatchesJavaScript(t *testing.T) {
	ctx := context.Background()
	ids, users := setup(t)
	vectorIDs := map[string]string{users["userA"].ID: "A", users["userB"].ID: "B"}
	for _, m := range testutil.JSVectors(t).Manifests {
		st := storage.NewMemoryStorage()
		ac, err := accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: m.Write, Storage: st})(ctx, accesscontrollers.Params{Identities: ids})
		require.NoError(t, err)
		require.Equal(t, m.AccessController, ac.Address(), "write %v", m.Write)
		data, err := st.Get(ctx, ac.Address()[len("/ipfs/"):])
		require.NoError(t, err)
		require.Equal(t, []byte(m.AccessControllerBytes), data)

		// Loading the JS block by address gives the same write list.
		loaded, err := accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Storage: st})(ctx, accesscontrollers.Params{Identities: ids, Address: m.AccessController})
		require.NoError(t, err)
		require.Equal(t, m.Write, loaded.(*accesscontrollers.IPFSAccessController).Write())
		for _, w := range m.Write {
			if w != "*" {
				require.Contains(t, vectorIDs, w)
			}
		}
	}
}

func entryBy(t *testing.T, identity *identitytypes.Identity) *oplog.Entry {
	t.Helper()
	e, err := oplog.CreateEntry(context.Background(), identity, "log", "payload", oplog.EntryOptions{})
	require.NoError(t, err)
	return e
}

func TestIPFSAccessControllerCanAppend(t *testing.T) {
	ctx := context.Background()
	ids, users := setup(t)
	create := func(write []string) accesscontrollers.AccessController {
		ac, err := accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: write, Storage: storage.NewMemoryStorage()})(ctx,
			accesscontrollers.Params{Identities: ids, Identity: users["userA"]})
		require.NoError(t, err)
		return ac
	}

	onlyA := create(nil) // defaults to the local identity
	require.Equal(t, accesscontrollers.IPFSType, onlyA.Type())
	ok, err := onlyA.CanAppend(ctx, entryBy(t, users["userA"]))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = onlyA.CanAppend(ctx, entryBy(t, users["userB"]))
	require.NoError(t, err)
	require.False(t, ok)

	anyone := create([]string{"*"})
	ok, err = anyone.CanAppend(ctx, entryBy(t, users["userC"]))
	require.NoError(t, err)
	require.True(t, ok)

	unknown := entryBy(t, users["userA"])
	unknown.Identity = "zdpuArx43BnXdDff5rjrGLYrxUomxNroc2uaocTgcWK76UfQT"
	ok, err = anyone.CanAppend(ctx, unknown)
	require.NoError(t, err)
	require.False(t, ok, "a writer whose identity cannot be found is refused")
}

func TestRelabeledEntryIsRefused(t *testing.T) {
	// An entry signed by B but carrying A's identity hash must not pass as
	// A's: the identity field is not covered by the signature.
	ctx := context.Background()
	ids, users := setup(t)
	ac, err := accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{users["userA"].ID}, Storage: storage.NewMemoryStorage()})(ctx,
		accesscontrollers.Params{Identities: ids})
	require.NoError(t, err)

	forged := entryBy(t, users["userB"])
	forged.Identity = users["userA"].Hash
	valid, err := oplog.VerifyEntry(forged)
	require.NoError(t, err)
	require.True(t, valid, "the signature itself still verifies")
	ok, err := ac.CanAppend(ctx, forged)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRegistry(t *testing.T) {
	for _, typ := range []string{"ipfs", "orbitdb"} {
		_, err := accesscontrollers.GetAccessController(typ)
		require.NoError(t, err)
	}
	_, err := accesscontrollers.GetAccessController("nope")
	require.Error(t, err)
	require.Error(t, accesscontrollers.UseAccessController("", accesscontrollers.IPFS(accesscontrollers.IPFSOptions{})))
	require.NoError(t, accesscontrollers.UseAccessController("custom", accesscontrollers.IPFS(accesscontrollers.IPFSOptions{})))

	require.Equal(t, "ipfs", accesscontrollers.TypeOf("/ipfs/zdpu"))
	require.Equal(t, "orbitdb", accesscontrollers.TypeOf("/orbitdb/zdpu"))
	require.Equal(t, "", accesscontrollers.TypeOf("zdpu"))
}

func TestFactoriesValidate(t *testing.T) {
	ctx := context.Background()
	_, err := accesscontrollers.IPFS(accesscontrollers.IPFSOptions{})(ctx, accesscontrollers.Params{})
	require.Error(t, err)
	ids, _ := setup(t)
	_, err = accesscontrollers.IPFS(accesscontrollers.IPFSOptions{})(ctx, accesscontrollers.Params{Identities: ids})
	require.Error(t, err, "no storage and no IPFS")
	_, err = accesscontrollers.OrbitDB(accesscontrollers.OrbitDBOptions{})(ctx, accesscontrollers.Params{Identities: ids})
	require.Error(t, err, "the orbitdb controller needs OrbitDB")
}
