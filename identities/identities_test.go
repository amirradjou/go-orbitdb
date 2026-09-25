package identities_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/amirradjou/go-orbitdb/identities"
	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/identities/providers"
	"github.com/amirradjou/go-orbitdb/internal/testutil"
	"github.com/amirradjou/go-orbitdb/keystore"
	"github.com/amirradjou/go-orbitdb/storage"
)

func newIdentities(t *testing.T) (*identities.Identities, *keystore.KeyStore) {
	t.Helper()
	ks := testutil.Keystore(t)
	ids, err := identities.New(identities.Options{Keystore: ks})
	require.NoError(t, err)
	return ids, ks
}

func TestCreateIdentityMatchesJavaScript(t *testing.T) {
	// Expected values from test/identities/identities.test.js ("create an
	// identity with saved keys") in @orbitdb/core 4.0.0.
	const (
		expectedPublicKey     = "0342fa42a69135eade1e37ea520bc8ee9e240efd62cb0edf0516b21258b4eae656"
		expectedIDSignature   = "3044022068b4bc360d127e39164fbc3b5184f5bd79cc5976286f793d9b38d1f2818e0259022027b875dc8c73635b32db72177b9922038ec4b1eabc8f1fd0919806b0b2519419"
		expectedPkIDSignature = "30440220464cd4a6202dae2d2fb75b47afc7cceafa6b13c310efabbbdaaf38e67f74188b02201bbef8c97b741b4bb9e3e5362edfcd2eb6fe3b93f4e68e5870fcc345a850f366"
	)
	ctx := context.Background()
	ids, ks := newIdentities(t)
	identity, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "userX"})
	require.NoError(t, err)

	providerKey, err := ks.GetKey(ctx, "userX")
	require.NoError(t, err)
	providerPub, err := keystore.PublicKey(providerKey)
	require.NoError(t, err)
	require.Equal(t, providerPub, identity.ID, "the id is the provider key's public key")
	require.Equal(t, expectedPublicKey, identity.PublicKey)
	require.Equal(t, providers.PublicKeyType, identity.Type)
	require.Equal(t, expectedIDSignature, identity.Signatures.ID)
	require.Equal(t, expectedPkIDSignature, identity.Signatures.PublicKey)

	ok, err := ids.VerifyIdentity(ctx, identity)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestCreateIdentityCreatesKeys(t *testing.T) {
	ctx := context.Background()
	ks, err := keystore.New(keystore.Options{Storage: storage.NewMemoryStorage()})
	require.NoError(t, err)
	ids, err := identities.New(identities.Options{Keystore: ks})
	require.NoError(t, err)

	identity, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "fresh"})
	require.NoError(t, err)
	for _, id := range []string{"fresh", identity.ID} {
		has, err := ks.HasKey(ctx, id)
		require.NoError(t, err)
		require.True(t, has, id)
	}
	ok, err := ids.VerifyIdentity(ctx, identity)
	require.NoError(t, err)
	require.True(t, ok)

	again, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "fresh"})
	require.NoError(t, err)
	require.Equal(t, identity.Hash, again.Hash, "creating the same identity again reuses its keys")
}

func TestCreateIdentityRequiresID(t *testing.T) {
	ids, _ := newIdentities(t)
	_, err := ids.CreateIdentity(context.Background(), identities.CreateOptions{})
	require.ErrorContains(t, err, "id is required")
}

func TestGetIdentityFromStorage(t *testing.T) {
	ctx := context.Background()
	st := storage.NewMemoryStorage()
	ids, err := identities.New(identities.Options{Keystore: testutil.Keystore(t), Storage: st})
	require.NoError(t, err)
	identity, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "userA"})
	require.NoError(t, err)

	data, err := st.Get(ctx, identity.Hash)
	require.NoError(t, err)
	require.Equal(t, identity.Bytes, data)

	got, err := ids.GetIdentity(ctx, identity.Hash)
	require.NoError(t, err)
	require.True(t, identitytypes.IsEqual(identity, got))

	_, err = ids.GetIdentity(ctx, "zdpuArx43BnXdDff5rjrGLYrxUomxNroc2uaocTgcWK76UfQT")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestVerifyIdentityRejectsTampering(t *testing.T) {
	ctx := context.Background()
	ids, _ := newIdentities(t)
	identity, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "QmFoo"})
	require.NoError(t, err)

	require.True(t, keystore.VerifyMessage(identity.Signatures.ID, identity.PublicKey, []byte(identity.ID)))
	require.True(t, keystore.VerifyMessage(identity.Signatures.PublicKey, identity.ID, []byte(identity.PublicKey+identity.Signatures.ID)))

	other, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "userB"})
	require.NoError(t, err)

	forged, err := identitytypes.New(identity.ID, other.PublicKey, other.Signatures, identity.Type, nil)
	require.NoError(t, err)
	ok, err := ids.VerifyIdentity(ctx, forged)
	require.NoError(t, err)
	require.False(t, ok, "signatures of another identity do not verify")

	ok, err = ids.VerifyIdentity(ctx, &identitytypes.Identity{ID: "incomplete"})
	require.NoError(t, err)
	require.False(t, ok)

	// A fresh Identities (empty verified cache) also rejects a swapped
	// provider signature.
	ids2, _ := newIdentities(t)
	swapped, err := identitytypes.New(identity.ID, identity.PublicKey, identitytypes.Signatures{
		ID:        identity.Signatures.ID,
		PublicKey: other.Signatures.PublicKey,
	}, identity.Type, nil)
	require.NoError(t, err)
	ok, err = ids2.VerifyIdentity(ctx, swapped)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestSignAndVerifyData(t *testing.T) {
	ctx := context.Background()
	ids, _ := newIdentities(t)
	identity, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "03602a3da3eb35f1148e8028f141ec415ef7f6d4103443edbfec2a0711d716f53f"})
	require.NoError(t, err)

	data := []byte("hello friend")
	sig, err := identity.Sign(ctx, data)
	require.NoError(t, err)
	require.True(t, ids.Verify(sig, identity.PublicKey, data))
	require.False(t, ids.Verify("invalid", identity.PublicKey, data))

	signingKey, err := ids.Keystore().GetKey(ctx, identity.ID)
	require.NoError(t, err)
	want, err := keystore.SignMessage(signingKey, data)
	require.NoError(t, err)
	require.Equal(t, want, sig)

	modified := *identity
	modified.ID = "this id does not exist"
	_, err = ids.Sign(ctx, &modified, data)
	require.EqualError(t, err, "private signing key not found from KeyStore")
}

// customProvider signs like the publickey provider under another type
// name, to exercise the provider registry.
type customProvider struct {
	*providers.PublicKeyProvider
	typ string
}

func (p customProvider) Type() string { return p.typ }

// customRuns keeps provider type names unique across -count runs, since the
// registry is process-wide.
var customRuns atomic.Int64

func TestCustomIdentityProvider(t *testing.T) {
	ctx := context.Background()
	ids, ks := newIdentities(t)
	typ := fmt.Sprint("custom-", customRuns.Add(1))
	provider := customProvider{providers.NewPublicKeyProvider(ks), typ}

	_, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "userC", Provider: provider})
	require.ErrorContains(t, err, "identity provider is unknown")

	require.Error(t, providers.UseIdentityProvider("", providers.VerifyPublicKeyIdentity))
	require.Error(t, providers.UseIdentityProvider(typ, nil))
	require.NoError(t, providers.UseIdentityProvider(typ, providers.VerifyPublicKeyIdentity))

	identity, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "userC", Provider: provider})
	require.NoError(t, err)
	require.Equal(t, typ, identity.Type)
	ok, err := ids.VerifyIdentity(ctx, identity)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = providers.GetIdentityProvider("never-registered")
	require.Error(t, err)
}

func TestDefaultKeystorePath(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ids, err := identities.New(identities.Options{Path: dir})
	require.NoError(t, err)
	identity, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "persisted"})
	require.NoError(t, err)
	require.NoError(t, ids.Keystore().Close())

	ids, err = identities.New(identities.Options{Path: dir})
	require.NoError(t, err)
	defer ids.Keystore().Close()
	again, err := ids.CreateIdentity(ctx, identities.CreateOptions{ID: "persisted"})
	require.NoError(t, err)
	require.Equal(t, identity.Hash, again.Hash, "keys persist in the keystore directory")
}
