package keystore_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/require"

	"github.com/amirradjou/go-orbitdb/internal/testutil"
	"github.com/amirradjou/go-orbitdb/keystore"
	"github.com/amirradjou/go-orbitdb/storage"
)

// Expected values are the ones asserted by test/key-store.test.js in
// @orbitdb/core 4.0.0 against the same fixture keys.
const (
	userAPublicKey = "02e7247a4c155b63d182a23c70cb6fe8ba2e44bc9e9d62dc45d4c4167ccde95944"
	userASignature = "3045022100df961fa46bb8a3cb92594a24205e6008a84daa563ac3530f583bb9f9cef5af3b02207b84c5d63387d0a710e42e05785fbccdaf2534c8ed16adb8afd57c3eba930529"
)

func newMemoryKeystore(t *testing.T) *keystore.KeyStore {
	t.Helper()
	ks, err := keystore.New(keystore.Options{Storage: storage.NewMemoryStorage()})
	require.NoError(t, err)
	return ks
}

func TestCreateHasGetKey(t *testing.T) {
	ctx := context.Background()
	ks := newMemoryKeystore(t)

	has, err := ks.HasKey(ctx, "X")
	require.NoError(t, err)
	require.False(t, has)

	created, err := ks.CreateKey(ctx, "X")
	require.NoError(t, err)
	require.EqualValues(t, crypto.Secp256k1, created.Type())

	has, err = ks.HasKey(ctx, "X")
	require.NoError(t, err)
	require.True(t, has)

	got, err := ks.GetKey(ctx, "X")
	require.NoError(t, err)
	require.True(t, created.Equals(got))

	_, err = ks.GetKey(ctx, "missing")
	require.ErrorIs(t, err, keystore.ErrNotFound)

	again, err := ks.GetOrCreateKey(ctx, "X")
	require.NoError(t, err)
	require.True(t, created.Equals(again), "GetOrCreateKey returns the existing key")
}

func TestEmptyIDIsRejected(t *testing.T) {
	ctx := context.Background()
	ks := newMemoryKeystore(t)
	_, err := ks.CreateKey(ctx, "")
	require.ErrorContains(t, err, "id needed to create a key")
	_, err = ks.GetKey(ctx, "")
	require.ErrorContains(t, err, "id needed to get a key")
	_, err = ks.HasKey(ctx, "")
	require.ErrorContains(t, err, "id needed to check a key")
}

func TestKeysAreStoredRaw(t *testing.T) {
	ctx := context.Background()
	st := storage.NewMemoryStorage()
	ks, err := keystore.New(keystore.Options{Storage: st})
	require.NoError(t, err)
	key, err := ks.CreateKey(ctx, "id")
	require.NoError(t, err)

	raw, err := st.Get(ctx, "private_id")
	require.NoError(t, err)
	require.Len(t, raw, 32, "secp256k1 keys are stored as their 32 raw bytes, like @orbitdb/core")
	want, err := key.Raw()
	require.NoError(t, err)
	require.Equal(t, want, raw)

	// A fresh keystore over the same storage reads the key back.
	ks2, err := keystore.New(keystore.Options{Storage: st})
	require.NoError(t, err)
	got, err := ks2.GetKey(ctx, "id")
	require.NoError(t, err)
	require.True(t, key.Equals(got))
}

func TestDefaultStorageUsesPath(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ks, err := keystore.New(keystore.Options{Path: dir})
	require.NoError(t, err)
	key, err := ks.CreateKey(ctx, "persisted")
	require.NoError(t, err)
	require.NoError(t, ks.Close())

	ks, err = keystore.New(keystore.Options{Path: dir})
	require.NoError(t, err)
	defer ks.Close()
	got, err := ks.GetKey(ctx, "persisted")
	require.NoError(t, err)
	require.True(t, key.Equals(got))
}

// copyDir copies the read-only fixture so LevelDB can open it for writing.
func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, e := range entries {
		in, err := os.Open(filepath.Join(src, e.Name()))
		require.NoError(t, err)
		out, err := os.Create(filepath.Join(dst, e.Name()))
		require.NoError(t, err)
		_, err = io.Copy(out, in)
		require.NoError(t, err)
		require.NoError(t, in.Close())
		require.NoError(t, out.Close())
	}
	return dst
}

func TestOpensJavaScriptKeystore(t *testing.T) {
	// testdata/jskeystore is test/fixtures/newtestkeys2 from @orbitdb/core,
	// a LevelDB database written by the JavaScript implementation.
	ks, err := keystore.New(keystore.Options{Path: copyDir(t, "testdata/jskeystore")})
	require.NoError(t, err)
	defer ks.Close()

	for id, want := range testutil.JSKeys {
		key, err := ks.GetKey(context.Background(), id)
		require.NoError(t, err, id)
		raw, err := key.Raw()
		require.NoError(t, err)
		require.Equal(t, want, hex.EncodeToString(raw), id)
	}
}

func TestSignMatchesJavaScript(t *testing.T) {
	ctx := context.Background()
	ks := testutil.Keystore(t)
	key, err := ks.GetKey(ctx, "userA")
	require.NoError(t, err)

	pub, err := keystore.PublicKey(key)
	require.NoError(t, err)
	require.Equal(t, userAPublicKey, pub)

	sig, err := keystore.SignMessage(key, []byte("data data data"))
	require.NoError(t, err)
	require.Equal(t, userASignature, sig, "signatures are deterministic and byte-identical to JS")

	require.True(t, keystore.VerifyMessage(sig, pub, []byte("data data data")))
}

func TestSignMessageErrors(t *testing.T) {
	_, err := keystore.SignMessage(nil, []byte("x"))
	require.ErrorContains(t, err, "no signing key")
	key, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	_, err = keystore.SignMessage(key, nil)
	require.ErrorContains(t, err, "input data")
}

func TestVerifyMessage(t *testing.T) {
	key, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	pub, err := keystore.PublicKey(key)
	require.NoError(t, err)
	data := []byte("data data data")
	sig, err := keystore.SignMessage(key, data)
	require.NoError(t, err)

	require.True(t, keystore.VerifyMessage(sig, pub, data))
	require.True(t, keystore.VerifyMessage(sig, pub, data), "cached result")

	require.False(t, keystore.VerifyMessage(sig, pub, []byte("other data")), "cached signature, different data")
	other, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	otherPub, err := keystore.PublicKey(other)
	require.NoError(t, err)
	require.False(t, keystore.VerifyMessage(sig, otherPub, data), "cached signature, different key")

	require.False(t, keystore.VerifyMessage("xxxxxx", pub, data))
	require.False(t, keystore.VerifyMessage(sig, "zz", data))
	require.False(t, keystore.VerifyMessage("", pub, data))
	require.False(t, keystore.VerifyMessage(sig, pub, nil))
}

func TestSignVerifyManyKeys(t *testing.T) {
	// The previous P-256 implementation encoded r, s, X and Y with
	// big.Int.Bytes(), which drops leading zeros, and ~1.5% of freshly
	// generated keys failed to verify their own signatures. DER encoding
	// has no fixed width to get wrong; keep the loop as a regression guard.
	for i := range 2000 {
		key, _, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		pub, err := keystore.PublicKey(key)
		require.NoError(t, err)
		data := []byte(fmt.Sprint("message ", i))
		sig, err := keystore.SignMessage(key, data)
		require.NoError(t, err)
		require.True(t, keystore.VerifyMessage(sig, pub, data), "iteration %d", i)
	}
}

func TestUnmarshalKeyTypes(t *testing.T) {
	edPriv, edPub, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)
	raw, err := edPriv.Raw()
	require.NoError(t, err)
	parsed, err := keystore.UnmarshalPrivateKey(raw)
	require.NoError(t, err)
	require.True(t, edPriv.Equals(parsed))

	pubRaw, err := edPub.Raw()
	require.NoError(t, err)
	parsedPub, err := keystore.UnmarshalPublicKey(pubRaw)
	require.NoError(t, err)
	require.True(t, edPub.Equals(parsedPub))

	sig, err := keystore.SignMessage(edPriv, []byte("hi"))
	require.NoError(t, err)
	require.True(t, keystore.VerifyMessage(sig, hex.EncodeToString(pubRaw), []byte("hi")))
}
