package identitytypes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Vectors from test/identities/identity.test.js in @orbitdb/core 4.0.0.
const (
	vectorID   = "0x01234567890abcdefghijklmnopqrstuvwxyz"
	vectorPK   = "<pubkey>"
	vectorType = "orbitdb"
	vectorHash = "zdpuArx43BnXdDff5rjrGLYrxUomxNroc2uaocTgcWK76UfQT"
)

var (
	vectorSigs  = Signatures{ID: "signature for <id>", PublicKey: "signature for <publicKey + idSignature>"}
	vectorBytes = []byte{164, 98, 105, 100, 120, 39, 48, 120, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 100, 116, 121, 112, 101, 103, 111, 114, 98, 105, 116, 100, 98, 105, 112, 117, 98, 108, 105, 99, 75, 101, 121, 104, 60, 112, 117, 98, 107, 101, 121, 62, 106, 115, 105, 103, 110, 97, 116, 117, 114, 101, 115, 162, 98, 105, 100, 114, 115, 105, 103, 110, 97, 116, 117, 114, 101, 32, 102, 111, 114, 32, 60, 105, 100, 62, 105, 112, 117, 98, 108, 105, 99, 75, 101, 121, 120, 39, 115, 105, 103, 110, 97, 116, 117, 114, 101, 32, 102, 111, 114, 32, 60, 112, 117, 98, 108, 105, 99, 75, 101, 121, 32, 43, 32, 105, 100, 83, 105, 103, 110, 97, 116, 117, 114, 101, 62}
)

func TestEncodingMatchesJavaScript(t *testing.T) {
	identity, err := New(vectorID, vectorPK, vectorSigs, vectorType, nil)
	require.NoError(t, err)
	require.Equal(t, vectorHash, identity.Hash)
	require.Equal(t, vectorBytes, identity.Bytes)
	require.True(t, IsIdentity(identity))
}

func TestDecodeJavaScriptBytes(t *testing.T) {
	identity, err := Decode(vectorBytes)
	require.NoError(t, err)
	require.Equal(t, vectorID, identity.ID)
	require.Equal(t, vectorPK, identity.PublicKey)
	require.Equal(t, vectorSigs, identity.Signatures)
	require.Equal(t, vectorType, identity.Type)
	require.Equal(t, vectorHash, identity.Hash)
	require.Equal(t, vectorBytes, identity.Bytes)
}

func TestNewValidates(t *testing.T) {
	cases := map[string]func() (*Identity, error){
		"identity id is required": func() (*Identity, error) {
			return New("", vectorPK, vectorSigs, vectorType, nil)
		},
		"invalid public key": func() (*Identity, error) {
			return New(vectorID, "", vectorSigs, vectorType, nil)
		},
		"signature of id is required": func() (*Identity, error) {
			return New(vectorID, vectorPK, Signatures{PublicKey: "x"}, vectorType, nil)
		},
		"signature of publicKey+id is required": func() (*Identity, error) {
			return New(vectorID, vectorPK, Signatures{ID: "x"}, vectorType, nil)
		},
		"identity type is required": func() (*Identity, error) {
			return New(vectorID, vectorPK, vectorSigs, "", nil)
		},
	}
	for msg, create := range cases {
		_, err := create()
		require.EqualError(t, err, msg)
	}
}

func TestDecodeRejectsInvalid(t *testing.T) {
	_, err := Decode(nil)
	require.Error(t, err)
	_, err = Decode([]byte{0xa0}) // {}
	require.Error(t, err)
}

func TestIsIdentityAndIsEqual(t *testing.T) {
	a, err := New(vectorID, vectorPK, vectorSigs, vectorType, nil)
	require.NoError(t, err)
	b, err := Decode(vectorBytes)
	require.NoError(t, err)
	require.True(t, IsEqual(a, b))

	require.False(t, IsIdentity(nil))
	require.False(t, IsIdentity(&Identity{ID: vectorID}))

	for name, mutate := range map[string]func(*Identity){
		"id":        func(i *Identity) { i.ID = "other" },
		"hash":      func(i *Identity) { i.Hash = "other" },
		"type":      func(i *Identity) { i.Type = "other" },
		"publicKey": func(i *Identity) { i.PublicKey = "other" },
		"idSig":     func(i *Identity) { i.Signatures.ID = "other" },
		"pkSig":     func(i *Identity) { i.Signatures.PublicKey = "other" },
	} {
		c := *b
		mutate(&c)
		require.False(t, IsEqual(a, &c), name)
	}
	require.False(t, IsEqual(a, nil))
}

type fixedSigner string

func (s fixedSigner) Sign(context.Context, *Identity, []byte) (string, error) { return string(s), nil }

func TestSign(t *testing.T) {
	identity, err := Decode(vectorBytes)
	require.NoError(t, err)
	_, err = identity.Sign(context.Background(), []byte("x"))
	require.Error(t, err, "decoded identities cannot sign")

	signing := identity.WithSigner(fixedSigner("sig"))
	sig, err := signing.Sign(context.Background(), []byte("x"))
	require.NoError(t, err)
	require.Equal(t, "sig", sig)
	require.True(t, IsEqual(identity, signing))
}
