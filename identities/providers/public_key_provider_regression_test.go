package providers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"orbitdb/go-orbitdb/keystore"
	"orbitdb/go-orbitdb/storage"
)

// TestCreateIdentityKnownShortCoordinateKey feeds the provider a throwaway
// P-256 key whose X coordinate starts with a zero byte. Before the fix the
// provider encoded it as 63 bytes and VerifyIdentity rejected it.
func TestCreateIdentityKnownShortCoordinateKey(t *testing.T) {
	hexInt := func(s string) *big.Int {
		v, ok := new(big.Int).SetString(s, 16)
		if !ok {
			t.Fatalf("bad hex %q", s)
		}
		return v
	}
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     hexInt("7fc2bbae50e6e31de98304145f57ab65d4a097654988fd59657e45ccf9ad1b"), // 31 bytes
			Y:     hexInt("d724255d1c5ecb3a171bbb0cdda6b3380edc28c52be6f576968cbb906b87ed8c"),
		},
		D: hexInt("a2efbc232cdfddbec6856c095dfb27be7c0a2d069e201313d2e99941a750feba"),
	}
	if len(key.X.Bytes()) != keystore.CoordinateSize-1 {
		t.Fatalf("vector sanity: X.Bytes() is %d bytes, want %d", len(key.X.Bytes()), keystore.CoordinateSize-1)
	}

	ks := keystore.NewKeyStore(storage.NewMemoryStorage())
	if err := ks.AddKey("short-x", key); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	provider := NewPublicKeyProvider(ks)

	identity, err := provider.CreateIdentity("short-x")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if len(identity.PublicKey) != 2*keystore.PublicKeySize {
		t.Fatalf("public key is %d hex chars, want %d", len(identity.PublicKey), 2*keystore.PublicKeySize)
	}
	if !strings.HasPrefix(identity.PublicKey, "007fc2bbae") {
		t.Fatalf("public key was not zero-padded: %s", identity.PublicKey)
	}

	ok, err := provider.VerifyIdentity(identity)
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if !ok {
		t.Fatal("VerifyIdentity returned false for a valid short-X identity")
	}
}

// TestCreateAndVerifyManyIdentities loops over many fresh identities so a
// regression to variable-width encoding shows up as a deterministic failure.
func TestCreateAndVerifyManyIdentities(t *testing.T) {
	n := 3000
	if testing.Short() {
		n /= 10
	}
	ks := keystore.NewKeyStore(storage.NewMemoryStorage())
	provider := NewPublicKeyProvider(ks)

	for i := 0; i < n; i++ {
		identity, err := provider.CreateIdentity(fmt.Sprintf("id-%d", i))
		if err != nil {
			t.Fatalf("[%d] CreateIdentity: %v", i, err)
		}
		if len(identity.PublicKey) != 2*keystore.PublicKeySize {
			t.Fatalf("[%d] public key is %d hex chars, want %d", i, len(identity.PublicKey), 2*keystore.PublicKeySize)
		}
		ok, err := provider.VerifyIdentity(identity)
		if err != nil || !ok {
			t.Fatalf("[%d] VerifyIdentity: ok=%v err=%v (pub=%s sigs=%v)", i, ok, err, identity.PublicKey, identity.Signatures)
		}
	}
}
