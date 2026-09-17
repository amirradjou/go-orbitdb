package identities

import (
	"fmt"
	"testing"

	"orbitdb/go-orbitdb/keystore"
	"orbitdb/go-orbitdb/storage"
)

// TestCreateSignVerifyManyIdentities is the end-to-end regression test for
// the big.Int.Bytes() leading-zero bug: before the fix roughly 1.5% of fresh
// identities could not verify their own signatures because a public key or
// signature with a leading zero byte was encoded one byte short.
func TestCreateSignVerifyManyIdentities(t *testing.T) {
	const total = 3000
	n := total
	if testing.Short() {
		n = total / 10
	}

	// MemoryStorage: an LRU of 100 would evict keys during the loop.
	ids, err := setupIdentities(storage.NewMemoryStorage())
	if err != nil {
		t.Fatalf("setupIdentities: %v", err)
	}
	data := []byte("leading-zero regression")

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("identity-%d", i)
		identity, err := ids.CreateIdentity(id)
		if err != nil {
			t.Fatalf("[%d] CreateIdentity: %v", i, err)
		}
		if len(identity.PublicKey) != 2*keystore.PublicKeySize {
			t.Fatalf("[%d] public key is %d hex chars, want %d: %s", i, len(identity.PublicKey), 2*keystore.PublicKeySize, identity.PublicKey)
		}
		for name, sig := range identity.Signatures {
			if len(sig) != 2*keystore.SignatureSize {
				t.Fatalf("[%d] %s signature is %d hex chars, want %d", i, name, len(sig), 2*keystore.SignatureSize)
			}
		}
		if !ids.VerifyIdentity(identity) {
			t.Fatalf("[%d] VerifyIdentity failed for %+v", i, identity)
		}

		sig, err := ids.Sign(id, data)
		if err != nil {
			t.Fatalf("[%d] Sign: %v", i, err)
		}
		if len(sig) != 2*keystore.SignatureSize {
			t.Fatalf("[%d] signature is %d hex chars, want %d", i, len(sig), 2*keystore.SignatureSize)
		}
		if !ids.Verify(sig, identity, data) {
			t.Fatalf("[%d] Verify failed: sig=%s pub=%s", i, sig, identity.PublicKey)
		}
		if ids.Verify(sig, identity, []byte("tampered")) {
			t.Fatalf("[%d] Verify accepted tampered data", i)
		}
	}
}

// TestVerifyRejectsMalformedPublicKey covers the exact-length check that
// replaced the old "at least 64 bytes, split in the middle" parsing.
func TestVerifyRejectsMalformedPublicKey(t *testing.T) {
	ids, err := setupIdentities(storage.NewMemoryStorage())
	if err != nil {
		t.Fatalf("setupIdentities: %v", err)
	}
	identity, err := ids.CreateIdentity("id")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	data := []byte("data")
	sig, err := ids.Sign("id", data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ids.Verify(sig, identity, data) {
		t.Fatal("sanity: valid signature did not verify")
	}

	good := identity.PublicKey
	for name, pk := range map[string]string{
		"one byte short": good[2:],
		"one byte long":  "00" + good,
		"not hex":        "zz" + good[2:],
		"empty":          "",
	} {
		identity.PublicKey = pk
		if ids.Verify(sig, identity, data) {
			t.Errorf("%s: Verify accepted malformed public key %q", name, pk)
		}
		if ids.VerifyIdentity(identity) {
			t.Errorf("%s: VerifyIdentity accepted malformed public key %q", name, pk)
		}
	}
}
