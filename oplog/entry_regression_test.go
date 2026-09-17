package oplog

import (
	"fmt"
	"testing"

	"orbitdb/go-orbitdb/identities/providers"
	"orbitdb/go-orbitdb/keystore"
	"orbitdb/go-orbitdb/storage"
)

// TestVerifyEntrySignatureManyIdentities is the oplog-level regression test
// for the big.Int.Bytes() leading-zero bug. Before the fix ~1.5% of fresh
// identities produced a 63-byte public key or signature, so the entry they
// signed failed VerifyEntrySignature and was silently dropped by every
// Log read path (Get, Values, Traverse, JoinEntry).
func TestVerifyEntrySignatureManyIdentities(t *testing.T) {
	n := 1000
	if testing.Short() {
		n /= 10
	}
	ks := keystore.NewKeyStore(storage.NewMemoryStorage())
	provider := providers.NewPublicKeyProvider(ks)

	for i := 0; i < n; i++ {
		identity, err := provider.CreateIdentity(fmt.Sprintf("writer-%d", i))
		if err != nil {
			t.Fatalf("[%d] CreateIdentity: %v", i, err)
		}
		entry := NewEntry(ks, identity, "log", fmt.Sprintf("payload-%d", i), Clock{ID: identity.PublicKey, Time: 1}, nil, nil)
		if len(entry.Key) != 2*keystore.PublicKeySize {
			t.Fatalf("[%d] entry key is %d hex chars, want %d", i, len(entry.Key), 2*keystore.PublicKeySize)
		}
		if len(entry.Signature) != 2*keystore.SignatureSize {
			t.Fatalf("[%d] entry signature is %d hex chars, want %d", i, len(entry.Signature), 2*keystore.SignatureSize)
		}
		if !VerifyEntrySignature(ks, entry) {
			t.Fatalf("[%d] entry %s did not verify (key=%s sig=%s)", i, entry.Hash, entry.Key, entry.Signature)
		}

		// Round trip through the CBOR codec as a Log reader would see it.
		decoded, err := Decode(entry.Bytes)
		if err != nil {
			t.Fatalf("[%d] Decode: %v", i, err)
		}
		if !VerifyEntrySignature(ks, decoded) {
			t.Fatalf("[%d] decoded entry %s did not verify", i, decoded.Hash)
		}
	}
}

// TestLogAppendAndReadBackManyEntries appends many entries from many fresh
// identities and checks every one is readable again, which is the user
// visible symptom of the leading-zero bug ("Skipping entry with invalid
// signature", missing values after join).
func TestLogAppendAndReadBackManyEntries(t *testing.T) {
	n := 300
	if testing.Short() {
		n /= 10
	}
	ks := keystore.NewKeyStore(storage.NewMemoryStorage())
	provider := providers.NewPublicKeyProvider(ks)

	for i := 0; i < n; i++ {
		identity, err := provider.CreateIdentity(fmt.Sprintf("writer-%d", i))
		if err != nil {
			t.Fatalf("[%d] CreateIdentity: %v", i, err)
		}
		log, err := NewLog("log", identity, storage.NewMemoryStorage(), ks)
		if err != nil {
			t.Fatalf("[%d] NewLog: %v", i, err)
		}
		appended, err := log.Append(fmt.Sprintf("payload-%d", i))
		if err != nil {
			t.Fatalf("[%d] Append: %v", i, err)
		}
		got, err := log.Get(appended.Hash)
		if err != nil {
			t.Fatalf("[%d] Get: %v", i, err)
		}
		if got.Hash != appended.Hash {
			t.Fatalf("[%d] Get returned %s, want %s", i, got.Hash, appended.Hash)
		}
		values, err := log.Values()
		if err != nil {
			t.Fatalf("[%d] Values: %v", i, err)
		}
		if len(values) != 1 {
			t.Fatalf("[%d] Values returned %d entries, want 1", i, len(values))
		}
	}
}
