package identitytypes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Helper function to create a test Identity with a generated key pair.
func createTestIdentity(id string, identityType string) (*Identity, error) {
	// Generate an ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Encode the public key
	publicKeyBytes := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Create the Identity object
	identity := &Identity{
		ID:         id,
		PublicKey:  publicKeyHex,
		PrivateKey: privateKey,
		Signatures: map[string]string{
			"id":        "test-id-signature",
			"publicKey": "test-publicKey-signature",
		},
		Type: identityType,
	}

	// Encode the identity to populate Hash and Bytes fields
	hash, bytes, err := EncodeIdentity(*identity)
	if err != nil {
		return nil, err
	}
	identity.Hash = hash
	identity.Bytes = bytes

	return identity, nil
}

func TestSignAndVerify(t *testing.T) {
	identity, err := createTestIdentity("test-id", "test-type")
	if err != nil {
		t.Fatalf("Failed to create test identity: %v", err)
	}

	data := []byte("test-data")

	// Test Sign
	signature, err := identity.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Test Verify
	if !identity.Verify(signature, data) {
		t.Fatal("Expected valid signature verification to succeed")
	}

	// Test with altered data
	if identity.Verify(signature, []byte("tampered-data")) {
		t.Fatal("Expected verification to fail with altered data")
	}
}

func TestIsIdentity(t *testing.T) {
	identity, err := createTestIdentity("test-id", "test-type")
	if err != nil {
		t.Fatalf("Failed to create test identity: %v", err)
	}

	if !IsIdentity(identity) {
		t.Fatal("Expected IsIdentity to return true for valid identity")
	}

	// Test with incomplete identity
	invalidIdentity := &Identity{}
	if IsIdentity(invalidIdentity) {
		t.Fatal("Expected IsIdentity to return false for incomplete identity")
	}
}

func TestIsEqual(t *testing.T) {
	identityA, err := createTestIdentity("test-id", "test-type")
	if err != nil {
		t.Fatalf("Failed to create test identity A: %v", err)
	}
	identityB, err := createTestIdentity("test-id", "test-type")
	if err != nil {
		t.Fatalf("Failed to create test identity B: %v", err)
	}

	// Modify identityB to match identityA's values
	identityB.ID = identityA.ID
	identityB.PublicKey = identityA.PublicKey
	identityB.Hash = identityA.Hash
	identityB.Signatures = identityA.Signatures
	identityB.Bytes = identityA.Bytes

	if !IsEqual(identityA, identityB) {
		t.Fatal("Expected IsEqual to return true for identical identities")
	}

	// Modify one field to make them unequal
	identityB.ID = "different-id"
	if IsEqual(identityA, identityB) {
		t.Fatal("Expected IsEqual to return false for differing identities")
	}
}

func TestEncodeDecodeIdentity(t *testing.T) {
	identity, err := createTestIdentity("test-id", "test-type")
	if err != nil {
		t.Fatalf("Failed to create test identity: %v", err)
	}

	// Test EncodeIdentity
	hash, bytes, err := EncodeIdentity(*identity)
	if err != nil {
		t.Fatalf("Failed to encode identity: %v", err)
	}
	if hash == "" {
		t.Fatal("Expected non-empty hash from EncodeIdentity")
	}
	if len(bytes) == 0 {
		t.Fatal("Expected non-empty bytes from EncodeIdentity")
	}

	// Test DecodeIdentity
	decodedIdentity, err := DecodeIdentity(bytes)
	if err != nil {
		t.Fatalf("Failed to decode identity: %v", err)
	}

	// Ensure the decoded identity matches the original
	if !IsEqual(identity, decodedIdentity) {
		t.Fatal("Expected decoded identity to be equal to the original")
	}
}
