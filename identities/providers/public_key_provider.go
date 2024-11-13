package providers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"orbitdb/go-orbitdb/identities/identitytypes"
)

// PublicKeyProvider is a simple provider using public key-based identities.
type PublicKeyProvider struct{}

// Type returns the provider type.
func (p *PublicKeyProvider) Type() string {
	return "publickey"
}

// createHardcodedKeyPair creates a fixed ECDSA private key for hardcoded testing.
func createHardcodedKeyPair() *ecdsa.PrivateKey {
	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = elliptic.P256()

	privateKey.D, _ = new(big.Int).SetString("5e5d9e0a44685aee2282a44d2d3e9a1b", 16)
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())

	return privateKey
}

// CreateIdentity generates a new Identity instance using the hardcoded ECDSA private key.
func (p *PublicKeyProvider) CreateIdentity(id string) (*identitytypes.Identity, error) {
	privateKey := createHardcodedKeyPair()

	// Convert the public key to a hex string
	publicKey := hex.EncodeToString(append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...))

	// Sign the ID to create a valid `idSignature`
	idSignature, err := signData(privateKey, []byte(id))
	if err != nil {
		return nil, err
	}

	// Sign the public key to create a valid `publicKeySignature`
	publicKeySignature, err := signData(privateKey, []byte(publicKey))
	if err != nil {
		return nil, err
	}

	// Create the identity instance with Type set to "publickey" and dummy signatures
	identity := &identitytypes.Identity{
		ID:         id,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Signatures: map[string]string{
			"id":        idSignature,
			"publicKey": publicKeySignature,
		},
		Type: p.Type(),
	}

	// Encode identity to generate hash and bytes representation
	hash, bytes, err := identitytypes.EncodeIdentity(*identity)
	if err != nil {
		return nil, err
	}
	identity.Hash = hash
	identity.Bytes = bytes

	return identity, nil
}

// VerifyIdentity checks and verifies the given identity, ensuring it has all required fields
// and that the signatures are valid.
func (p *PublicKeyProvider) VerifyIdentity(identity *identitytypes.Identity) (bool, error) {
	// Check that the identity has all necessary fields populated
	if !identitytypes.IsIdentity(identity) {
		return false, errors.New("identity is missing required fields")
	}

	// Verify the ID signature
	idSignature, hasIdSig := identity.Signatures["id"]
	if !hasIdSig || !p.Verify(identity, idSignature, []byte(identity.ID)) {
		return false, errors.New("invalid or missing ID signature")
	}

	// Verify the public key signature
	publicKeySignature, hasPubKeySig := identity.Signatures["publicKey"]
	if !hasPubKeySig || !p.Verify(identity, publicKeySignature, []byte(identity.PublicKey)) {
		return false, errors.New("invalid or missing public key signature")
	}

	// Additional validation can be added here if needed

	return true, nil
}

// GetId retrieves or generates an ID based on the identity's public key.
func (p *PublicKeyProvider) GetId(id string) (string, error) {
	privateKey := createHardcodedKeyPair() // Replace with keystore logic in the future
	publicKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	return hex.EncodeToString(publicKey), nil
}

// Sign signs data using the identity's private key.
func (p *PublicKeyProvider) Sign(data string, identity *identitytypes.Identity) (string, error) {
	return identity.Sign([]byte(data))
}

// Verify verifies the identity signature.
func (p *PublicKeyProvider) Verify(identity *identitytypes.Identity, signature string, data []byte) bool {
	return identity.Verify(signature, data)
}

// NewPublicKeyProvider creates a new instance of PublicKeyProvider.
func NewPublicKeyProvider() *PublicKeyProvider {
	return &PublicKeyProvider{}
}

func signData(privateKey *ecdsa.PrivateKey, data []byte) (string, error) {
	// Hash the data to create a deterministic signature
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	// Encode the signature as a hex string
	return hex.EncodeToString(r.Bytes()) + hex.EncodeToString(s.Bytes()), nil
}
