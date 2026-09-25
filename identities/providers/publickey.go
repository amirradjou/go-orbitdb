package providers

import (
	"context"
	"errors"
	"fmt"

	"github.com/amirradjou/go-orbitdb/identities/identitytypes"
	"github.com/amirradjou/go-orbitdb/keystore"
)

// PublicKeyType is the type of identities created by PublicKeyProvider.
const PublicKeyType = "publickey"

// PublicKeyProvider is the default provider: the identity id is the public
// key of a keystore key named after the caller-chosen id, and that key signs
// the identity's signing key.
type PublicKeyProvider struct {
	keystore *keystore.KeyStore
}

// NewPublicKeyProvider returns a provider using keys from ks.
func NewPublicKeyProvider(ks *keystore.KeyStore) *PublicKeyProvider {
	return &PublicKeyProvider{keystore: ks}
}

// Type implements Provider.
func (p *PublicKeyProvider) Type() string { return PublicKeyType }

// GetID implements Provider. It returns the hex public key of the key stored
// under id, creating the key if needed.
func (p *PublicKeyProvider) GetID(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", errors.New("id is required")
	}
	key, err := p.keystore.GetOrCreateKey(ctx, id)
	if err != nil {
		return "", err
	}
	return keystore.PublicKey(key)
}

// SignIdentity implements Provider.
func (p *PublicKeyProvider) SignIdentity(ctx context.Context, data []byte, id string) (string, error) {
	if id == "" {
		return "", errors.New("id is required")
	}
	key, err := p.keystore.GetKey(ctx, id)
	if err != nil {
		return "", fmt.Errorf("signing key for %q not found: %w", id, err)
	}
	return keystore.SignMessage(key, data)
}

// VerifyPublicKeyIdentity checks that the key whose public key is the
// identity id signed the identity's public key and id signature.
func VerifyPublicKeyIdentity(_ context.Context, identity *identitytypes.Identity) (bool, error) {
	data := []byte(identity.PublicKey + identity.Signatures.ID)
	return keystore.VerifyMessage(identity.Signatures.PublicKey, identity.ID, data), nil
}
