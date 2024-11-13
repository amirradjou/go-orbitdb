package identities

import (
	"errors"
	"orbitdb/go-orbitdb/identities/identitytypes"
	"orbitdb/go-orbitdb/identities/providers"
)

// Identities manages a collection of identities
type Identities struct {
	storage  map[string]*identitytypes.Identity
	provider Provider
}

// NewIdentities initializes the identities manager with a specific provider.
func NewIdentities(providerType string) (*Identities, error) {
	provider, err := GetProvider(providerType)
	if err != nil {
		return nil, err
	}

	return &Identities{
		storage:  make(map[string]*identitytypes.Identity),
		provider: provider,
	}, nil
}

// CreateIdentity generates a new identity using the selected provider.
func (ids *Identities) CreateIdentity(id string) (*identitytypes.Identity, error) {
	identity, err := ids.provider.CreateIdentity(id)
	if err != nil {
		return nil, err
	}

	if !identitytypes.IsIdentity(identity) {
		return nil, errors.New("invalid identity created")
	}

	// Store the identity in the storage map
	ids.storage[identity.Hash] = identity
	return identity, nil
}

// VerifyIdentity verifies the provided identity.
func (ids *Identities) VerifyIdentity(identity *identitytypes.Identity) bool {
	verified, _ := ids.provider.VerifyIdentity(identity)
	return verified
}

// Sign signs the provided data using the identity's private key.
func (ids *Identities) Sign(identity *identitytypes.Identity, data []byte) (string, error) {
	if identity.PrivateKey == nil {
		return "", errors.New("private signing key not found for identity")
	}
	return identity.Sign(data)
}

// Verify verifies the provided signature against the data and public key.
func (ids *Identities) Verify(signature string, identity *identitytypes.Identity, data []byte) bool {
	return identity.Verify(signature, data)
}

// init registers the default provider.
func init() {
	RegisterProvider(providers.NewPublicKeyProvider())
}
