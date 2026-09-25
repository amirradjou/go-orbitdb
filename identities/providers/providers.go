// Package providers implements identity providers, which decide what an
// identity id is and vouch for the identity's signing key.
//
// It mirrors src/identities/providers in @orbitdb/core. The built-in
// "publickey" provider is registered by default; others can be added with
// UseIdentityProvider.
package providers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/orbitdb/go-orbitdb/identities/identitytypes"
)

// Provider creates identities of one type.
type Provider interface {
	// Type is the identity type this provider creates, e.g. "publickey".
	Type() string
	// GetID returns the identity id for the caller-chosen id.
	GetID(ctx context.Context, id string) (string, error)
	// SignIdentity signs data (the identity's public key followed by its id
	// signature) on behalf of the caller-chosen id.
	SignIdentity(ctx context.Context, data []byte, id string) (string, error)
}

// VerifyFunc checks that the provider of identity.Type vouched for it.
type VerifyFunc func(ctx context.Context, identity *identitytypes.Identity) (bool, error)

var (
	mu       sync.RWMutex
	registry = map[string]VerifyFunc{PublicKeyType: VerifyPublicKeyIdentity}
)

// UseIdentityProvider registers the verifier for identities of type typ,
// replacing any existing registration.
func UseIdentityProvider(typ string, verify VerifyFunc) error {
	if typ == "" {
		return errors.New("identity provider type is required")
	}
	if verify == nil {
		return errors.New("identity provider verify function is required")
	}
	mu.Lock()
	defer mu.Unlock()
	registry[typ] = verify
	return nil
}

// GetIdentityProvider returns the verifier registered for typ.
func GetIdentityProvider(typ string) (VerifyFunc, error) {
	mu.RLock()
	defer mu.RUnlock()
	verify, ok := registry[typ]
	if !ok {
		return nil, fmt.Errorf("identity provider type %q is not supported", typ)
	}
	return verify, nil
}
