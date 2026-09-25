// Package identities creates, stores, signs with and verifies OrbitDB
// identities.
//
// It mirrors src/identities/identities.js in @orbitdb/core. Creating an
// identity for id "alice" with the default publickey provider works as
// follows:
//
//  1. the provider's key "alice" is fetched or created; its public key (hex)
//     becomes the identity id;
//  2. a signing key stored under that identity id is fetched or created; its
//     public key becomes identity.PublicKey;
//  3. the signing key signs the identity id (Signatures.ID) and the provider
//     key signs PublicKey+Signatures.ID (Signatures.PublicKey).
//
// The identity block is written to the identities storage so peers can
// fetch it by the hash entries refer to.
package identities

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/orbitdb/go-orbitdb/identities/identitytypes"
	"github.com/orbitdb/go-orbitdb/identities/providers"
	"github.com/orbitdb/go-orbitdb/keystore"
	"github.com/orbitdb/go-orbitdb/storage"
)

// DefaultKeysPath is where New keeps keys when neither Keystore nor Path is
// set.
var DefaultKeysPath = filepath.Join(".", "orbitdb", "identities")

const verifiedCacheSize = 1000

// Options configures New.
type Options struct {
	// Keystore holds the private keys. If nil, one is opened at Path.
	Keystore *keystore.KeyStore
	// Path is the keystore directory used when Keystore is nil. Defaults to
	// DefaultKeysPath.
	Path string
	// Storage holds identity blocks by hash. OrbitDB passes an LRU cache in
	// front of IPFS block storage so identities replicate between peers.
	// Defaults to an in-memory storage.
	Storage storage.Storage
}

// CreateOptions configures CreateIdentity.
type CreateOptions struct {
	// ID is the caller-chosen id the provider derives the identity from.
	ID string
	// Provider creates the identity. Defaults to a PublicKeyProvider over
	// the Identities' keystore.
	Provider providers.Provider
}

// Identities manages identities backed by a keystore.
type Identities struct {
	keystore *keystore.KeyStore
	storage  storage.Storage
	verified *lru.Cache[string, *identitytypes.Identity]
}

// New returns an Identities.
func New(opts Options) (*Identities, error) {
	ks := opts.Keystore
	if ks == nil {
		path := opts.Path
		if path == "" {
			path = DefaultKeysPath
		}
		var err error
		if ks, err = keystore.New(keystore.Options{Path: path}); err != nil {
			return nil, err
		}
	}
	st := opts.Storage
	if st == nil {
		st = storage.NewMemoryStorage()
	}
	verified, err := lru.New[string, *identitytypes.Identity](verifiedCacheSize)
	if err != nil {
		return nil, err
	}
	return &Identities{keystore: ks, storage: st, verified: verified}, nil
}

// Keystore returns the keystore identities are created from.
func (ids *Identities) Keystore() *keystore.KeyStore { return ids.keystore }

// CreateIdentity creates an identity and adds it to storage.
func (ids *Identities) CreateIdentity(ctx context.Context, opts CreateOptions) (*identitytypes.Identity, error) {
	provider := opts.Provider
	if provider == nil {
		provider = providers.NewPublicKeyProvider(ids.keystore)
	}
	if _, err := providers.GetIdentityProvider(provider.Type()); err != nil {
		return nil, fmt.Errorf("identity provider is unknown, register it with providers.UseIdentityProvider: %w", err)
	}

	id, err := provider.GetID(ctx, opts.ID)
	if err != nil {
		return nil, err
	}
	signingKey, err := ids.keystore.GetOrCreateKey(ctx, id)
	if err != nil {
		return nil, err
	}
	publicKey, err := keystore.PublicKey(signingKey)
	if err != nil {
		return nil, err
	}
	idSignature, err := keystore.SignMessage(signingKey, []byte(id))
	if err != nil {
		return nil, err
	}
	publicKeyAndIDSignature, err := provider.SignIdentity(ctx, []byte(publicKey+idSignature), opts.ID)
	if err != nil {
		return nil, err
	}

	identity, err := identitytypes.New(id, publicKey, identitytypes.Signatures{
		ID:        idSignature,
		PublicKey: publicKeyAndIDSignature,
	}, provider.Type(), ids)
	if err != nil {
		return nil, err
	}
	if err := ids.storage.Put(ctx, identity.Hash, identity.Bytes); err != nil {
		return nil, fmt.Errorf("store identity: %w", err)
	}
	return identity, nil
}

// GetIdentity returns the identity stored under hash. It may be fetched from
// peers when the storage is IPFS-backed. The identity can sign only if its
// key is in this Identities' keystore.
func (ids *Identities) GetIdentity(ctx context.Context, hash string) (*identitytypes.Identity, error) {
	data, err := ids.storage.Get(ctx, hash)
	if err != nil {
		return nil, err
	}
	identity, err := identitytypes.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode identity %s: %w", hash, err)
	}
	return identity.WithSigner(ids), nil
}

// VerifyIdentity checks both of the identity's signatures: that its signing
// key signed its id, and that its provider vouched for the signing key.
func (ids *Identities) VerifyIdentity(ctx context.Context, identity *identitytypes.Identity) (bool, error) {
	if !identitytypes.IsIdentity(identity) {
		return false, nil
	}
	if !keystore.VerifyMessage(identity.Signatures.ID, identity.PublicKey, []byte(identity.ID)) {
		return false, nil
	}
	if cached, ok := ids.verified.Get(identity.Signatures.ID); ok {
		return identitytypes.IsEqual(identity, cached), nil
	}
	verify, err := providers.GetIdentityProvider(identity.Type)
	if err != nil {
		return false, err
	}
	ok, err := verify(ctx, identity)
	if err != nil || !ok {
		return false, err
	}
	ids.verified.Add(identity.Signatures.ID, identity)
	return true, nil
}

// Sign signs data with identity's private key, which must be in the
// keystore. It implements identitytypes.Signer.
func (ids *Identities) Sign(ctx context.Context, identity *identitytypes.Identity, data []byte) (string, error) {
	key, err := ids.keystore.GetKey(ctx, identity.ID)
	if errors.Is(err, keystore.ErrNotFound) {
		return "", errors.New("private signing key not found from KeyStore")
	}
	if err != nil {
		return "", err
	}
	return keystore.SignMessage(key, data)
}

// Verify reports whether signature is publicKey's signature of data.
func (ids *Identities) Verify(signature, publicKey string, data []byte) bool {
	return keystore.VerifyMessage(signature, publicKey, data)
}
