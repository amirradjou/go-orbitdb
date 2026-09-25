// Package keystore manages the private keys OrbitDB identities sign with.
//
// It mirrors src/key-store.js in @orbitdb/core: keys are secp256k1 keys from
// go-libp2p's crypto package, stored as their 32 raw bytes under
// "private_<id>", public keys are exchanged as the hex of their 33-byte
// compressed form, and signatures are the hex of a DER-encoded ECDSA
// signature over SHA-256 of the message. Signing is deterministic
// (RFC 6979), so Go and JavaScript produce byte-identical signatures for the
// same key and message.
package keystore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/crypto"

	"github.com/amirradjou/go-orbitdb/storage"
)

// DefaultPath is where New keeps keys when neither Storage nor Path is set.
const DefaultPath = "./keystore"

const (
	keyPrefix     = "private_"
	keyCacheSize  = 1000
	verifiedLimit = 1000
)

// ErrNotFound is returned by GetKey when the keystore has no key for an id.
var ErrNotFound = errors.New("keystore: key not found")

// Options configures New.
type Options struct {
	// Storage holds the keys. If nil, New uses an LRU cache in front of a
	// LevelStorage at Path.
	Storage storage.Storage
	// Path is the LevelDB directory used when Storage is nil. Defaults to
	// DefaultPath.
	Path string
}

// KeyStore stores private keys by id.
type KeyStore struct {
	storage storage.Storage
	cache   *lru.Cache[string, crypto.PrivKey]
	mu      sync.Mutex // serialises CreateKey/AddKey
}

// New opens a keystore.
func New(opts Options) (*KeyStore, error) {
	st := opts.Storage
	if st == nil {
		path := opts.Path
		if path == "" {
			path = DefaultPath
		}
		level, err := storage.NewLevelStorage(path)
		if err != nil {
			return nil, err
		}
		cache, err := storage.NewLRUStorage(keyCacheSize)
		if err != nil {
			return nil, err
		}
		st = storage.NewComposedStorage(cache, level)
	}
	cache, err := lru.New[string, crypto.PrivKey](keyCacheSize)
	if err != nil {
		return nil, err
	}
	return &KeyStore{storage: st, cache: cache}, nil
}

// HasKey reports whether a key is stored for id.
func (ks *KeyStore) HasKey(ctx context.Context, id string) (bool, error) {
	if id == "" {
		return false, errors.New("keystore: id needed to check a key")
	}
	if ks.cache.Contains(id) {
		return true, nil
	}
	_, err := ks.storage.Get(ctx, keyPrefix+id)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// AddKey stores key under id, replacing any key already stored for it.
func (ks *KeyStore) AddKey(ctx context.Context, id string, key crypto.PrivKey) error {
	if id == "" {
		return errors.New("keystore: id needed to add a key")
	}
	raw, err := key.Raw()
	if err != nil {
		return fmt.Errorf("keystore: marshal key: %w", err)
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err := ks.storage.Put(ctx, keyPrefix+id, raw); err != nil {
		return err
	}
	ks.cache.Add(id, key)
	return nil
}

// CreateKey generates a secp256k1 key and stores it under id. Like
// @orbitdb/core it replaces any key already stored for id; callers that
// want get-or-create should call GetKey first.
func (ks *KeyStore) CreateKey(ctx context.Context, id string) (crypto.PrivKey, error) {
	if id == "" {
		return nil, errors.New("keystore: id needed to create a key")
	}
	priv, _, err := crypto.GenerateSecp256k1Key(nil)
	if err != nil {
		return nil, err
	}
	if err := ks.AddKey(ctx, id, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

// GetKey returns the key stored for id, or an error wrapping ErrNotFound.
func (ks *KeyStore) GetKey(ctx context.Context, id string) (crypto.PrivKey, error) {
	if id == "" {
		return nil, errors.New("keystore: id needed to get a key")
	}
	if key, ok := ks.cache.Get(id); ok {
		return key, nil
	}
	raw, err := ks.storage.Get(ctx, keyPrefix+id)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	key, err := UnmarshalPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("keystore: key %s: %w", id, err)
	}
	ks.cache.Add(id, key)
	return key, nil
}

// GetOrCreateKey returns the key stored for id, creating one if there is
// none.
func (ks *KeyStore) GetOrCreateKey(ctx context.Context, id string) (crypto.PrivKey, error) {
	key, err := ks.GetKey(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return ks.CreateKey(ctx, id)
	}
	return key, err
}

// Clear removes every key.
func (ks *KeyStore) Clear(ctx context.Context) error {
	ks.cache.Purge()
	return ks.storage.Clear(ctx)
}

// Close closes the underlying storage.
func (ks *KeyStore) Close() error {
	ks.cache.Purge()
	return ks.storage.Close()
}

// PublicKey returns the hex encoding of key's raw public key, the form
// identities and entries carry.
func PublicKey(key crypto.PrivKey) (string, error) {
	raw, err := key.GetPublic().Raw()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// UnmarshalPrivateKey parses a raw private key the way @libp2p/crypto's
// privateKeyFromRaw does: 32 bytes is secp256k1, 64 bytes is Ed25519 and
// anything else is tried as a PKCS#1 RSA key.
func UnmarshalPrivateKey(raw []byte) (crypto.PrivKey, error) {
	switch len(raw) {
	case 32:
		return crypto.UnmarshalSecp256k1PrivateKey(raw)
	case 64:
		return crypto.UnmarshalEd25519PrivateKey(raw)
	}
	return crypto.UnmarshalRsaPrivateKey(raw)
}

// UnmarshalPublicKey parses a raw public key the way @libp2p/crypto's
// publicKeyFromRaw does: 32 bytes is Ed25519, 33 bytes is compressed
// secp256k1 and anything else is tried as a DER (PKIX) ECDSA or RSA key.
func UnmarshalPublicKey(raw []byte) (crypto.PubKey, error) {
	switch len(raw) {
	case 32:
		return crypto.UnmarshalEd25519PublicKey(raw)
	case 33:
		return crypto.UnmarshalSecp256k1PublicKey(raw)
	}
	if key, err := crypto.UnmarshalECDSAPublicKey(raw); err == nil {
		return key, nil
	}
	return crypto.UnmarshalRsaPublicKey(raw)
}

// SignMessage signs data with key and returns the hex-encoded signature.
func SignMessage(key crypto.PrivKey, data []byte) (string, error) {
	if key == nil {
		return "", errors.New("keystore: no signing key given")
	}
	if len(data) == 0 {
		return "", errors.New("keystore: given input data was empty")
	}
	sig, err := key.Sign(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

type verified struct {
	publicKey string
	data      string
}

// verifiedCache remembers recently verified signatures, as @orbitdb/core
// does, so re-verifying the same entry or identity is a map lookup.
var verifiedCache = mustLRU[string, verified](verifiedLimit)

func mustLRU[K comparable, V any](size int) *lru.Cache[K, V] {
	c, err := lru.New[K, V](size)
	if err != nil {
		panic(err)
	}
	return c
}

// VerifyMessage reports whether signature (hex) is a valid signature of data
// by publicKey (hex of the raw public key). Malformed input verifies as
// false.
func VerifyMessage(signature, publicKey string, data []byte) bool {
	if signature == "" || publicKey == "" || len(data) == 0 {
		return false
	}
	if v, ok := verifiedCache.Get(signature); ok {
		return v.publicKey == publicKey && v.data == string(data)
	}
	if !verifySignature(signature, publicKey, data) {
		return false
	}
	verifiedCache.Add(signature, verified{publicKey: publicKey, data: string(data)})
	return true
}

func verifySignature(signature, publicKey string, data []byte) bool {
	rawKey, err := hex.DecodeString(publicKey)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	key, err := UnmarshalPublicKey(rawKey)
	if err != nil {
		return false
	}
	ok, err := key.Verify(data, sig)
	return err == nil && ok
}
