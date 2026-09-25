// Package identitytypes defines the Identity record that signs OrbitDB log
// entries, and its dag-cbor encoding.
//
// It mirrors src/identities/identity.js in @orbitdb/core: an identity is the
// block {id, publicKey, signatures: {id, publicKey}, type}, addressed by the
// base58btc CID of its dag-cbor bytes.
package identitytypes

import (
	"context"
	"errors"

	"github.com/amirradjou/go-orbitdb/internal/block"
)

// Signatures are the two signatures that bind an identity together.
type Signatures struct {
	// ID is the signature of the identity id by the identity's signing key
	// (the key behind PublicKey).
	ID string
	// PublicKey is the signature of PublicKey+Signatures.ID by the key the
	// identity provider vouches for (for the publickey provider, the key
	// whose public key is the identity id).
	PublicKey string
}

// Signer signs data on behalf of an identity. Identities implements it.
type Signer interface {
	Sign(ctx context.Context, identity *Identity, data []byte) (string, error)
}

// Identity is an OrbitDB identity.
type Identity struct {
	ID         string
	PublicKey  string
	Signatures Signatures
	Type       string

	// Hash is the base58btc CID of Bytes.
	Hash string
	// Bytes is the dag-cbor encoding of the identity.
	Bytes []byte

	signer Signer
}

// New validates the fields and returns an encoded identity. signer may be
// nil for identities that are only verified, never used to sign (for
// example identities decoded from peers).
func New(id, publicKey string, signatures Signatures, typ string, signer Signer) (*Identity, error) {
	switch {
	case id == "":
		return nil, errors.New("identity id is required")
	case publicKey == "":
		return nil, errors.New("invalid public key")
	case signatures.ID == "":
		return nil, errors.New("signature of id is required")
	case signatures.PublicKey == "":
		return nil, errors.New("signature of publicKey+id is required")
	case typ == "":
		return nil, errors.New("identity type is required")
	}
	identity := &Identity{
		ID:         id,
		PublicKey:  publicKey,
		Signatures: signatures,
		Type:       typ,
		signer:     signer,
	}
	hash, data, err := Encode(identity)
	if err != nil {
		return nil, err
	}
	identity.Hash = hash
	identity.Bytes = data
	return identity, nil
}

// Encode returns the hash and dag-cbor bytes of identity.
func Encode(identity *Identity) (hash string, data []byte, err error) {
	return block.Encode(map[string]any{
		"id":        identity.ID,
		"publicKey": identity.PublicKey,
		"signatures": map[string]any{
			"id":        identity.Signatures.ID,
			"publicKey": identity.Signatures.PublicKey,
		},
		"type": identity.Type,
	})
}

// Decode parses an identity block. The result has no signer.
func Decode(data []byte) (*Identity, error) {
	v, err := block.Decode(data)
	if err != nil {
		return nil, err
	}
	m, err := block.Map(v)
	if err != nil {
		return nil, err
	}
	sigs, err := block.Map(m["signatures"])
	if err != nil {
		return nil, errors.New("identity: signatures object is required")
	}
	// Missing fields decode as "" and are reported by New's validation.
	id, _ := m["id"].(string)
	publicKey, _ := m["publicKey"].(string)
	typ, _ := m["type"].(string)
	idSig, _ := sigs["id"].(string)
	pkSig, _ := sigs["publicKey"].(string)
	return New(id, publicKey, Signatures{ID: idSig, PublicKey: pkSig}, typ, nil)
}

// Sign signs data with the identity's private key.
func (i *Identity) Sign(ctx context.Context, data []byte) (string, error) {
	if i.signer == nil {
		return "", errors.New("identity cannot sign: it has no signer")
	}
	return i.signer.Sign(ctx, i, data)
}

// WithSigner returns a copy of i that signs through signer.
func (i *Identity) WithSigner(signer Signer) *Identity {
	c := *i
	c.signer = signer
	return &c
}

// IsIdentity reports whether every field of identity is set.
func IsIdentity(identity *Identity) bool {
	return identity != nil &&
		identity.ID != "" &&
		identity.Hash != "" &&
		len(identity.Bytes) > 0 &&
		identity.PublicKey != "" &&
		identity.Signatures.ID != "" &&
		identity.Signatures.PublicKey != "" &&
		identity.Type != ""
}

// IsEqual reports whether a and b are the same identity.
func IsEqual(a, b *Identity) bool {
	return a != nil && b != nil &&
		a.ID == b.ID &&
		a.Hash == b.Hash &&
		a.Type == b.Type &&
		a.PublicKey == b.PublicKey &&
		a.Signatures == b.Signatures
}
