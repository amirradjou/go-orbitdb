package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"orbitdb/go-orbitdb/storage"
	"sync"
)

// KeyStore provides a key management system backed by a Storage interface.
type KeyStore struct {
	storage storage.Storage
	mu      sync.Mutex
}

// PrivateKeyData represents the serialized form of a private key.
type PrivateKeyData struct {
	Curve string `json:"curve"`
	X     string `json:"x"`
	Y     string `json:"y"`
	D     string `json:"d"`
}

const (
	// CoordinateSize is the fixed byte width of a P-256 field element or
	// scalar (X, Y, r and s). Values are always zero-padded to this width
	// when encoded: big.Int.Bytes() strips leading zeros, which would make
	// ~1 in 128 public keys and signatures shorter than expected and
	// impossible to split back into their two halves.
	CoordinateSize = 32

	// PublicKeySize is the byte length of an encoded public key (X || Y).
	PublicKeySize = 2 * CoordinateSize

	// SignatureSize is the byte length of an encoded signature (r || s).
	SignatureSize = 2 * CoordinateSize
)

// NewKeyStore initializes a new KeyStore with the provided Storage.
func NewKeyStore(storage storage.Storage) *KeyStore {
	return &KeyStore{
		storage: storage,
	}
}

// CreateKey generates a new ECDSA key pair and stores it under the given ID.
func (ks *KeyStore) CreateKey(id string) (*ecdsa.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.HasKey(id) {
		return nil, errors.New("key already exists for this ID")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Serialize the private key
	privateKeyBytes, err := SerializePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Store the serialized private key
	err = ks.storage.Put("private_"+id, privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// HasKey checks if a key exists for a given ID.
func (ks *KeyStore) HasKey(id string) bool {
	_, err := ks.storage.Get("private_" + id)
	return err == nil
}

// AddKey adds a private key to the keystore (e.g., for imported keys).
func (ks *KeyStore) AddKey(id string, privateKey *ecdsa.PrivateKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.HasKey(id) {
		return errors.New("key already exists for this ID")
	}

	// Serialize the private key
	privateKeyBytes, err := SerializePrivateKey(privateKey)
	if err != nil {
		return err
	}

	// Store the serialized private key
	return ks.storage.Put("private_"+id, privateKeyBytes)
}

// Clear removes all keys from the KeyStore.
func (ks *KeyStore) Clear() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	return ks.storage.Clear()
}

// GetKey retrieves a private key by ID from storage.
func (ks *KeyStore) GetKey(id string) (*ecdsa.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	privateKeyBytes, err := ks.storage.Get("private_" + id)
	if err != nil {
		return nil, errors.New("key not found")
	}

	// Deserialize the private key
	return DeserializePrivateKey(privateKeyBytes)
}

// SignMessage signs data using the private key associated with the given ID.
func (ks *KeyStore) SignMessage(id string, data []byte) (string, error) {
	privateKey, err := ks.GetKey(id)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(marshalSignature(r, s)), nil
}

// VerifyMessage verifies the signature against the data using the public key.
func (ks *KeyStore) VerifyMessage(publicKey ecdsa.PublicKey, data []byte, signatureHex string) (bool, error) {
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, err
	}

	r, s, err := unmarshalSignature(sigBytes)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(data)
	return ecdsa.Verify(&publicKey, hash[:], r, s), nil
}

// marshalSignature encodes r and s as two fixed-width, big-endian,
// zero-padded CoordinateSize halves (r || s).
func marshalSignature(r, s *big.Int) []byte {
	sig := make([]byte, SignatureSize)
	r.FillBytes(sig[:CoordinateSize])
	s.FillBytes(sig[CoordinateSize:])
	return sig
}

// unmarshalSignature splits a fixed-width r || s signature back into its
// two scalars. The length must be exactly SignatureSize.
func unmarshalSignature(sig []byte) (r, s *big.Int, err error) {
	if len(sig) != SignatureSize {
		return nil, nil, fmt.Errorf("invalid signature length: %d, want %d", len(sig), SignatureSize)
	}
	r = new(big.Int).SetBytes(sig[:CoordinateSize])
	s = new(big.Int).SetBytes(sig[CoordinateSize:])
	return r, s, nil
}

// EncodePublicKey returns the hex encoding of a P-256 public key as
// X || Y, each zero-padded to CoordinateSize bytes, so the result is always
// PublicKeySize bytes (2*PublicKeySize hex characters) and can be parsed
// back with ReconstructPublicKeyFromHex.
func EncodePublicKey(publicKey *ecdsa.PublicKey) (string, error) {
	if publicKey == nil || publicKey.X == nil || publicKey.Y == nil {
		return "", errors.New("public key is nil")
	}
	if publicKey.X.Sign() < 0 || publicKey.Y.Sign() < 0 ||
		publicKey.X.BitLen() > 8*CoordinateSize || publicKey.Y.BitLen() > 8*CoordinateSize {
		return "", fmt.Errorf("public key coordinate does not fit in %d bytes", CoordinateSize)
	}
	buf := make([]byte, PublicKeySize)
	publicKey.X.FillBytes(buf[:CoordinateSize])
	publicKey.Y.FillBytes(buf[CoordinateSize:])
	return hex.EncodeToString(buf), nil
}

// SerializePrivateKey serializes an ECDSA private key to a JSON-encoded byte slice.
func SerializePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	data := PrivateKeyData{
		Curve: key.Curve.Params().Name,
		X:     key.X.Text(16), // Serialize as hex string
		Y:     key.Y.Text(16),
		D:     key.D.Text(16),
	}
	return json.Marshal(data)
}

// DeserializePrivateKey reconstructs an ECDSA private key from a JSON-encoded byte slice.
func DeserializePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	var keyData PrivateKeyData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, err
	}

	curve := elliptic.P256() // Default to P256; extendable for other curves.
	if keyData.Curve != curve.Params().Name {
		return nil, errors.New("unsupported curve")
	}

	x := new(big.Int)
	y := new(big.Int)
	d := new(big.Int)

	x.SetString(keyData.X, 16)
	y.SetString(keyData.Y, 16)
	d.SetString(keyData.D, 16)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

// ReconstructPublicKeyFromHex parses a public key produced by EncodePublicKey
// (hex of X || Y, each exactly CoordinateSize bytes) back into an ecdsa.PublicKey.
func ReconstructPublicKeyFromHex(pubKeyHex string) (*ecdsa.PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, err
	}
	if len(pubKeyBytes) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d, want %d", len(pubKeyBytes), PublicKeySize)
	}
	xBytes := pubKeyBytes[:CoordinateSize]
	yBytes := pubKeyBytes[CoordinateSize:]
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return pubKey, nil
}
