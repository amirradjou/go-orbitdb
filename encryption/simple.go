// Package encryption provides encryption modules for oplog.Encryption.
//
// Simple is compatible with @orbitdb/simple-encryption: a password is
// stretched with PBKDF2-SHA256 (32767 iterations, 16-byte random salt) into
// an AES-128-GCM key, and each ciphertext is salt || nonce || sealed data.
// Databases encrypted by either implementation can be read by the other.
package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	saltLength  = 16
	nonceLength = 12
	keyLength   = 16
	iterations  = 32767
	// rekeyAfter bounds how many messages are sealed under one derived key
	// before a new salt is drawn. Nonces are random for every message.
	rekeyAfter = 1 << 20
)

// Simple encrypts with a key derived from a password. It implements
// oplog.Encrypter and is safe for concurrent use.
type Simple struct {
	password string

	mu    sync.Mutex
	salt  []byte
	aead  cipher.AEAD
	count int

	// keys caches derived keys by salt, since deriving one is deliberately
	// slow and every entry of a peer usually shares a salt.
	keys *lru.Cache[string, cipher.AEAD]
}

// NewSimple returns an encrypter for password.
func NewSimple(password []byte) (*Simple, error) {
	keys, err := lru.New[string, cipher.AEAD](256)
	if err != nil {
		return nil, err
	}
	return &Simple{password: string(password), keys: keys}, nil
}

func (s *Simple) derive(salt []byte) (cipher.AEAD, error) {
	if aead, ok := s.keys.Get(string(salt)); ok {
		return aead, nil
	}
	key, err := pbkdf2.Key(sha256.New, s.password, salt, iterations, keyLength)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s.keys.Add(string(salt), aead)
	return aead, nil
}

// Encrypt implements oplog.Encrypter. Each call uses a fresh random nonce.
func (s *Simple) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	if s.aead == nil || s.count >= rekeyAfter {
		salt := make([]byte, saltLength)
		if _, err := rand.Read(salt); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		aead, err := s.derive(salt)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		s.salt, s.aead, s.count = salt, aead, 0
	}
	s.count++
	salt, aead := s.salt, s.aead
	s.mu.Unlock()

	out := make([]byte, saltLength+nonceLength, saltLength+nonceLength+len(plaintext)+aead.Overhead())
	copy(out, salt)
	if _, err := rand.Read(out[saltLength:]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[saltLength:], plaintext, nil), nil
}

// Decrypt implements oplog.Encrypter.
func (s *Simple) Decrypt(_ context.Context, data []byte) ([]byte, error) {
	if len(data) < saltLength+nonceLength+16 {
		return nil, errors.New("encryption: ciphertext too short")
	}
	aead, err := s.derive(data[:saltLength])
	if err != nil {
		return nil, err
	}
	nonce := data[saltLength : saltLength+nonceLength]
	plaintext, err := aead.Open(nil, nonce, data[saltLength+nonceLength:], nil)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}
	return plaintext, nil
}
