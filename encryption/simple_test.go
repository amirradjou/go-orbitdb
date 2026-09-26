package encryption_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/orbitdb/go-orbitdb/encryption"
	"github.com/orbitdb/go-orbitdb/internal/testutil"
)

func TestDecryptsJavaScriptCiphertexts(t *testing.T) {
	cases := testutil.JSVectors(t).SimpleEncryption
	require.NotEmpty(t, cases)
	for _, c := range cases {
		enc, err := encryption.NewSimple([]byte(c.Password))
		require.NoError(t, err)
		got, err := enc.Decrypt(context.Background(), c.Ciphertext)
		require.NoError(t, err, "password %q", c.Password)
		require.True(t, bytes.Equal(c.Plaintext, got), "password %q", c.Password)
	}
}

func TestRoundTripAndFreshNonces(t *testing.T) {
	ctx := context.Background()
	enc, err := encryption.NewSimple([]byte("secret"))
	require.NoError(t, err)
	a, err := enc.Encrypt(ctx, []byte("same"))
	require.NoError(t, err)
	b, err := enc.Encrypt(ctx, []byte("same"))
	require.NoError(t, err)
	require.Equal(t, a[:16], b[:16], "the salt (and so the derived key) is reused")
	require.NotEqual(t, a[16:28], b[16:28], "every message gets its own nonce")

	for _, ct := range [][]byte{a, b} {
		pt, err := enc.Decrypt(ctx, ct)
		require.NoError(t, err)
		require.Equal(t, []byte("same"), pt)
	}

	other, err := encryption.NewSimple([]byte("secret"))
	require.NoError(t, err)
	pt, err := other.Decrypt(ctx, a)
	require.NoError(t, err, "another instance with the same password decrypts")
	require.Equal(t, []byte("same"), pt)
}

func TestRejectsWrongPasswordAndTampering(t *testing.T) {
	ctx := context.Background()
	enc, err := encryption.NewSimple([]byte("right"))
	require.NoError(t, err)
	ct, err := enc.Encrypt(ctx, []byte("data"))
	require.NoError(t, err)

	wrong, err := encryption.NewSimple([]byte("wrong"))
	require.NoError(t, err)
	_, err = wrong.Decrypt(ctx, ct)
	require.Error(t, err)

	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 1
	_, err = enc.Decrypt(ctx, tampered)
	require.Error(t, err)

	_, err = enc.Decrypt(ctx, []byte{1, 2, 3})
	require.ErrorContains(t, err, "too short")
}

func TestConcurrentUse(t *testing.T) {
	ctx := context.Background()
	enc, err := encryption.NewSimple([]byte("p"))
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				ct, err := enc.Encrypt(ctx, []byte("x"))
				require.NoError(t, err)
				pt, err := enc.Decrypt(ctx, ct)
				require.NoError(t, err)
				require.Equal(t, []byte("x"), pt)
			}
		}()
	}
	wg.Wait()
}
