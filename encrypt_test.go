package encryption

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func BenchmarkEncryption(b *testing.B) {
	for n := 0; n < b.N; n++ {
		Encrypt([]byte("hello, world"), "secret passphrase")
	}
}
func BenchmarkDecryption(b *testing.B) {
	encrypted := Encrypt([]byte("hello, world"), "secret passphrase")
	for n := 0; n < b.N; n++ {
		Decrypt(encrypted, "secret passphrase")
	}
}

func TestEncryption(t *testing.T) {
	encrypted := Encrypt([]byte("hello, world"), "secret passphrase")
	decrypted, err := Decrypt(encrypted, "secret passphrase")
	assert.Nil(t, err)
	assert.Equal(t, []byte("hello, world"), decrypted)
	encrypted2 := Encrypt([]byte("hello, world"), "secret passphrase")
	assert.NotEqual(t, encrypted, encrypted2)

	decrypted, err = Decrypt(encrypted, "wrong passphrase")
	assert.NotNil(t, err)
}
