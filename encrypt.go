package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Iter is the iteration count for pbkdf2.
// Using a higher iteration count will increase the cost of an exhaustive search but will also make derivation proportionally slower.
var Iter = 500

// Encrypt byte using string passphrase into a string
// `iv.salt.encrypted` which each piece (iv, salt, encrypted) is
// base64 encoded. Can be decrypted using Decrypt.
func Encrypt(plaintext []byte, passphrase string) string {
	encrypted, salt, iv := EncryptByte(plaintext, []byte(passphrase))
	return fmt.Sprintf("%s.%s.%s", base64.URLEncoding.EncodeToString(iv), base64.URLEncoding.EncodeToString(salt), base64.URLEncoding.EncodeToString(encrypted))
}

// Decrypt string of form `iv.salt.encrypted` to the byte of its original. Throws
// error if the decryption fails.
func Decrypt(encrypted string, passphrase string) (decrypted []byte, err error) {
	s := strings.Split(encrypted, ".")
	if len(s) != 3 {
		err = errors.New("incorrect decryption string")
		return
	}
	var encryptedBytes, salt, iv []byte
	encryptedBytes, err = base64.URLEncoding.DecodeString(s[2])
	if err != nil {
		return
	}
	salt, err = base64.URLEncoding.DecodeString(s[1])
	if err != nil {
		return
	}
	iv, err = base64.URLEncoding.DecodeString(s[0])
	if err != nil {
		return
	}
	decrypted, err = DecryptByte(encryptedBytes, []byte(passphrase), salt, iv)
	return
}

// EncryptByte using pdbkdf2 encryption as specified by NIST. See Section 8.2 of
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// for more information.
func EncryptByte(plaintext []byte, passphrase []byte) (encrypted []byte, salt []byte, iv []byte) {
	key, salt := deriveKey(passphrase, nil)
	iv = make([]byte, 12)

	rand.Read(iv)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	encrypted = aesgcm.Seal(nil, iv, plaintext, nil)
	return
}

// DecryptByte using pdbkdf2 decyprtion as specified by NIST to decrypt bytes based on
// a passphrase, a salt, and an IV.
func DecryptByte(data []byte, passphrase []byte, salt []byte, iv []byte) (plaintext []byte, err error) {
	key, _ := deriveKey(passphrase, salt)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	plaintext, err = aesgcm.Open(nil, iv, data, nil)
	return
}

// deriveKey derives a pbkdf2 Key and salt as specified
// by RFC2898 (http://www.ietf.org/rfc/rfc2898.txt).
func deriveKey(passphrase []byte, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		rand.Read(salt)
	}
	return pbkdf2.Key(passphrase, salt, Iter, 32, sha256.New), salt
}
