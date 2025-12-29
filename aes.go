package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type Crypt struct {
	gcm cipher.AEAD
}

func NewCrypt(key []byte) (*Crypt, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	return &Crypt{
		gcm: gcm,
	}, nil
}

func (m *Crypt) Encrypt(decoded []byte) ([]byte, error) {
	nonce := make([]byte, m.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	return m.gcm.Seal(nonce, nonce, decoded, nil), nil
}

func (m *Crypt) Decrypt(encoded []byte) ([]byte, error) {
	nonceSize := m.gcm.NonceSize()
	if len(encoded) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := encoded[:nonceSize]
	ciphertext := encoded[nonceSize:]

	decoded, err := m.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	return decoded, nil
}
