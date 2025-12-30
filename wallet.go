package wallet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"github.com/co-in/prkg"
	"github.com/co-in/storage"
)

const (
	KindAddress uint32 = 1
	KindPublic  uint32 = 2
)

type Keystore struct {
	db storage.Database

	mnemonicLen int
	rawEntropy  []byte
	encEntropy  []byte
	passHash    []byte
	salt        []byte
	dk          *prkg.DK

	coinID   uint32
	walletID uint32

	dict prkg.Dictionary
	mu   sync.Mutex
}

// Option
/*
	- WithMnemonicLen
	- WithDictionary
	- WithWalletID
*/
type Option func(*Keystore)

func WithMnemonicLen(value int) Option {
	return func(m *Keystore) {
		m.mnemonicLen = value
	}
}

func WithDictionary(value prkg.Dictionary) Option {
	return func(m *Keystore) {
		m.dict = value
	}
}

func WithWalletID(value uint32) Option {
	return func(m *Keystore) {
		m.walletID = value
	}
}

func NewKeystore(database storage.Database, coinID uint32, options ...Option) (*Keystore, error) {
	m := &Keystore{
		db:          database,
		mnemonicLen: 24,
		dict:        prkg.DictEnglish,
		coinID:      coinID,
		walletID:    1,
	}

	for _, option := range options {
		option(m)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	//read from the file
	if err := m.db.View(func(tx storage.TransactionRead) error {
		var err error

		if m.salt, err = tx.Get(keySalt.Bytes()); err != nil && !errors.As(err, &storage.ErrKeyNotFound{}) {
			return fmt.Errorf("get salt: %w", err)
		}

		if m.encEntropy, err = tx.Get(keyEncEntropy.Bytes()); err != nil && !errors.As(err, &storage.ErrKeyNotFound{}) {
			return fmt.Errorf("get enc:entropy: %w", err)
		}

		if m.passHash, err = tx.Get(keyPasswordHash.Bytes()); err != nil && !errors.As(err, &storage.ErrKeyNotFound{}) {
			return fmt.Errorf("get pass:hash: %w", err)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("check wallet: %w", err)
	}

	if m.salt == nil {
		m.salt = make([]byte, 32)

		if _, err := rand.Read(m.salt); err != nil {
			return nil, fmt.Errorf("gen salt: %w", err)
		}

		if err := m.db.Update(func(tx storage.Transaction) error {
			return tx.Set(keySalt.Bytes(), m.salt)
		}); err != nil {
			return nil, fmt.Errorf("save salt: %w", err)
		}
	}

	return m, nil
}

func (m *Keystore) Link(kind uint32, key []byte, path string) error {
	var prefix []byte

	switch kind {
	case KindAddress:
		prefix = []byte("a/")
	case KindPublic:
		prefix = []byte("p/")
	default:
		return errors.New("unknown kind")
	}

	return m.db.Update(func(tx storage.Transaction) error {
		return tx.Set(append(prefix, key...), []byte(path))
	})
}

func (m *Keystore) Restore(words []string) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rawEntropy, err = m.dict.Entropy(words)
	if err != nil {
		return fmt.Errorf("entropy: %w", err)
	}

	return nil
}

func (m *Keystore) Unlock(password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entropy, err := m.getEntropy(password)
	if err != nil {
		return fmt.Errorf("getEntropy: %w", err)
	}

	//restore DK
	mnemonic, err := m.dict.Mnemonic(entropy)
	if err != nil {
		return fmt.Errorf("restore mnemonic: %w", err)
	}
	var seed [64]byte
	seed, err = m.dict.Seed(mnemonic, password)
	if err != nil {
		return fmt.Errorf("restore seed: %w", err)
	}
	if m.dk, err = prkg.NewDK(seed); err != nil {
		return fmt.Errorf("restore dk: %w", err)
	}

	return nil
}

func (m *Keystore) Lock() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dk = nil

	return nil
}

func (m *Keystore) Backup(password string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entropy, err := m.getEntropy(password)
	if err != nil {
		return nil, fmt.Errorf("getEntropy: %w", err)
	}

	mnemonic, err := m.dict.Mnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("mnemonic: %w", err)
	}

	return mnemonic, nil
}

func (m *Keystore) SecretByPath(path ...uint32) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isLocked() {
		return nil, ErrWalletIsLocked
	}

	sk, err := m.dk.Jump(path[:]...)
	if err != nil {
		return nil, fmt.Errorf("jump dk: %w", err)
	}

	return sk, nil
}

func (m *Keystore) NextSecret(kind uint32) ([]byte, error) {
	if kind == 0 {
		return nil, errors.New("invalid kind")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isLocked() {
		return nil, ErrWalletIsLocked
	}

	var sk []byte
	path := prkg.NewPath(m.coinID, m.walletID, kind, 0)
	keysCountKey := []byte(path.String())
	err := m.db.Update(func(tx storage.Transaction) error {
		//get keys count raw
		keysCount, err := tx.Get(keysCountKey)
		if err != nil {
			if !errors.As(err, &storage.ErrKeyNotFound{}) {
				return fmt.Errorf("get keys count: %w", err)
			}

			keysCount = []byte("0")
		}

		//parse keys count
		index, err := strconv.ParseUint(string(keysCount), 10, 32)
		if err != nil {
			return fmt.Errorf("parse keys count: %w", err)
		}

		//next path
		index++
		path.SetIndex(uint32(index))

		//gen next key
		if sk, err = m.dk.Jump(path[:]...); err != nil {
			return fmt.Errorf("jump dk: %w", err)
		}

		//update keys count
		err = tx.Set(keysCountKey, []byte(fmt.Sprintf("%d", index)))
		if err != nil {
			return fmt.Errorf("set keys count: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("update: %w", err)
	}

	return sk, nil
}

func (m *Keystore) IsProtected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.isProtected()
}

func (m *Keystore) IsEmpty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.isEmpty()
}

func (m *Keystore) IsLocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.isLocked()
}

func (m *Keystore) Close() {
	m.db.Close()
}

var regExpPassStrength = regexp.MustCompile(`^.{8,64}$`) //SP-800-63-4
func (m *Keystore) getEntropy(password string) (entropy []byte, err error) {
	if !regExpPassStrength.MatchString(password) {
		return nil, errors.New("weak password [8-64] symbols required")
	}

	salt := sha256.Sum256(append([]byte(password), m.salt...))
	ph := sha256.Sum256(append(salt[:], []byte(password)...))

	//set password flow
	if !m.isProtected() {
		if err = m.db.Update(func(tx storage.Transaction) error {
			return tx.Set(keyPasswordHash.Bytes(), ph[:])
		}); err != nil {
			return nil, fmt.Errorf("set pass:hash: %w", err)
		}

		m.passHash = ph[:]
	}

	if !bytes.Equal(m.passHash, ph[:]) {
		return nil, errors.New("invalid password")
	}

	crypt, err := NewCrypt(salt[:])
	if err != nil {
		return nil, fmt.Errorf("NewCrypt: %w", err)
	}

	//not restored, generate new
	if m.isEmpty() {
		//generate entropy
		if m.rawEntropy == nil {
			if err = m.genRawEntropy(); err != nil {
				return nil, fmt.Errorf("generate entropy: %w", err)
			}
		}

		//encode entropy
		m.encEntropy, err = crypt.Encrypt(m.rawEntropy)

		//raw entropy is not needed anymore
		m.rawEntropy = nil

		//save encoded entropy
		if err = m.db.Update(func(tx storage.Transaction) error {
			return tx.Set(keyEncEntropy.Bytes(), m.encEntropy)
		}); err != nil {
			return nil, fmt.Errorf("set enc:entropy: %w", err)
		}
	}

	//decode saved entropy
	entropy, err = crypt.Decrypt(m.encEntropy)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return entropy, nil
}

func (m *Keystore) isLocked() bool {
	return m.dk == nil
}

func (m *Keystore) isProtected() bool {
	return m.passHash != nil
}

func (m *Keystore) isEmpty() bool {
	return m.encEntropy == nil
}

func (m *Keystore) genRawEntropy() (err error) {
	m.rawEntropy, err = prkg.EntropyFromSize(m.mnemonicLen)
	if err != nil {
		return fmt.Errorf("new entropy: %w", err)
	}

	return nil
}
