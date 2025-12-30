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

	"github.com/co-in/hr32"
	"github.com/co-in/prkg"
	"github.com/co-in/storage"
)

const (
	PathCoin   = 65248
	PathWallet = 1

	PathKindExpense = 1
	PathKindChange  = 2
	PathKindQuorum  = 3

	PathCount = 0
)

type Wallet struct {
	db   storage.Database
	sec  *hr32.Config
	addr *hr32.Config

	mnemonicLen int
	rawEntropy  []byte
	encEntropy  []byte
	passHash    []byte
	salt        []byte
	dk          *prkg.DK

	dict prkg.Dictionary
	mu   sync.Mutex
}

type Option func(*Wallet)

func WithMnemonicLen(value int) Option {
	return func(m *Wallet) {
		m.mnemonicLen = value
	}
}

func WithDictionary(value prkg.Dictionary) Option {
	return func(m *Wallet) {
		m.dict = value
	}
}

func WithHRAddress(value *hr32.Config) Option {
	return func(m *Wallet) {
		m.addr = value
	}
}

func WithHRSecret(value *hr32.Config) Option {
	return func(m *Wallet) {
		m.sec = value
	}
}

func NewWallet(database storage.Database, options ...Option) (*Wallet, error) {
	hrAddr, err := hr32.Default.Clone(
		hr32.WithPrefix("addr"),
	)
	if err != nil {
		return nil, fmt.Errorf("hr32 addr: %w", err)
	}

	hrSec, err := hr32.Default.Clone(
		hr32.WithPrefix("sec"),
	)
	if err != nil {
		return nil, fmt.Errorf("hr32 sec: %w", err)
	}

	m := &Wallet{
		db: database,

		mnemonicLen: 24,
		dict:        prkg.DictEnglish,
		addr:        hrAddr,
		sec:         hrSec,
	}

	for _, option := range options {
		option(m)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	//read from the file
	if err = m.db.View(func(tx storage.TransactionRead) error {
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
		_, err = rand.Read(m.salt)
		if err != nil {
			return nil, fmt.Errorf("gen salt: %w", err)
		}

		err = m.db.Update(func(tx storage.Transaction) error {
			return tx.Set(keySalt.Bytes(), m.salt)
		})
		if err != nil {
			return nil, fmt.Errorf("save salt: %w", err)
		}
	}

	return m, nil
}

func (m *Wallet) Restore(words []string) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rawEntropy, err = m.dict.Entropy(words)
	if err != nil {
		return fmt.Errorf("entropy: %w", err)
	}

	return nil
}

func (m *Wallet) Unlock(password string) error {
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

func (m *Wallet) Lock() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dk = nil

	return nil
}

func (m *Wallet) Backup(password string) ([]string, error) {
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

func (m *Wallet) SecretByPath(path ...uint32) ([]byte, error) {
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

func (m *Wallet) NextSecret(kind uint32) ([]byte, error) {
	if kind == 0 {
		return nil, errors.New("invalid kind")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isLocked() {
		return nil, ErrWalletIsLocked
	}

	var sk []byte
	path := prkg.NewPath(PathCoin, PathWallet, kind, 0)
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

func (m *Wallet) IsProtected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.isProtected()
}

func (m *Wallet) IsEmpty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.isEmpty()
}

func (m *Wallet) IsLocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.isLocked()
}

func (m *Wallet) Close() {
	m.db.Close()
}

var regExpPassStrength = regexp.MustCompile(`^.{8,64}$`) //SP-800-63-4
func (m *Wallet) getEntropy(password string) (entropy []byte, err error) {
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

func (m *Wallet) isLocked() bool {
	return m.dk == nil
}

func (m *Wallet) isProtected() bool {
	return m.passHash != nil
}

func (m *Wallet) isEmpty() bool {
	return m.encEntropy == nil
}

func (m *Wallet) genRawEntropy() (err error) {
	m.rawEntropy, err = prkg.EntropyFromSize(m.mnemonicLen)
	if err != nil {
		return fmt.Errorf("new entropy: %w", err)
	}

	return nil
}
