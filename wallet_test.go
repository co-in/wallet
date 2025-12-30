package wallet_test

import (
	"strings"
	"testing"

	"github.com/co-in/storage"
	"github.com/co-in/storage/badger"
	"github.com/co-in/wallet"
	sdk "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
)

var (
	mnemonicRaw = "rather knee chalk cream index dress tenant casino panther blossom benefit pool rack " +
		"flat trigger ghost disorder enroll kid brief provide pave whisper off"
	mnemonicRes = strings.Split(mnemonicRaw, " ")
	password    = "password"
	kindExpense = uint32(1)
)

func newDB(t *testing.T) (storage.Database, func()) {
	db, err := badger.NewStorage("", badger.WithSDKOption(func(options sdk.Options) sdk.Options {
		options.InMemory = true
		options.Logger = nil
		options.VLogPercentile = 0

		return options
	}))
	require.NoError(t, err)

	return db, db.Close
}

func newWallet(t *testing.T, db storage.Database, options ...wallet.Option) (*wallet.Wallet, func()) {
	w, err := wallet.NewWallet(db, 65248, options...)
	require.NoError(t, err)
	require.NotNil(t, w)

	return w, w.Close
}

func Test1(t *testing.T) {
	db, dbC := newDB(t)
	defer dbC()
	w, wC := newWallet(t, db, wallet.WithWalletID(2))
	defer wC()

	require.True(t, w.IsLocked())
	require.True(t, w.IsEmpty())
	require.False(t, w.IsProtected())

	//1. convert mnemonic to entropy (without db)
	err := w.Restore(mnemonicRes)
	require.NoError(t, err)
	require.True(t, w.IsLocked())
	require.True(t, w.IsEmpty()) //temporary entropy, wait password
	require.False(t, w.IsProtected())

	//2. encrypt entropy by password
	//3. save entropy to db
	//4. return mnemonic from entropy
	mnemonic, err := w.Backup(password)
	require.NoError(t, err)
	require.True(t, w.IsLocked())
	require.False(t, w.IsEmpty()) //entropy saved
	require.True(t, w.IsProtected())

	//5. compare mnemonic are same
	require.Equal(t, mnemonic, mnemonicRes)
}

func Test2(t *testing.T) {
	mnemonicLen := 12
	db, dbC := newDB(t)
	defer dbC()
	w, wC := newWallet(t, db, wallet.WithMnemonicLen(mnemonicLen))
	defer wC()

	//1. generate the entropy
	//2. encrypt the entropy by password
	//3. save the entropy to db
	//4. return the mnemonic from the entropy
	mnemonic, err := w.Backup(password)
	require.NoError(t, err)
	require.True(t, w.IsLocked())
	require.False(t, w.IsEmpty()) //generated random entropy
	require.True(t, w.IsProtected())

	//5. check generated mnemonic length
	require.Len(t, mnemonic, mnemonicLen)
}

func Test3(t *testing.T) {
	db, dbC := newDB(t)
	defer dbC()
	w, wC := newWallet(t, db)
	defer wC()

	//1. generate the entropy
	//2. encrypt the entropy by the password
	//3. save the entropy to the db
	//4. return the mnemonic from the entropy
	//5. restore DK from mnemonic
	err := w.Unlock(password)
	require.NoError(t, err)
	require.False(t, w.IsLocked())
	require.False(t, w.IsEmpty()) //generated random entropy
	require.True(t, w.IsProtected())

	//6. reset DK
	err = w.Lock()
	require.NoError(t, err)
	require.True(t, w.IsLocked())
	require.False(t, w.IsEmpty()) //generated random entropy
	require.True(t, w.IsProtected())
}

func Test4(t *testing.T) {
	db, dbC := newDB(t)
	defer dbC()
	w, wC := newWallet(t, db)
	defer wC()

	err := w.Unlock(password)
	require.NoError(t, err)

	sk1, err := w.NextSecret(kindExpense)
	require.NoError(t, err)
	require.NotNil(t, sk1)
	sk2, err := w.NextSecret(kindExpense)
	require.NoError(t, err)
	require.NotNil(t, sk2)
	require.NotEqual(t, sk1, sk2)

	err = w.Lock()
	require.NoError(t, err)

	sk, err := w.NextSecret(kindExpense)
	require.ErrorIs(t, wallet.ErrWalletIsLocked, err)
	require.Nil(t, sk)
}
