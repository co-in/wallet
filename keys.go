package wallet

type key string

func (m key) Bytes() []byte {
	return []byte(m)
}

const (
	keyEncEntropy   key = "enc:entropy"
	keyPasswordHash key = "pass:hash"
	keySalt         key = "salt"
)
