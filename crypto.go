package art

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}
