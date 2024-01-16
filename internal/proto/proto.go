package proto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func DHKeyGen() (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519() // multiple invocations of this function return the same value
	return curve.GenerateKey(rand.Reader)
}

func KeyExchangeKeyGen() (*ecdh.PrivateKey, error) {
	return DHKeyGen()
}

/* the unauthenticated KeyExchange is just SUK^ek or EK^suk */
func KeyExchange(sk *ecdh.PrivateKey, pk *ecdh.PublicKey) ([]byte, error) {
	return sk.ECDH(pk)
}

type StageKeyInfo struct {
	IKeys    [][]byte
	TreeKeys [][]byte
}

/*
 * encoding the stage key info struct into a single byte stream
 * can't use encoding/gob because the byte streams aren't guaranteed to be equivalent
 * across different encoders
 */
func (info *StageKeyInfo) ToBytes() []byte {
	a := make([][]byte, 0)
	a = append(a, bytes.Join(info.IKeys, []byte(" ")))
	a = append(a, bytes.Join(info.TreeKeys, []byte(" ")))
	b := bytes.Join(a, []byte(" "))
	return b
}

// Returns 32 bytes
func DeriveStageKey(tk *ecdh.PrivateKey, info *StageKeyInfo) ([]byte, error) {
	hash := sha256.New
	// secret is tree key
	// info should be struct with: array of ids & array of public key nodes
	hkdf := hkdf.New(hash, tk.Bytes(), nil, info.ToBytes())
	stageKey := make([]byte, 32)
	_, err := io.ReadFull(hkdf, stageKey)
	if err != nil {
		return nil, err
	}
	return stageKey, nil
}
