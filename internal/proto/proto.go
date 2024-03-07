package proto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

type Message struct {
	IKeys    [][]byte
	EKeys    [][]byte
	Suk      []byte
	TreeKeys [][]byte
}

const StageKeySize = 32

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
	PrevStageKey  []byte
	TreeSecretKey []byte
	TreeKeys      [][]byte
	IKeys         [][]byte
}

func (skInfo *StageKeyInfo) GetIKM() []byte {
	// Secret in HKDF = (prevStageKey + treeSecret + serializedTree)
	ikm := make([]byte, 0)
	ikm = append(ikm, skInfo.PrevStageKey...)
	ikm = append(ikm, skInfo.TreeSecretKey...)
	ikm = append(ikm, bytes.Join(skInfo.TreeKeys, []byte(""))...)

	return ikm
}

func (skInfo *StageKeyInfo) GetInfo() []byte {
	return bytes.Join(skInfo.IKeys, []byte(""))
}

func DeriveStageKey(skInfo *StageKeyInfo) ([]byte, error) {
	hash := sha256.New
	ikm := skInfo.GetIKM()
	info := skInfo.GetInfo()

	hkdf := hkdf.New(hash, ikm, nil, info)
	stageKey := make([]byte, StageKeySize)
	_, err := io.ReadFull(hkdf, stageKey)
	if err != nil {
		return nil, err
	}

	return stageKey, nil
}
