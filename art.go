package art

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/syslab-wm/art/internal/keyutl"
	"golang.org/x/crypto/hkdf"
)

type SetupMessage struct {
	IKeys    [][]byte `json:"iKeys"`
	EKeys    [][]byte `json:"eKeys"`
	Suk      []byte   `json:"suk"`
	TreeKeys [][]byte `json:"treeKeys"`
}

type UpdateMessage struct {
	Idx            int
	PathPublicKeys [][]byte
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

//

// prev sk, current tk, IDs, Public Tree
func DeriveStageKey(skInfo *StageKeyInfo) ([]byte, error) {
	hash := sha256.New
	ikm := skInfo.GetIKM()   // HKDF secret
	info := skInfo.GetInfo() // HKDF info

	hkdf := hkdf.New(hash, ikm, nil, info) // nil salt
	stageKey := make([]byte, StageKeySize)
	_, err := io.ReadFull(hkdf, stageKey)
	if err != nil {
		return nil, err
	}

	return stageKey, nil
}

func PathNodeKeys(leafKey *ecdh.PrivateKey, copathKeys []*ecdh.PublicKey) (
	[]*ecdh.PrivateKey, error) {
	pathKeys := make([]*ecdh.PrivateKey, 0)
	pathKeys = append(pathKeys, leafKey)

	// starting at the "bottom" of the copath and working up
	for i := 0; i < len(copathKeys); i++ {
		raw, err := pathKeys[i].ECDH(copathKeys[len(copathKeys)-i-1])
		if err != nil {
			return nil, fmt.Errorf("ECDH for node failed: %v", err)
		}

		key, err := keyutl.UnmarshalPrivateX25519FromRaw(raw)
		if err != nil {
			return nil, fmt.Errorf("can't unmarshal private x25519 key for node: %v", err)
		}

		pathKeys = append(pathKeys, key)
	}

	return pathKeys, nil
}
