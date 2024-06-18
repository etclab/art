package art

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/etclab/mu"
	"golang.org/x/crypto/hkdf"
)

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

		key, err := UnmarshalPrivateX25519FromRaw(raw)
		if err != nil {
			return nil, fmt.Errorf("can't unmarshal private x25519 key for node: %v", err)
		}

		pathKeys = append(pathKeys, key)
	}

	return pathKeys, nil
}

func marshallPublicKeys(pathKeys []*ecdh.PrivateKey) [][]byte {
	marshalledPathKeys := make([][]byte, 0, len(pathKeys))

	for _, key := range pathKeys {
		marshalledKey, err := MarshalPublicEKToPEM(key.PublicKey())
		if err != nil {
			mu.Fatalf("failed to marshal public EK: %v", err)
		}
		marshalledPathKeys = append(marshalledPathKeys, marshalledKey)
	}

	return marshalledPathKeys
}

func CreateUpdateMessage(index int, pathKeys []*ecdh.PrivateKey) UpdateMessage {
	marshalledPathKeys := marshallPublicKeys(pathKeys)
	updateMsg := UpdateMessage{
		Idx:            index,
		PathPublicKeys: marshalledPathKeys,
	}
	return updateMsg
}

func GetPublicKeys(pathKeys []*ecdh.PrivateKey) []*ecdh.PublicKey {
	publicPathKeys := make([]*ecdh.PublicKey, 0, len(pathKeys))
	for _, key := range pathKeys {
		publicPathKeys = append(publicPathKeys, key.PublicKey())
	}
	return publicPathKeys
}

func UnmarshallPublicKeys(pathKeys [][]byte) []*ecdh.PublicKey {
	updatedPathKeys := make([]*ecdh.PublicKey, 0, len(pathKeys))
	for _, pem := range pathKeys {
		key, err := UnmarshalPublicEKFromPEM(pem)
		if err != nil {
			mu.Fatalf("failed to marshal public EK: %v", err)
		}
		updatedPathKeys = append(updatedPathKeys, key)
	}
	return updatedPathKeys
}

func SetupGroup(configFile, initiator string) (*TreeState, *SetupMessage) {

	g := &Group{}
	members := getMembersFromFile(configFile)
	g.addMembers(members)

	suk := g.generateInitiatorKeys(initiator)
	leafKeys := g.generateLeafKeys(suk)

	treeSecret, treePublic := generateTree(leafKeys)
	setupMsg := g.createSetupMessage(suk.PublicKey(), treePublic)

	var state TreeState
	state.Lk = g.initiator.leafKey
	state.PublicTree = treePublic
	state.IKeys = setupMsg.IKeys
	state.Sk = setupMsg.DeriveStageKey(treeSecret)

	return &state, setupMsg
}

func ProcessSetupMessage(index int, privEKFile, setupMsgFile, initiatorPubIKFile,
	sigFile string) *TreeState {

	VerifyMessageSignature(initiatorPubIKFile, setupMsgFile, sigFile)

	var state TreeState
	var setupMsg SetupMessage
	setupMsg.Read(setupMsgFile)
	suk := setupMsg.GetSetupKey()
	state.PublicTree = setupMsg.GetPublicTree()
	state.Lk = DeriveLeafKeyOrFail(privEKFile, suk)
	state.IKeys = setupMsg.IKeys

	treeSecret := state.DeriveTreeKey(index)
	state.Sk = setupMsg.DeriveStageKey(treeSecret)

	return &state
}

func UpdateKey(index int, treeStateFile string) (*UpdateMessage,
	*TreeState, *ed25519.PrivateKey) {

	var err error
	var state TreeState

	state.Read(treeStateFile)

	// create a new leaf key
	state.Lk, err = DHKeyGen()
	if err != nil {
		mu.Fatalf("error creating the new leaf key: %v", err)
	}

	pathKeys := UpdateCoPathNodes(index, &state)
	treeSecret := pathKeys[len(pathKeys)-1]

	publicPathKeys := GetPublicKeys(pathKeys)

	updateMsg := CreateUpdateMessage(index, pathKeys)

	// replace the updated nodes in the full tree representation
	state.PublicTree = UpdatePublicTree(publicPathKeys, state.PublicTree,
		index)

	prevStageKey := state.Sk
	state.DeriveStageKey(treeSecret)

	return &updateMsg, &state, &prevStageKey
}

func ProcessUpdateMessage(index int, treeStateFile, updateMsgFile, macFile string) *TreeState {

	var updateMsg UpdateMessage
	updateMsg.Read(updateMsgFile)

	var state TreeState
	state.Read(treeStateFile)

	updateMsg.VerifyUpdateMessage(state.Sk, macFile)

	updatedPathKeys := UnmarshallPublicKeys(updateMsg.PathPublicKeys)

	// replace the updated nodes in the full tree representation
	state.PublicTree = UpdatePublicTree(updatedPathKeys, state.PublicTree,
		updateMsg.Idx)

	pathKeys := UpdateCoPathNodes(index, &state)
	treeSecret := pathKeys[len(pathKeys)-1]

	state.DeriveStageKey(treeSecret)

	return &state
}
