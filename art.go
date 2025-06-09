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

// StageKeySize is the size of the stage key (group key) in bytes
const StageKeySize = 32

// DHKeyGen returns a private leaf key (an X25519 key)
func DHKeyGen() (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519() // multiple invocations of this function return the same value
	return curve.GenerateKey(rand.Reader)
}

// KeyExchangeKeyGen returns a private setup key (an X25519).  The current
// implementation is simply a wrapper for [DHKeyGen].
func KeyExchangeKeyGen() (*ecdh.PrivateKey, error) {
	return DHKeyGen()
}

// KeyExchange performs an unauthetnicated Diffie-Hellman computation,
// returning the shared secret.
func KeyExchange(sk *ecdh.PrivateKey, pk *ecdh.PublicKey) ([]byte, error) {
	return sk.ECDH(pk)
}

// StageKeyInfo represents the input data to the KDF that produces the next
// stage key.
type StageKeyInfo struct {
	// PrevStageKey is the previous stage key
	PrevStageKey []byte

	// TreeSecretKey is the secret (private) key for the ART root
	TreeSecretKey []byte

	// TreeKeys are the breadth-first list of ART public keys
	TreeKeys [][]byte

	// IKeys is the list of identity (ed25519) public keys for each member
	IKeys [][]byte
}

// GetIKM serializes the previous stage key, the ART secret root key, and the
// ART public tree.  This information is the key for the HMAC-based KDF.
func (skInfo *StageKeyInfo) GetIKM() []byte {
	// Secret in HKDF = (prevStageKey + treeSecret + serializedTree)
	ikm := make([]byte, 0)
	ikm = append(ikm, skInfo.PrevStageKey...)
	ikm = append(ikm, skInfo.TreeSecretKey...)
	ikm = append(ikm, bytes.Join(skInfo.TreeKeys, []byte(""))...)

	return ikm
}

// GetInfo returns a serialization of the members' identity (ed25519) keys.
// This information is the context info for the HMAC-based KDF.
func (skInfo *StageKeyInfo) GetInfo() []byte {
	return bytes.Join(skInfo.IKeys, []byte(""))
}

// DeriveStageKey derives the new stage key (group key).

// This function corresponds to the DeriveStageKey function in Algorithm 2 of
// the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// Compute all the private keys from the given leafKey up to the root.
//
// This function corresponds to the PathNodeKeys function in Algorithm 2 of
// the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// CreateUpdateMessage computes an Update message.  The index parameter is the
// index of the group member performing the update, and pathKeys is the list of
// private keys up to the root that the user's update has changed.  (This
// function will in turn compute the corresponding public keys.)
func CreateUpdateMessage(index int, pathKeys []*ecdh.PrivateKey) UpdateMessage {
	marshalledPathKeys := marshallPublicKeys(pathKeys)
	updateMsg := UpdateMessage{
		Idx:            index,
		PathPublicKeys: marshalledPathKeys,
	}
	return updateMsg
}

// GetPublickKeys returns the list of public keys corresponding to the input
// list of private keys.
func GetPublicKeys(pathKeys []*ecdh.PrivateKey) []*ecdh.PublicKey {
	publicPathKeys := make([]*ecdh.PublicKey, 0, len(pathKeys))
	for _, key := range pathKeys {
		publicPathKeys = append(publicPathKeys, key.PublicKey())
	}
	return publicPathKeys
}

// UnmarshallPublicKeys takes a list of public keys that are formated as PEM
// encodings of PXIX, ASN.1 DER form, and returns the corresponding
// *[ecdh.PublicKey]s.  The keys must be X25519 public keys.
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

// SetupGroup sets up an initial ART group.  configFile is a text file where
// each row corresponds to a group member, and there are three columns:
//
// 1. The member's name
// 2. The member's identity public key file (ed25519)
// 3. The member's empherals (setup) public key file (x25519)
//
// Pathnames can be absolute or relative; if relative, they are resolved
// relative to the config file itself.  The identity file must be a PEM
// encoding of the PKIX, ASN.1 DER form, where the PEM type is "ED25519 PUBLIC
// KEY".  The setup key must be a PEM encoding of the PKIX, ASN.1 DER form,
// where the PEM type is "X25519 PUBLIC KEY".
//
// The initiator parameter is the group member name that serves as the group's
// initiator.  This must be a member listed in the config file.  However, as a
// convenience, if initiator is the empty string, the first member in the
// config file is the initiator.
//
// This function corresponds to the SetupGroup procedure in Algorithm 1 of
// the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// ProcessSetupMessage processes a Setup Message.
//
// This function corresponds to the ProcessSetupMessage procedure in Algorithm
// 3 of the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// UpdateKey updates a member's ART leaf key.
//
// The index parameter is the member's group index number; treeStateFile is the
// path to the file storing the member's ART state.
//
// This funciton outputs the update message, the member's new ART state, and
// the previous stage (group) key.
//
// This function corresponds to the UpdateKey procedure in Algorithm
// 4 of the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// ProcessUpateMessage processes an Key Update message.
//
// The index parameter is the member's group index number; treeStateFile is the
// path to the file storing the member's ART state; updateMsgFile is the path
// to the file storing the update message, and macFile is the file storing the
// associated MAC on the update message.

// This function corresponds to the ProcessUpdateMessage procedure in Algorithm
// 5 of the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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
