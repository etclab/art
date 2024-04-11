package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/syslab-wm/art"
	"github.com/syslab-wm/art/internal/keyutl"
	"github.com/syslab-wm/mu"
)

func signMAC(sk ed25519.PrivateKey, msg art.UpdateMessage, macFile string) error {
	// converting the update message contents into a byte array
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(msg.Idx))
	MACBytes := bytes.Join(msg.PathPublicKeys, []byte(" "))
	MACBytes = append(MACBytes, bs...)

	// creating the MAC
	mac := hmac.New(sha256.New, sk)
	mac.Write(MACBytes)
	macData := mac.Sum(nil)

	// creating the MAC sig file
	err := os.WriteFile(macFile, macData, 0440)
	if err != nil {
		return fmt.Errorf("can't write MAC signature file: %v", err)
	}

	return nil
}

func getPublicKeys(pathKeys []*ecdh.PrivateKey) []*ecdh.PublicKey {
	publicPathKeys := make([]*ecdh.PublicKey, 0, len(pathKeys))
	for _, key := range pathKeys {
		publicPathKeys = append(publicPathKeys, key.PublicKey())
	}
	return publicPathKeys
}

func marshallPublicKeys(pathKeys []*ecdh.PrivateKey) [][]byte {
	marshalledPathKeys := make([][]byte, 0, len(pathKeys))

	for _, key := range pathKeys {
		marshalledKey, err := keyutl.MarshalPublicEKToPEM(key.PublicKey())
		if err != nil {
			mu.Fatalf("failed to marshal public EK: %v", err)
		}
		marshalledPathKeys = append(marshalledPathKeys, marshalledKey)
	}

	return marshalledPathKeys
}

func createUpdateMessage(index int, pathKeys []*ecdh.PrivateKey) art.UpdateMessage {
	marshalledPathKeys := marshallPublicKeys(pathKeys)
	updateMsg := art.UpdateMessage{
		Idx:            index,
		PathPublicKeys: marshalledPathKeys,
	}
	return updateMsg
}

func saveUpdateMessage(updateFile string, updateMsg *art.UpdateMessage) {
	messageFile, err := os.Create(updateFile)
	if err != nil {
		mu.Fatalf("error creating update message file: %v", err)
	}

	enc := json.NewEncoder(messageFile)
	enc.Encode(updateMsg)

	defer messageFile.Close()
}

func generateMAC(sk ed25519.PrivateKey, updateMsg art.UpdateMessage,
	macFile string) {
	// sign the message with the old stage key (symmetric signing)
	err := signMAC(sk, updateMsg, macFile)
	if err != nil {
		mu.Fatalf("error creating MAC signature: %v", err)
	}
}

func deriveStageKey(state *art.TreeState, treeSecret *ecdh.PrivateKey) {
	// TODO: this is repeated
	treeKeys, err := state.PublicTree.MarshalKeys()
	if err != nil {
		mu.Fatalf("failed to marshal the updated tree's public keys: %v", err)
	}

	stageInfo := art.StageKeyInfo{
		PrevStageKey:  state.Sk,
		TreeSecretKey: treeSecret.Bytes(),
		IKeys:         state.IKeys,
		TreeKeys:      treeKeys,
	}
	state.Sk, err = art.DeriveStageKey(&stageInfo)
	if err != nil {
		mu.Fatalf("DeriveStageKey failed: %v", err)
	}
}

func updateKey(opts *options, state *art.TreeState) {
	var err error

	// create a new leaf key
	state.Lk, err = art.DHKeyGen()
	if err != nil {
		mu.Fatalf("error creating the new leaf key: %v", err)
	}

	pathKeys := art.UpdateCoPathNodes(opts.idx, state)
	treeSecret := pathKeys[len(pathKeys)-1]

	publicPathKeys := getPublicKeys(pathKeys)

	updateMsg := createUpdateMessage(opts.idx, pathKeys)
	saveUpdateMessage(opts.updateFile, &updateMsg)
	generateMAC(state.Sk, updateMsg, opts.macFile)

	// replace the updated nodes in the full tree representation
	state.PublicTree = art.UpdatePublicTree(publicPathKeys, state.PublicTree,
		opts.idx)

	deriveStageKey(state, treeSecret)
	fmt.Printf("Stage key: %v\n", state.Sk)
}

func main() {
	opts := parseOptions()

	state := art.ReadTreeState(opts.treeStateFile)

	updateKey(opts, state)

	art.SaveTreeState(opts.treeStateFile, state)
}
