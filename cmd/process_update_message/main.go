package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/syslab-wm/art"
	"github.com/syslab-wm/mu"
)

func decodeMessage(file *os.File, m *art.UpdateMessage) {
	dec := json.NewDecoder(file)
	err := dec.Decode(&m)
	if err != nil {
		mu.Fatalf("error decoding message from file:", err)
	}
}

func readUpdateMessage(msgFilePath string, updateMsg *art.UpdateMessage) {
	msgFile, err := os.Open(msgFilePath)
	if err != nil {
		mu.Fatalf("error opening message file:", err)
	}
	defer msgFile.Close()
	decodeMessage(msgFile, updateMsg)
}

func verifyMAC(sk ed25519.PrivateKey, msg art.UpdateMessage,
	macFile string) (bool, error) {
	// convert the update message contents into a byte array
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(msg.Idx))
	MACBytes := bytes.Join(msg.PathPublicKeys, []byte(" "))
	MACBytes = append(MACBytes, bs...)

	// create the MAC
	mac := art.NewHMAC(sk)
	mac.Write(MACBytes)
	macData := mac.Sum(nil)

	// get the expected MAC data from the MAC file
	expectedMAC, err := os.ReadFile(macFile)
	if err != nil {
		return false, fmt.Errorf("can't read MAC signature file: %v", err)
	}

	return hmac.Equal(macData, expectedMAC), nil
}

// verify the message signature with the current stage key
func verifyUpdateMessage(sk ed25519.PrivateKey, uMsg art.UpdateMessage,
	macFile string) {
	valid, err := verifyMAC(sk, uMsg, macFile)
	if err != nil {
		mu.Fatalf("error verifying update message file signature: %v", err)
	}
	if !valid {
		mu.Fatalf("update message failed to pass signature verification")
	}
}

func unmarshallPublicKeys(pathKeys [][]byte) []*ecdh.PublicKey {
	updatedPathKeys := make([]*ecdh.PublicKey, 0, len(pathKeys))
	for _, pem := range pathKeys {
		key, err := art.UnmarshalPublicEKFromPEM(pem)
		if err != nil {
			mu.Fatalf("failed to marshal public EK: %v", err)
		}
		updatedPathKeys = append(updatedPathKeys, key)
	}
	return updatedPathKeys
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

func processUpdateMessage(opts *options, state *art.TreeState) {
	var updateMessage art.UpdateMessage

	readUpdateMessage(opts.updateMessageFile, &updateMessage)
	verifyUpdateMessage(state.Sk, updateMessage, opts.macFile)

	updatedPathKeys := unmarshallPublicKeys(updateMessage.PathPublicKeys)

	// replace the updated nodes in the full tree representation
	state.PublicTree = art.UpdatePublicTree(updatedPathKeys, state.PublicTree,
		updateMessage.Idx)

	pathKeys := art.UpdateCoPathNodes(opts.idx, state)
	treeSecret := pathKeys[len(pathKeys)-1]

	deriveStageKey(state, treeSecret)
	fmt.Printf("Stage key: %v\n", state.Sk)
}

func main() {
	opts := parseOptions()

	state := art.ReadTreeState(opts.treeStateFile)

	processUpdateMessage(opts, state)

	art.SaveTreeState(opts.treeStateFile, state)
}
