package main

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"os"

	"github.com/syslab-wm/art"
	"github.com/syslab-wm/mu"
)

func verifyMessage(publicKeyPath, msgFile, sigFile string) {
	valid, err := art.VerifySignature(publicKeyPath, msgFile, sigFile)
	if err != nil {
		mu.Fatalf("error: %v", err)
	}
	if !valid {
		mu.Fatalf("error: message signature verification failed for %v", msgFile)
	}
}

func decodeMessage(file *os.File, m *art.SetupMessage) {
	dec := json.NewDecoder(file)
	err := dec.Decode(&m)
	if err != nil {
		mu.Fatalf("error decoding message from file:", err)
	}
}

func readMessage(msgFilePath string, m *art.SetupMessage) {
	msgFile, err := os.Open(msgFilePath)
	if err != nil {
		mu.Fatalf("error opening message file:", err)
	}
	defer msgFile.Close()
	decodeMessage(msgFile, m)
}

func getSetupKey(m *art.SetupMessage) *ecdh.PublicKey {
	suk, err := art.UnmarshalPublicEKFromPEM(m.Suk)
	if err != nil {
		mu.Fatalf("failed to unmarshal public SUK")
	}
	return suk
}

func getPublicTree(m *art.SetupMessage) *art.PublicNode {
	tree, err := art.UnmarshalKeysToPublicTree(m.TreeKeys)
	if err != nil {
		mu.Fatalf("error unmarshalling the public tree keys: %v", err)
	}
	return tree
}

// derive the member's private leaf key
func deriveLeafKey(privKeyFile string, setupKey *ecdh.PublicKey) *ecdh.PrivateKey {
	leafKey, err := art.DeriveLeafKey(privKeyFile, setupKey)
	if err != nil {
		mu.Fatalf("error deriving the private leaf key: %v", err)
	}
	return leafKey
}

func deriveTreeKey(state *art.TreeState, index int) *ecdh.PrivateKey {
	// find the nodes on the copath
	copathNodes := make([]*ecdh.PublicKey, 0)
	copathNodes = art.CoPath(state.PublicTree, index, copathNodes)

	// with the leaf key, derive the private keys on the path up to the root
	pathKeys, err := art.PathNodeKeys(state.Lk, copathNodes)
	if err != nil {
		mu.Fatalf("error deriving the private path keys: %v", err)
	}

	// the initial tree key is the last key in pathKeys
	return pathKeys[len(pathKeys)-1]
}

func deriveStageKey(treeKey *ecdh.PrivateKey, m *art.SetupMessage) []byte {
	stageInfo := art.StageKeyInfo{
		PrevStageKey:  make([]byte, art.StageKeySize),
		TreeSecretKey: treeKey.Bytes(),
		IKeys:         m.IKeys,
		TreeKeys:      m.TreeKeys,
	}
	stageKey, err := art.DeriveStageKey(&stageInfo)
	if err != nil {
		mu.Fatalf("failed to derive the stage key: %v", err)
	}

	return stageKey
}

func processMessage(opts *options, state *art.TreeState) {
	var m art.SetupMessage

	verifyMessage(opts.initiatorPubIKFile, opts.setupMessageFile, opts.sigFile)
	readMessage(opts.setupMessageFile, &m)

	suk := getSetupKey(&m)
	state.PublicTree = getPublicTree(&m)
	state.Lk = deriveLeafKey(opts.privEKFile, suk)
	state.IKeys = m.IKeys
	tk := deriveTreeKey(state, opts.index)
	state.Sk = deriveStageKey(tk, &m)

	fmt.Printf("Stage key: %v\n", state.Sk)
}

func main() {
	opts := parseOptions()

	var state art.TreeState
	processMessage(opts, &state)

	art.SaveTreeState(opts.treeStateFile, &state)
}
