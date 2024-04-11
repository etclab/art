package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/syslab-wm/art"
	"github.com/syslab-wm/art/internal/keyutl"
	"github.com/syslab-wm/mu"
)

const shortUsage = `Usage: process_update_message [options] INDEX \ 
	PRIVATE_EK_FILE TREE_FILE UPDATE_MSG_FILE`
const usage = `Usage: process_update_message [options] INDEX \ 
	PRIVATE_EK_FILE TREE_FILE UPDATE_MSG_FILE

Process a key update message as a group member at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is processing the key 
	update message, this index is based off the member's position in the group 
	config file, where the first entry is at index 1.

  PRIVATE_EK_KEY_FILE
	The 'current' group member's private ephemeral key file (also called a 
	prekey). This is a PEM-encoded X25519 private key.

  STATE_FILE
  	The file that contains the current state of the tree. This state will be 
	used as a starting point to process the update message. This file will be 
	overwritten with the new current state of the tree after all updates have 
	been processed.

  UPDATE_MSG_FILE
	The file that contains the update message that needs to be processed.

options:
  -mac-file UPDATE_MSG_MAC_FILE
	The update message's corresponding mac file. If omitted a default file is 
	UPDATE_MSG_FILE.mac.

  -h, -help
    Show this usage statement and exit.

examples:
  ./process_update_message 2 bob-ek.pem bob-state cici_update_key`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional arguments
	idx               int
	privEKFile        string
	treeStateFile     string
	updateMessageFile string

	// options
	macFile string
}

func decodeMessage(file *os.File, m *art.KeyUpdateMessage) {
	dec := json.NewDecoder(file)
	err := dec.Decode(&m)
	if err != nil {
		mu.Fatalf("error decoding message from file:", err)
	}
}

func readUpdateMessage(msgFilePath string, updateMsg *art.KeyUpdateMessage) {
	msgFile, err := os.Open(msgFilePath)
	if err != nil {
		mu.Fatalf("error opening message file:", err)
	}
	defer msgFile.Close()
	decodeMessage(msgFile, updateMsg)
}

func verifyMAC(sk ed25519.PrivateKey, msg art.KeyUpdateMessage,
	macFile string) (bool, error) {
	// convert the update message contents into a byte array
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(msg.Idx))
	MACBytes := bytes.Join(msg.PathPublicKeys, []byte(" "))
	MACBytes = append(MACBytes, bs...)

	// create the MAC
	mac := hmac.New(sha256.New, sk)
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
func verifyUpdateMessage(sk ed25519.PrivateKey, uMsg art.KeyUpdateMessage,
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
		key, err := keyutl.UnmarshalPublicEKFromPEM(pem)
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
	var updateMessage art.KeyUpdateMessage

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

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() != 4 {
		mu.Fatalf(shortUsage)
	}

	opts.idx, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Fatalf("error converting positional argument INDEX to int: %v", err)
	}
	opts.privEKFile = flag.Arg(1)
	opts.treeStateFile = flag.Arg(2)
	opts.updateMessageFile = flag.Arg(3)

	if opts.macFile == "" {
		opts.macFile = opts.updateMessageFile + ".mac"
	}

	return &opts
}

func main() {
	opts := parseOptions()

	state := art.ReadTreeState(opts.treeStateFile)

	processUpdateMessage(opts, state)

	art.SaveTreeState(opts.treeStateFile, state)
}
