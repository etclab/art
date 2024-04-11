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

const shortUsage = "Usage: update_key [options] INDEX PRIVATE_EK_KEY_FILE TREE_FILE"
const usage = `Usage: update_key [options] INDEX PRIVATE_EK_KEY_FILE TREE_FILE

Update an agent's key at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is updating the key, 
	this index is based off the member's position in the group config
	file, where the first entry is at index 1.

  PRIVATE_EK_KEY_FILE
	The 'current' group member's private ephemeral key file (also called a 
	prekey). This is a PEM-encoded X25519 private key.

  TREE_FILE
	The file that contains the current state of the tree. This state will be 
	used as a starting point to process key updates and update messages. This 
	file will be overwritten with the new current state of the tree after all 
	updates have been processed.

options:
  -h, -help
    Show this usage statement and exit.

  -update-file UPDATE_FILE 
	If specified, the current member will update their leaf key, the tree, and 
	the stage key. The update message containing the leaf index and path of 
	updated keys will be written to UPDATE_FILE. If omitted, the update message
	is saved to file update_key.msg

  -mac-file MAC_FILE
  	The MAC for the update message will be written to MAC_FILE. If omitted, the 
	MAC is saved to file UPDATE_FILE.mac

examples:  
  ./update_key -update-file cici_update_key 3 cici-ek.pem cici-state`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional args
	idx           int
	privEkFile    string
	treeStateFile string

	// options
	updateFile string
	macFile    string
}

func signMAC(sk ed25519.PrivateKey, msg art.KeyUpdateMessage, macFile string) error {
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

func createUpdateMessage(index int, pathKeys []*ecdh.PrivateKey) art.KeyUpdateMessage {
	marshalledPathKeys := marshallPublicKeys(pathKeys)
	updateMsg := art.KeyUpdateMessage{
		Idx:            index,
		PathPublicKeys: marshalledPathKeys,
	}
	return updateMsg
}

func saveKeyUpdateMessage(updateFile string, updateMsg *art.KeyUpdateMessage) {
	messageFile, err := os.Create(updateFile)
	if err != nil {
		mu.Fatalf("error creating update message file: %v", err)
	}

	enc := json.NewEncoder(messageFile)
	enc.Encode(updateMsg)

	defer messageFile.Close()
}

func generateMAC(sk ed25519.PrivateKey, updateMsg art.KeyUpdateMessage,
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
	saveKeyUpdateMessage(opts.updateFile, &updateMsg)
	generateMAC(state.Sk, updateMsg, opts.macFile)

	// replace the updated nodes in the full tree representation
	state.PublicTree = art.UpdatePublicTree(publicPathKeys, state.PublicTree,
		opts.idx)

	deriveStageKey(state, treeSecret)
	fmt.Printf("Stage key: %v\n", state.Sk)
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.updateFile, "update-file", "update_key.msg", "")
	flag.StringVar(&opts.macFile, "sig-file", "", "")
	flag.Parse()

	if flag.NArg() != 3 {
		mu.Fatalf(shortUsage)
	}

	opts.idx, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Fatalf("error converting positional argument INDEX to int: %v", err)
	}
	opts.privEkFile = flag.Arg(1)
	opts.treeStateFile = flag.Arg(2)

	if opts.macFile == "" {
		opts.macFile = opts.updateFile + ".mac"
	}

	return &opts
}

func main() {
	opts := parseOptions()

	state := art.ReadTreeState(opts.treeStateFile)

	updateKey(opts, state)

	art.SaveTreeState(opts.treeStateFile, state)
}
