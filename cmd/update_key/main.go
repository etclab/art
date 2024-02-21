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
	"math"
	"os"
	"strconv"

	"art/internal/keyutl"
	"art/internal/mu"
	"art/internal/proto"
	"art/internal/tree"
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
	The 'current' group member's private ephemeral key file (also called a prekey).  
	This is a PEM-encoded X25519 private key.

  // TODO: the case when -setup option is used
  TREE_FILE
	The file that contains the current state of the tree. This state will be used
	as a starting point to process key updates and update messages. If the -setup
	option is selected, the setup message will be used instead to get the initial
	state of the tree. This file will be overwritten with the new current state of 
	the tree after all updates have been processed.

options:
  -h, -help
    Show this usage statement and exit.

  -u UPDATE_FILE 
	If specified, the current member will update their leaf key, the tree, and the
	stage key. The update message containing the leaf index and path of updated keys
	will be written to UPDATE_FILE, and the signature for the message will be written 
	to UPDATE_FILE.sig

examples:  
  ./update_key -u cici_update_key 3 cici-ek.pem cici-state`

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
}

type keyUpdateMessage struct {
	Idx            int
	PathPublicKeys [][]byte
}

type stageKeyInfo struct {
	IKeys    [][]byte
	TreeKeys [][]byte
}

type treeState struct {
	// TODO: maybe add a tracker for the stage number to ensure updates are processed in the correct order
	publicTree *tree.PublicNode
	sk         ed25519.PrivateKey
	lk         *ecdh.PrivateKey
	ikeys      [][]byte
}

type treejson struct {
	PublicTree [][]byte
	Sk         []byte
	Lk         []byte
	Ikeys      [][]byte
}

func signMAC(sk ed25519.PrivateKey, msg keyUpdateMessage, macFile string) error {
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

// processTreeState = load the tree state from file
func processTreeState(opts *options, state *treeState) {
	// decoding the file containing the tree state
	var treejson treejson
	dec_message, err := os.Open(opts.treeStateFile)
	if err != nil {
		mu.Die("error opening TREE_FILE:", err)
	}
	dec := json.NewDecoder(dec_message)
	err = dec.Decode(&treejson)
	if err != nil {
		mu.Die("error decoding state from TREE_FILE:", err)
	}
	dec_message.Close()

	// converting the []byte values into the tree state values
	state.ikeys = treejson.Ikeys
	state.publicTree, err = tree.UnmarshalKeysToPublicTree(treejson.PublicTree)
	if err != nil {
		mu.Die("error unmarshaling private tree from TREE_FILE", err)
	}

	state.sk, err = keyutl.UnmarshalPrivateIKFromPEM(treejson.Sk)
	if err != nil {
		mu.Die("error unmarshaling private stage key from TREE_FILE: %v", err)
	}

	state.lk, err = keyutl.UnmarshalPrivateEKFromPEM(treejson.Lk)
	if err != nil {
		mu.Die("error unmarshaling private leaf key from TREE_FILE: %v", err)
	}
}

func copath(root *tree.PublicNode, idx int, copathNodes []*ecdh.PublicKey) []*ecdh.PublicKey {
	// if len(copathNodes) == 0 {
	// 	copathNodes = append(copathNodes, root.GetPk())
	// }

	// height of 0 means we're at the leaf
	if root.Height == 0 {
		// copathNodes = append(copathNodes, root)
		return copathNodes
	}

	// leaf is in the left subtree
	if idx <= int(math.Pow(2, float64(root.Height)))/2 {
		copathNodes = append(copathNodes, root.Right.GetPk())
		return copath(root.Left, idx, copathNodes)
	} else { // leaf is in the right subtree
		idx = idx - int(math.Pow(2, float64(root.Height)))/2
		copathNodes = append(copathNodes, root.Left.GetPk())
		return copath(root.Right, idx, copathNodes)
	}
}

func pathNodeKeys(leafKey *ecdh.PrivateKey, copathKeys []*ecdh.PublicKey) ([]*ecdh.PrivateKey, error) {
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

/* updating the full tree with the new leaf and path keys */
func updatePublicTree(pathKeys []*ecdh.PublicKey, root *tree.PublicNode, idx int) *tree.PublicNode {
	// height of 0 means we're at the leaf
	if root.Height == 0 {
		root.UpdatePk(pathKeys[0])
		// copathNodes = append(copathNodes, root)
		return root
	}

	// leaf is in the left subtree
	if idx <= int(math.Pow(2, float64(root.Height)))/2 {
		root.UpdatePk(pathKeys[len(pathKeys)-1])
		root.Left = updatePublicTree(pathKeys[:len(pathKeys)-1], root.Left, idx)

	} else { // leaf is in the right subtree
		idx = idx - int(math.Pow(2, float64(root.Height)))/2
		root.UpdatePk(pathKeys[len(pathKeys)-1])
		root.Right = updatePublicTree(pathKeys[:len(pathKeys)-1], root.Right, idx)
	}
	return root
}

func updateTreeState(opts *options, state *treeState) {
	// creating/truncating the TREE_FILE
	tree_file, err := os.Create(opts.treeStateFile)
	if err != nil {
		mu.Die("error creating TREE_FILE: %v", err)
	}

	// filling in the treejson struct to encode into the tree state file
	publicTree, err := state.publicTree.MarshalKeys()
	if err != nil {
		mu.Die("failed to marshal the private keys from the current tree state: %v", err)
	}

	sk, err := keyutl.MarshalPrivateIKToPEM(state.sk)
	if err != nil {
		mu.Die("error marshaling private stage key from the current tree state: %v", err)
	}

	lk, err := keyutl.MarshalPrivateEKToPEM(state.lk)
	if err != nil {
		mu.Die("error unmarshaling private leaf key from TREE_FILE: %v", err)
	}

	// encoding the tree state
	enc := json.NewEncoder(tree_file)
	treejson := treejson{publicTree, sk, lk, state.ikeys}
	enc.Encode(treejson)
	tree_file.Close()
}

/* updating the member's key */
func updateKey(opts *options, state *treeState) ed25519.PrivateKey {
	// create a new leaf key
	var err error
	state.lk, err = proto.DHKeyGen()
	if err != nil {
		mu.Die("error creating the new leaf key: %v", err)
	}

	// update the path node keys
	copathNodes := make([]*ecdh.PublicKey, 0)
	copathNodes = copath(state.publicTree, opts.idx, copathNodes)

	// with the leaf key, derive the private keys on the path up to the root
	pathKeys, err := pathNodeKeys(state.lk, copathNodes)
	if err != nil {
		mu.Die("error deriving the new private path keys: %v", err)
	}
	tk := pathKeys[len(pathKeys)-1]

	// marshalling the public path node keys
	publicPathKeys := make([]*ecdh.PublicKey, 0, len(pathKeys))
	marshalledPathKeys := make([][]byte, 0, len(pathKeys))
	for _, key := range pathKeys {
		publicPathKeys = append(publicPathKeys, key.PublicKey())
		marshalledKey, err := keyutl.MarshalPublicEKToPEM(key.PublicKey())
		if err != nil {
			mu.Die("failed to marshal public EK: %v", err)
		}
		marshalledPathKeys = append(marshalledPathKeys, marshalledKey)
	}

	// replace the updated nodes in the full tree representation
	state.publicTree = updatePublicTree(publicPathKeys, state.publicTree, opts.idx)
	treeKeys, err := state.publicTree.MarshalKeys()
	if err != nil {
		mu.Die("failed to marshal the updated tree's public keys: %v", err)
	}

	// creating the message file with the member's index and the new public path node keys
	message_file, err := os.Create(opts.updateFile)
	if err != nil {
		mu.Die("error creating update message file: %v", err)
	}

	// encoding the message
	enc := json.NewEncoder(message_file)
	updateMsg := keyUpdateMessage{opts.idx, marshalledPathKeys}
	enc.Encode(updateMsg)
	message_file.Close()

	// sign the message with the old stage key (symmetric signing)
	err = signMAC(state.sk, updateMsg, opts.updateFile+".mac")
	if err != nil {
		mu.Die("error creating MAC signature: %v", err)
	}

	// find the new stage key with the new tree key (and updated full tree)
	stageInfo := proto.StageKeyInfo{
		PrevStageKey:  state.sk,
		TreeSecretKey: tk.Bytes(),
		IKeys:         state.ikeys,
		TreeKeys:      treeKeys,
	}
	state.sk, err = proto.DeriveStageKey(&stageInfo)
	if err != nil {
		mu.Die("DeriveStageKey failed: %v", err)
	}

	return state.sk
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.updateFile, "u", "update_key.msg", "The file to write the key update message to")
	flag.Parse()

	if flag.NArg() != 3 {
		mu.Die(shortUsage)
	}

	opts.idx, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Die("error converting positional argument INDEX to int: %v", err)
	}
	opts.privEkFile = flag.Arg(1)
	opts.treeStateFile = flag.Arg(2)

	return &opts
}

func main() {
	opts := parseOptions()

	var state treeState
	var sk ed25519.PrivateKey

	fmt.Printf("processing tree state file: %s\n", opts.treeStateFile)
	processTreeState(opts, &state)

	// update the member's leaf key and create a key update message
	fmt.Printf("updating the member's leaf key\n")
	sk = updateKey(opts, &state)

	// write the new tree state to the tree state file
	updateTreeState(opts, &state)

	fmt.Printf("Stage key: ")
	fmt.Println(sk)
}
