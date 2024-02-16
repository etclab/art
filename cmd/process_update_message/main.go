package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"

	"art/internal/keyutl"
	"art/internal/mu"
	"art/internal/tree"

	"golang.org/x/crypto/hkdf"
)

const shortUsage = `Usage: process_update_message [options] INDEX PRIVATE_EK_FILE TREE_FILE UPDATE_FILE`
const usage = `Usage: process_update_message [options] INDEX PRIVATE_EK_FILE TREE_FILE UPDATE_FILE

Process a key update message as a group member at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is processing the key 
	update message, this index is based off the member's position in the group config
	file, where the first entry is at index 1.

  PRIVATE_EK_KEY_FILE
	The 'current' group member's private ephemeral key file (also called a prekey).  
	This is a PEM-encoded X25519 private key.

  // TODO: the case when -setup option is used
  TREE_FILE
  	The file that contains the current state of the tree. This state will be used
  	as a starting point to process the update message. If the -setup
  	option is selected, the setup message will be used instead to get the initial
  	state of the tree. This file will be overwritten with the new current state of 
  	the tree after all updates have been processed.

  UPDATE_FILE
	The file that contains the update messages that needs to be processed.

options:
  -h, -help
    Show this usage statement and exit.

examples:
  ./process_update_message 2 bob-ek.pem bob-state cici_update_key`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional
	idx           int
	privEkFile    string
	treeStateFile string
	updateFile    string
}

type updateMessage struct {
	Idx            int
	PathPublicKeys [][]byte
}

type stageKeyInfo struct {
	IKeys    [][]byte
	TreeKeys [][]byte
}

type treeState struct {
	// maybe add a tracker for the stage number to ensure updates are processed in the correct order
	publicTree *tree.PublicNode
	sk         ed25519.PrivateKey
	lk         *ecdh.PrivateKey
	ikeys      [][]byte
}

type treeGob struct {
	PublicTree [][]byte
	Sk         []byte
	Lk         []byte
	Ikeys      [][]byte
}

func verifyMAC(sk ed25519.PrivateKey, msg updateMessage, macFile string) (bool, error) {
	fmt.Println(sk[:32])
	// converting the update message contents into a byte array
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(msg.Idx))
	MACBytes := bytes.Join(msg.PathPublicKeys, []byte(" "))
	MACBytes = append(MACBytes, bs...)

	// creating the MAC
	mac := hmac.New(sha256.New, sk)
	mac.Write(MACBytes)
	macData := mac.Sum(nil)

	// getting the expected MAC data from the MAC file
	expectedMAC, err := os.ReadFile(macFile)
	if err != nil {
		return false, fmt.Errorf("can't read MAC signature file: %v", err)
	}

	return hmac.Equal(macData, expectedMAC), nil
}

func processTreeState(opts *options, state *treeState) {
	// decoding the file containing the tree state
	var treegob treeGob
	dec_message, err := os.Open(opts.treeStateFile)
	if err != nil {
		mu.Die("error opening TREE_FILE:", err)
	}
	dec := gob.NewDecoder(dec_message)
	err = dec.Decode(&treegob)
	if err != nil {
		mu.Die("error decoding state from TREE_FILE:", err)
	}
	dec_message.Close()

	// converting the []byte values into the tree state values
	state.ikeys = treegob.Ikeys
	state.publicTree, err = tree.UnmarshalKeysToPublicTree(treegob.PublicTree)
	if err != nil {
		mu.Die("error unmarshaling private tree from TREE_FILE", err)
	}

	state.sk, err = keyutl.UnmarshalPrivateIKFromPEM(treegob.Sk)
	if err != nil {
		mu.Die("error unmarshaling private stage key from TREE_FILE: %v", err)
	}

	state.lk, err = keyutl.UnmarshalPrivateEKFromPEM(treegob.Lk)
	if err != nil {
		mu.Die("error unmarshaling private leaf key from TREE_FILE: %v", err)
	}
}

// updateTreeState = save tree state to file
func updateTreeState(opts *options, state *treeState) {
	// creating/truncating the TREE_FILE
	tree_file, err := os.Create(opts.treeStateFile)
	if err != nil {
		mu.Die("error creating TREE_FILE: %v", err)
	}

	// filling in the treeGob struct to encode into the tree state file
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
	enc := gob.NewEncoder(tree_file)
	treegob := treeGob{publicTree, sk, lk, state.ikeys}
	enc.Encode(treegob)
	tree_file.Close()
}

func deriveStageKey(tk *ecdh.PrivateKey, stageInfo *stageKeyInfo) ed25519.PrivateKey {
	hash := sha256.New
	// secret is tree key
	// info should be struct with: array of ids & array of public key nodes

	// encoding the stage key info struct into a single byte stream
	/* can't use encoding/gob because the byte streams aren't guaranteed to be equivalent
	 * accross different encoders
	 */
	stageByteArray := make([][]byte, 0)
	stageByteArray = append(stageByteArray, bytes.Join(stageInfo.IKeys, []byte(" ")))
	stageByteArray = append(stageByteArray, bytes.Join(stageInfo.TreeKeys, []byte(" ")))
	stageBytes := bytes.Join(stageByteArray, []byte(" "))

	hkdf := hkdf.New(hash, tk.Bytes(), nil, stageBytes)
	stageRaw := make([]byte, ed25519.PrivateKeySize)
	_, err := io.ReadFull(hkdf, stageRaw)
	if err != nil {
		mu.Die("failed to generate stage key: %v:", err)
	}

	// is this correct to unmarshal? what key type should the stage key be?
	stageKey, err := keyutl.UnmarshalPrivateIKFromRaw(stageRaw)
	if err != nil {
		mu.Die("failed to unmarshal stage key: %v:", err)
	}

	return stageKey
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

func processUpdateMessage(opts *options, updateMsg string, state *treeState) ed25519.PrivateKey {
	// decoding the message file
	var upMsg updateMessage
	dec_message, err := os.Open(updateMsg)
	if err != nil {
		mu.Die("error opening message file: %v", err)
	}
	dec := gob.NewDecoder(dec_message)
	err = dec.Decode(&upMsg)
	if err != nil {
		mu.Die("error decoding message from file: %v", err)
	}
	dec_message.Close()

	// verify the signature on the update message with the current stage key
	valid, err := verifyMAC(state.sk, upMsg, updateMsg+".mac")
	if err != nil {
		mu.Die("error verifying update message file signature: %v", err)
	}
	if !valid {
		mu.Die("update message failed to pass signature verification")
	}

	// unmarshalling the public path node keys
	updatedPathKeys := make([]*ecdh.PublicKey, 0, len(upMsg.PathPublicKeys))
	for _, pem := range upMsg.PathPublicKeys {
		key, err := keyutl.UnmarshalPublicEKFromPEM(pem)
		if err != nil {
			mu.Die("failed to marshal public EK: %v", err)
		}
		updatedPathKeys = append(updatedPathKeys, key)
	}

	// find the first/lowest index in the copath/tree that needs to be updated for this member?
	// replace the updated nodes in the full tree representation
	state.publicTree = updatePublicTree(updatedPathKeys, state.publicTree, upMsg.Idx)

	// update the current members' path node keys
	copathNodes := make([]*ecdh.PublicKey, 0)
	copathNodes = copath(state.publicTree, opts.idx, copathNodes)
	memPathKeys, err := pathNodeKeys(state.lk, copathNodes)
	if err != nil {
		mu.Die("error deriving the private path keys: %v", err)
	}

	// derive the new stage key with the updated tree key and other info
	treeKeys, err := state.publicTree.MarshalKeys()
	if err != nil {
		mu.Die("failed to marshal the updated tree's public keys: %v", err)
	}

	tk := memPathKeys[len(memPathKeys)-1]
	stageInfo := stageKeyInfo{IKeys: state.ikeys, TreeKeys: treeKeys}
	state.sk = deriveStageKey(tk, &stageInfo)

	return state.sk
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() != 4 {
		mu.Die(shortUsage)
	}

	opts.idx, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Die("error converting positional argument INDEX to int: %v", err)
	}
	opts.privEkFile = flag.Arg(1)
	opts.treeStateFile = flag.Arg(2)
	opts.updateFile = flag.Arg(3)

	return &opts
}

func main() {
	opts := parseOptions()
	var state treeState
	var sk ed25519.PrivateKey

	fmt.Printf("processing tree state file: %s\n", opts.treeStateFile)
	processTreeState(opts, &state)

	fmt.Printf("processing update message: %s\n", opts.updateFile)
	sk = processUpdateMessage(opts, opts.updateFile, &state)

	// write the new tree state to the tree state file
	updateTreeState(opts, &state)

	fmt.Printf("Stage key: %s\n", sk)
}
