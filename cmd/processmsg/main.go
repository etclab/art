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
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"art/internal/keyutl"
	"art/internal/mu"
	"art/internal/proto"
	"art/internal/tree"

	"golang.org/x/crypto/hkdf"
)

const shortUsage = "Usage: processmsg [options] INDEX PRIVATE_EK_KEY_FILE TREE_FILE"
const usage = `Usage: processmsg [options] INDEX PRIVATE_EK_KEY_FILE TREE_FILE

Process a group setup message as a group member at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is processing the setup
	message, this index is based off the member's position in the group config
	file, where the first entry is at index 1.

  PRIVATE_EK_KEY_FILE
	The 'current' group member's private ephemeral key file (also called a prekey).  
	This is a PEM-encoded X25519 private key.

  TREE_FILE
	The file that contains the current state of the tree. This state will be used
	as a starting point to process key updates and update messages. If the -setup
	option is selected, the setup message will be used instead to get the initial
	state of the tree. This file will be overwritten with the new current state of 
	the tree after all updates have been processed.

options:
  -h, -help
    Show this usage statement and exit.

  -setup SETUP_MSG_FILE
	The file containing the group setup message, if one needs to be processed. This
	message will have a corresponding signature file with the name SETUP_MSG_FILE.sig
	This option must be specified in conjunction with the -pk option.

  -pk PUBLIC_ID_KEY_FILE
 	The initiator's public key file.  This is a PEM-encoded ED25519 key that will
	be used to verify the signed message file.
  	This option must be specified in conjunction with the -setup option.

  -pu UPDATE_MSG_FILE1,UPDATE_MSG_FILE2,...
	The file(s) containing update messages that need to be processed. If more than
	one file is specified, the file names must be comma-separated. The files will 
	be processed in the order they are given. 
	If applicable, these files will be processed after the setup message.

  -u UPDATE_FILE 
	If specified, the current member will update their leaf key, the tree, and the
	stage key. The update message containing the leaf index and path of updated keys
	will be written to UPDATE_FILE, and the signature for the message will be written 
	to UPDATE_FILE.sig
	If applicable, the leaf key will be updated after the setup message and/or any
	update messages are processed.

examples:
  ./processmsg -setup groupconfig.dir/message -pk alice-ik-pub.pem -u bob_update_key 2 bob-ek.pem bob_tree_state
  ./processmsg -setup groupconfig.dir/message -pk alice-ik-pub.pem -pu bob_update_key 3 mary-ek.pem mary_tree_state
  ./processmsg -u mary_update_key 3 mary-ek.pem mary_tree_state
  ./processmsg -pu mary_update_key 2 bob-ek.pem bob_tree_state`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	idx        int
	ek         string
	treeState  string
	setupMsg   string
	pk         string
	updateMsgs string
	updateFile string
}

type message struct {
	IKeys    [][]byte
	EKeys    [][]byte
	Suk      []byte
	TreeKeys [][]byte
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

type treejson struct {
	PublicTree [][]byte
	Sk         []byte
	Lk         []byte
	Ikeys      [][]byte
}

func verifySetup(pkPath string, msgfile string, sigfile string) (bool, error) {
	encoding, err := keyutl.StringToKeyEncoding("pem")
	if err != nil {
		mu.Die("%v", err)
	}

	pk, err := keyutl.ReadPublicIKFromFile(pkPath, encoding)
	if err != nil {
		return false, fmt.Errorf("can't read public key file: %v", err)
	}

	msgData, err := os.ReadFile(msgfile)
	if err != nil {
		return false, fmt.Errorf("can't read message file: %v", err)
	}

	sigData, err := os.ReadFile(sigfile)
	if err != nil {
		return false, fmt.Errorf("can't read sigfile: %v", err)
	}

	// regular Ed25519
	valid := ed25519.Verify(pk, msgData, sigData)
	return valid, nil
}

func verifyMAC(sk ed25519.PrivateKey, msg updateMessage, macFile string) (bool, error) {
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

func signMAC(sk ed25519.PrivateKey, msg updateMessage, macFile string) error {
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

func processTreeState(opts *options, state *treeState) {
	// decoding the file containing the tree state
	var treejson treejson
	dec_message, err := os.Open(opts.treeState)
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

func updateTreeState(opts *options, state *treeState) {
	// creating/truncating the TREE_FILE
	tree_file, err := os.Create(opts.treeState)
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

func deriveLeafKey(ekPath string, suk *ecdh.PublicKey) (*ecdh.PrivateKey, error) {
	encoding, err := keyutl.StringToKeyEncoding("pem")
	if err != nil {
		mu.Die("%v", err)
	}

	ek, err := keyutl.ReadPrivateEKFromFile(ekPath, encoding)
	if err != nil {
		return nil, fmt.Errorf("can't read private key file: %v", err)
	}

	raw, err := proto.KeyExchange(ek, suk)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the member's leaf key: %v", err)
	}

	leafKey, err := keyutl.UnmarshalPrivateX25519FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal the member's leaf key: %v", err)
	}

	return leafKey, nil
}

func processMessage(opts *options, state *treeState) ed25519.PrivateKey {
	// decoding the message file
	var m message
	dec_message, err := os.Open(opts.setupMsg)
	if err != nil {
		mu.Die("error opening message file:", err)
	}
	dec := json.NewDecoder(dec_message)
	err = dec.Decode(&m)
	if err != nil {
		mu.Die("error decoding message from file:", err)
	}
	dec_message.Close()

	// unmarshalling all the keys (may be unnecessary)
	EKS := make([]*ecdh.PublicKey, 0, len(m.EKeys))
	IKS := make([]ed25519.PublicKey, 0, len(m.IKeys))

	for i := 0; i < len(m.EKeys); i++ {
		unmarshalledEK, err := keyutl.UnmarshalPublicEKFromPEM(m.EKeys[i])
		if err != nil {
			mu.Die("failed to marshal public EK")
		}
		EKS = append(EKS, unmarshalledEK)

		unmarshalledIK, err := keyutl.MarshalPublicIKToPEM(m.IKeys[i])
		if err != nil {
			mu.Die("failed to marshal public IK")
		}
		IKS = append(IKS, unmarshalledIK)
	}

	suk, err := keyutl.UnmarshalPublicEKFromPEM(m.Suk)
	if err != nil {
		mu.Die("failed to marshal public SUK")
	}

	// unmarshalling the public tree
	state.publicTree, err = tree.UnmarshalKeysToPublicTree(m.TreeKeys)
	if err != nil {
		mu.Die("error unmarshalling the public tree keys: %v", err)
	}

	// derive the member's private leaf key
	state.lk, err = deriveLeafKey(opts.ek, suk)
	if err != nil {
		mu.Die("error deriving the private leaf key: %v", err)
	}

	// find the nodes on the copath
	copathNodes := make([]*ecdh.PublicKey, 0)
	copathNodes = copath(state.publicTree, opts.idx, copathNodes)

	// with the leaf key, derive the private keys on the path up to the root
	pathKeys, err := pathNodeKeys(state.lk, copathNodes)
	if err != nil {
		mu.Die("error deriving the private path keys: %v", err)
	}

	// the initial tree key is the last key in pathKeys
	tk := pathKeys[len(pathKeys)-1]

	// stage key derivation
	state.ikeys = m.IKeys
	stageInfo := stageKeyInfo{IKeys: m.IKeys, TreeKeys: m.TreeKeys}
	state.sk = deriveStageKey(tk, &stageInfo)

	return state.sk
}

func processUpdateMessage(opts *options, updateMsg string, state *treeState) ed25519.PrivateKey {
	// decoding the message file
	var upMsg updateMessage
	dec_message, err := os.Open(updateMsg)
	if err != nil {
		mu.Die("error opening message file: %v", err)
	}
	dec := json.NewDecoder(dec_message)
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
	updateMsg := updateMessage{opts.idx, marshalledPathKeys}
	enc.Encode(updateMsg)
	message_file.Close()

	// sign the message with the old stage key (symmetric signing)
	err = signMAC(state.sk, updateMsg, opts.updateFile+".mac")
	if err != nil {
		mu.Die("error creating MAC signature: %v", err)
	}

	// find the new stage key with the new tree key (and updated full tree)
	stageInfo := stageKeyInfo{IKeys: state.ikeys, TreeKeys: treeKeys}
	state.sk = deriveStageKey(tk, &stageInfo)

	return state.sk
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.setupMsg, "setup", "", "The setup message file to process")
	flag.StringVar(&opts.pk, "pk", "", "The initiator's public key file")
	flag.StringVar(&opts.updateMsgs, "pu", "", "The update message file(s) to process")
	flag.StringVar(&opts.updateFile, "u", "", "The file to write an update message to")
	flag.Parse()

	if flag.NArg() != 3 {
		mu.Die(shortUsage)
	}

	opts.idx, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Die("error converting positional argument INDEX to int: %v", err)
	}
	opts.ek = flag.Arg(1)
	opts.treeState = flag.Arg(2)

	if opts.pk == "" && opts.setupMsg != "" {
		mu.Die("error: must specify -pk if -setup is selected")
	}
	if opts.setupMsg == "" && opts.pk != "" {
		mu.Die("error: must specify -setup if -pk is selected")
	}

	return &opts
}

func main() {
	opts := parseOptions()
	var state treeState
	var sk ed25519.PrivateKey

	if opts.setupMsg != "" {
		// validate the message
		valid, err := verifySetup(opts.pk, opts.setupMsg, opts.setupMsg+".sig")
		if err != nil {
			mu.Die("error: %v", err)
		}

		if !valid {
			mu.Die("error: message signature verification failed")
		}
		// process the message
		// fill in the tree state struct
		fmt.Printf("processing setup message: %s\n", opts.setupMsg)
		sk = processMessage(opts, &state)
		//fmt.Println(sk)
	} else {
		// process the tree_state file
		fmt.Printf("processing tree state file: %s\n", opts.treeState)
		processTreeState(opts, &state)
		sk = state.sk
		//fmt.Println(sk)
	}

	if opts.updateMsgs != "" {
		// split up the different file names
		messages := strings.Split(opts.updateMsgs, ",")
		// process the update messages
		for _, msg := range messages {
			fmt.Printf("processing update message: %s\n", msg)
			sk = processUpdateMessage(opts, msg, &state)
			//fmt.Println(sk)
		}

	}

	if opts.updateFile != "" {
		// update the member's leaf key and create update message
		fmt.Printf("updating the member's leaf key\n")
		sk = updateKey(opts, &state)
	}

	// write the new tree state to the tree state file
	updateTreeState(opts, &state)

	// print out the current stage key - may want to add a stage number?
	fmt.Println("Final/current stage key: ")
	fmt.Println(sk)
}
