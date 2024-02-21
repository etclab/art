package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"

	"art/internal/cryptutl"
	"art/internal/keyutl"
	"art/internal/mu"
	"art/internal/proto"
	"art/internal/tree"
)

const shortUsage = "Usage: process_setup_message [options] INDEX PRIVATE_EK_KEY_FILE TREE_FILE"
const usage = `Usage: process_setup_message [options] INDEX PRIVATE_EK_KEY_FILE TREE_FILE

Process a group setup message as a group member at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is processing the setup
	message, this index is based off the member's position in the group config
	file, where the first entry is at index 1.

  PRIVATE_EK_FILE
	The 'current' group member's private ephemeral key file (also called a prekey).  
	This is a PEM-encoded X25519 private key.

  INITIATOR_PUB_IK_FILE
    The initiator's public identity key.  This is a PEM-encoded ED25519 key.

  SETUP_MESSAGE_FILE
	The file containing the group setup message.


options:
  -h, -help
    Show this usage statement and exit.

  -sigfile SETUP_MSG_SIGNATURE_FILE
    This setup message's corresponding signature file (signed with the initiator's IK).
    If not provided, the tool will look for a file SETUP_MESSAGE_FILE.sig.

  // TODO: json output
  -out-state STATE_FILE
    The file to output the node's state after processing the setup message.  If
    not provided, the default is state.json. 


examples:
  ./process_setup_message -out-state bob-state.json 2 bob-ek.pem alice-ik-pub.pem setup.msg`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional arguments
	index              int
	privEKFile         string
	initiatorPubIKFile string
	setupMessageFile   string

	// options
	sigFile      string
	outStateFile string
}

type message struct {
	IKeys    [][]byte
	EKeys    [][]byte
	Suk      []byte
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

func updateTreeState(opts *options, state *treeState) {
	// creating/truncating the TREE_FILE
	tree_file, err := os.Create(opts.outStateFile)
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

// TODO: move this to internal/tree/tree.go
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

func deriveLeafKey(ekPath string, suk *ecdh.PublicKey) (*ecdh.PrivateKey, error) {
	ek, err := keyutl.ReadPrivateEKFromFile(ekPath, keyutl.PEM)
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
	// TODO: message should be a public struct in internal/proto/; make it
	// serializable to json.
	var m message
	dec_message, err := os.Open(opts.setupMessageFile)
	if err != nil {
		mu.Die("error opening message file:", err)
	}
	dec := json.NewDecoder(dec_message)
	err = dec.Decode(&m)
	if err != nil {
		mu.Die("error decoding message from file:", err)
	}
	dec_message.Close()

	// XXX: unmarshalling all the keys (may be unnecessary)
	EKS := make([]*ecdh.PublicKey, 0, len(m.EKeys))
	IKS := make([]ed25519.PublicKey, 0, len(m.IKeys))

	for i := 0; i < len(m.EKeys); i++ {
		unmarshalledEK, err := keyutl.UnmarshalPublicEKFromPEM(m.EKeys[i])
		if err != nil {
			mu.Die("failed to marshal public EK")
		}
		EKS = append(EKS, unmarshalledEK)

		// XXX: shouldn't this be keyutl.Unmarshal ?
		unmarshalledIK, err := keyutl.MarshalPublicIKToPEM(m.IKeys[i])
		if err != nil {
			mu.Die("failed to marshal public IK")
		}
		IKS = append(IKS, unmarshalledIK)
	}

	suk, err := keyutl.UnmarshalPublicEKFromPEM(m.Suk)
	if err != nil {
		mu.Die("failed to unmarshal public SUK")
	}

	// unmarshalling the public tree
	state.publicTree, err = tree.UnmarshalKeysToPublicTree(m.TreeKeys)
	if err != nil {
		mu.Die("error unmarshalling the public tree keys: %v", err)
	}

	// derive the member's private leaf key
	state.lk, err = deriveLeafKey(opts.privEKFile, suk)
	if err != nil {
		mu.Die("error deriving the private leaf key: %v", err)
	}

	// find the nodes on the copath
	copathNodes := make([]*ecdh.PublicKey, 0)
	copathNodes = copath(state.publicTree, opts.index, copathNodes)

	// with the leaf key, derive the private keys on the path up to the root
	pathKeys, err := pathNodeKeys(state.lk, copathNodes)
	if err != nil {
		mu.Die("error deriving the private path keys: %v", err)
	}

	// the initial tree key is the last key in pathKeys
	tk := pathKeys[len(pathKeys)-1]

	// stage key derivation
	stageInfo := proto.StageKeyInfo{
		PrevStageKey:  state.sk,
		TreeSecretKey: tk.Bytes(),
		IKeys:         m.IKeys,
		TreeKeys:      m.TreeKeys,
	}
	state.sk, err = proto.DeriveStageKey(&stageInfo)

	if err != nil {
		mu.Die("failed to derive the stage key: %v", err)
	}

	return state.sk
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.sigFile, "sigfile", "", "")
	// TODO: json output
	flag.StringVar(&opts.outStateFile, "out-state", "", "The file to write tree state to")
	flag.Parse()

	if flag.NArg() != 4 {
		mu.Die(shortUsage)
	}

	opts.index, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Die("error converting positional argument INDEX to int: %v", err)
	}
	opts.privEKFile = flag.Arg(1)
	opts.initiatorPubIKFile = flag.Arg(2)
	opts.setupMessageFile = flag.Arg(3)

	if opts.sigFile == "" {
		opts.sigFile = opts.setupMessageFile + ".sig"
	}

	return &opts
}

func main() {
	opts := parseOptions()
	var state treeState
	var sk ed25519.PrivateKey

	// validate the message
	valid, err := cryptutl.VerifySignature(opts.initiatorPubIKFile, opts.setupMessageFile, opts.sigFile)
	if err != nil {
		mu.Die("error: %v", err)
	}
	if !valid {
		mu.Die("error: message signature verification failed")
	}

	sk = processMessage(opts, &state)
	//fmt.Println(sk)

	// write the new tree state to the tree state file
	updateTreeState(opts, &state)

	// TODO: print out the current stage key - may want to add a stage number?
	fmt.Println("Final/current stage key: ")
	fmt.Println(sk)
}
