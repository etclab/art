package art

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/etclab/art/internal/jsonutl"
	"github.com/etclab/mu"
)

// Node is a node in the ART tree
type Node struct {
	sk        *ecdh.PrivateKey
	left      *Node
	right     *Node
	x         int
	y         int
	numLeaves int
}

// PublicNode is a node in the public ART tree
type PublicNode struct {
	pk *ecdh.PublicKey

	// Left is the left child
	Left *PublicNode

	// Right is the right child
	Right *PublicNode

	// The nodes height, calculated upwards.  That is, a height of zero
	// indicates a leaf node.
	Height int
}

type treeJson struct {
	PublicTree [][]byte `json:"publicTree"`
	Sk         []byte   `json:"sk"`
	Lk         []byte   `json:"lk"`
	IKeys      [][]byte `json:"iKeys"`
}

// TODO: TreeState: maybe add a tracker for the stage number to ensure updates
// are processed in the correct order

// TreeState is an ART member's state
type TreeState struct {
	// PublicTree he root of the ART tree of public nodes
	PublicTree *PublicNode

	// Sk is the stage key
	Sk ed25519.PrivateKey

	// Lk is the member's leaf keys
	Lk *ecdh.PrivateKey

	// IKeysare the public identity keys (ed25519 keys) for the members
	IKeys [][]byte
}

// Save marshalls the TreeState as a JSON file
func (treeState *TreeState) Save(fileName string) {
	treeJson := MarshallTreeState(treeState)
	jsonutl.Encode(fileName, treeJson)
}

// SaveStageKey writes the stage key as a PEM file.
func (treeState *TreeState) SaveStageKey(fileName string) {
	stageKey := treeState.Sk

	err := WritePrivateIKToFile(stageKey, fileName, EncodingPEM)
	if err != nil {
		mu.Fatalf("error saving stage key: %v", err)
	}
}

// StageKey returns the private stage key
func (treeState *TreeState) StageKey() ed25519.PrivateKey {
	return treeState.Sk
}

// DeriveTreeKey derives the tree key (the root's secret key).
func (treeState *TreeState) DeriveTreeKey(index int) *ecdh.PrivateKey {
	// find the nodes on the copath
	copathNodes := make([]*ecdh.PublicKey, 0)
	copathNodes = CoPath(treeState.PublicTree, index, copathNodes)

	// with the leaf key, derive the private keys on the path up to the root
	pathKeys, err := PathNodeKeys(treeState.Lk, copathNodes)
	if err != nil {
		mu.Fatalf("error deriving the private path keys: %v", err)
	}

	// the initial tree key is the last key in pathKeys
	return pathKeys[len(pathKeys)-1]
}

// Read loads a TreeState from a JSON file.
func (treeState *TreeState) Read(treeStateFile string) {
	var tree treeJson

	treeFile, err := os.Open(treeStateFile)
	if err != nil {
		mu.Fatalf("error opening file %s", treeStateFile)
	}

	decoder := json.NewDecoder(treeFile)
	err = decoder.Decode(&tree)
	if err != nil {
		mu.Fatalf("error reading tree state from %s", treeStateFile)
	}

	defer treeFile.Close()

	treeState.UnMarshallTreeState(&tree)
}

// DeriveStageKey derives the stage key (the group key)
func (state *TreeState) DeriveStageKey(treeSecret *ecdh.PrivateKey) {
	treeKeys, err := state.PublicTree.MarshalKeys()
	if err != nil {
		mu.Fatalf("failed to marshal the updated tree's public keys: %v", err)
	}

	stageInfo := StageKeyInfo{
		PrevStageKey:  state.Sk,
		TreeSecretKey: treeSecret.Bytes(),
		IKeys:         state.IKeys,
		TreeKeys:      treeKeys,
	}
	stageKey, err := DeriveStageKey(&stageInfo)

	if err != nil {
		mu.Fatalf("DeriveStageKey failed: %v", err)
	}

	state.Sk = stageKey
}

// leftSubtreeSize computes the number of leaves in the leftsubtree of a
// tree with x leaves
func leftSubtreeSize(x int) int {
	// 2^{ ceil(log2(x))  -   1}
	exp := math.Ceil(math.Log2(float64(x))) - 1
	return int(math.Pow(2, exp))
}

func createTree(leafKeys []*ecdh.PrivateKey, x int, y int) (*Node, error) {
	// base case
	n := len(leafKeys)
	if n == 1 {
		return &Node{sk: leafKeys[0], left: nil, right: nil, x: x, y: y}, nil
	}

	h := leftSubtreeSize(n)
	left, err := createTree(leafKeys[:h], x+1, 2*y)
	if err != nil {
		return nil, err
	}
	right, err := createTree(leafKeys[h:], x+1, 2*y+1)
	if err != nil {
		return nil, err
	}

	// compute current node's private key from its children's keys

	pkRight := right.sk.PublicKey()
	raw, err := left.sk.ECDH(pkRight)
	if err != nil {
		return nil, fmt.Errorf("ECDH for node failed: %v", err)
	}
	sk, err := UnmarshalPrivateX25519FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal private x25519 key for node: %v", err)
	}

	return &Node{sk: sk, left: left, right: right, x: x, y: y, numLeaves: n}, nil

}

// CreateTree creates the initial ART tree.  The group initiator calls this
// function as part of the group setup.
//
// This function corresponds to the CreateTree function in Algorithm 2 of the "On
// Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
func CreateTree(leafKeys []*ecdh.PrivateKey) (*Node, error) {
	return createTree(leafKeys, 0, 0)
}

// PublicKeys generates the public ART tree, and returns the public root.
//
// This function corresponds to the PublicKeys function in Algorithm 2 of the "On
// Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
func (node *Node) PublicKeys() *PublicNode {
	if node == nil {
		return nil
	}

	left := node.left.PublicKeys()
	right := node.right.PublicKeys()
	pk := node.sk.PublicKey()

	return &PublicNode{pk: pk, Left: left, Right: right}
}

/*
***
*** Helper functions for private trees ***
***
 */

// MarshalKeys marshals the keys of the private ART tree.
func (node *Node) MarshalKeys() ([][]byte, error) {
	marshalled_list := make([][]byte, 0)

	if node == nil {
		return marshalled_list, nil
	}

	node_list := make([](*Node), 0)
	node_list = append(node_list, node)

	for len(node_list) != 0 {
		current := node_list[0]

		marshalledPK, err := MarshalPrivateEKToPEM(current.sk)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private EK: %v", err)
		}
		marshalled_list = append(marshalled_list, marshalledPK)

		if current.left != nil {
			node_list = append(node_list, current.left)
		}
		if current.right != nil {
			node_list = append(node_list, current.right)
		}
		node_list = node_list[1:]
	}

	return marshalled_list, nil
}

// UnmarshalKeysToPrivateTree constructs a private tree from a level-order list
// of marshalled keys.
func UnmarshalKeysToPrivateTree(marshalledKeys [][]byte) (*Node, error) {
	root := &Node{sk: nil, left: nil, right: nil, x: 0, y: 0}
	nodeQueue := make([]*Node, 0)

	for i := 0; i < len(marshalledKeys); i++ {
		// unmarshal the value
		pk, err := UnmarshalPrivateEKFromPEM(marshalledKeys[i])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private EK: %v", err)
		}

		// insert it into the tree
		root, nodeQueue = insertNode(root, pk, nodeQueue)
	}

	return root, nil
}

func insertNode(root *Node, sk *ecdh.PrivateKey, nodeQueue []*Node) (*Node, []*Node) {
	node := &Node{sk: sk, left: nil, right: nil, x: 0, y: 0}

	if root.sk == nil {
		root = node
	} else if nodeQueue[0].left == nil {
		nodeQueue[0].left = node
	} else { //nodeQueue[0].right == nil
		nodeQueue[0].right = node
		nodeQueue = nodeQueue[1:]
	}

	nodeQueue = append(nodeQueue, node)
	return root, nodeQueue
}

// GetSk returns the secret (private key) of an ART node.
func (Node *Node) GetSk() *ecdh.PrivateKey {
	return Node.sk
}

/*
***
*** Helper functions for private trees ***
***
 */

// MarshalKeys marshals the public keys level-by-level, starting
// at the root.
func (publicNode *PublicNode) MarshalKeys() ([][]byte, error) {
	//key_list := make([]*ecdh.PublicKey, 0)
	marshalledList := make([][]byte, 0)

	if publicNode == nil {
		return marshalledList, nil
	}

	node_list := make([](*PublicNode), 0)
	node_list = append(node_list, publicNode)

	for len(node_list) != 0 {
		current := node_list[0]
		//key_list = append(key_list, current.pk)

		marshalledPK, err := MarshalPublicEKToPEM(current.pk)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public EK: %v", err)
		}
		marshalledList = append(marshalledList, marshalledPK)

		if current.Left != nil {
			node_list = append(node_list, current.Left)
		}
		if current.Right != nil {
			node_list = append(node_list, current.Right)
		}
		node_list = node_list[1:]
	}

	return marshalledList, nil
}

// GetPK returns the a node's public ECDH (x25519) key.
func (publicNode *PublicNode) GetPk() *ecdh.PublicKey {
	return publicNode.pk
}

// UpdatePk sets a node's public ECDH (x25519) key.
func (publicNode *PublicNode) UpdatePk(newPK *ecdh.PublicKey) {
	publicNode.pk = newPK
}

// UnmarshalKeysToPublicTree constructs a public tree from a level-order list
// of marshalled public keys.
func UnmarshalKeysToPublicTree(marshalledKeys [][]byte) (*PublicNode, error) {
	root := &PublicNode{pk: nil, Left: nil, Right: nil}
	nodeQueue := make([]*PublicNode, 0)

	for i := 0; i < len(marshalledKeys); i++ {
		// unmarshal the value
		pk, err := UnmarshalPublicEKFromPEM(marshalledKeys[i])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal public EK: %v", err)
		}

		// insert it into the tree
		root, nodeQueue = insertPublicNode(root, pk, nodeQueue)
	}

	updatePublicHeights(root)
	return root, nil
}

func insertPublicNode(root *PublicNode, pk *ecdh.PublicKey, nodeQueue []*PublicNode) (*PublicNode, []*PublicNode) {
	node := &PublicNode{pk: pk, Left: nil, Right: nil, Height: 0}

	if root.pk == nil {
		root = node
	} else if nodeQueue[0].Left == nil {
		nodeQueue[0].Left = node
		nodeQueue[0].Height = node.Height + 1
	} else { //nodeQueue[0].right == nil
		nodeQueue[0].Right = node
		if nodeQueue[0].Left.Height < node.Height {
			nodeQueue[0].Height = node.Height + 1
		}
		nodeQueue = nodeQueue[1:]
	}

	nodeQueue = append(nodeQueue, node)
	return root, nodeQueue
}

func updatePublicHeights(node *PublicNode) *PublicNode {
	if node.Left == nil && node.Right == nil {
		node.Height = 0
		return node
	}

	left := updatePublicHeights(node.Left)
	right := updatePublicHeights(node.Right)

	if left.Height > right.Height {
		node.Height = left.Height + 1
	} else {
		node.Height = right.Height + 1
	}
	return node
}

//	CoPath returns the list of public node keys (x25519 keys) for all nodes on
//	the copath to the leaf at index idx.
//
// This function corresponds to the CoPath function in Algorithm 2 of the "On
// Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
func CoPath(root *PublicNode, idx int, copathNodes []*ecdh.PublicKey) []*ecdh.PublicKey {
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
		return CoPath(root.Left, idx, copathNodes)
	} else { // leaf is in the right subtree
		idx = idx - int(math.Pow(2, float64(root.Height)))/2
		copathNodes = append(copathNodes, root.Left.GetPk())
		return CoPath(root.Right, idx, copathNodes)
	}
}

// DeriveLeafKey devives a member's leaf key from its initial setup key
// (ekPath) and the public setup key of the initiator (suk).
//
// This function corresponds to the line 6 in the ProcessSetupMessage in
// Algorithm 3 of the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
func DeriveLeafKey(ekPath string, suk *ecdh.PublicKey) (*ecdh.PrivateKey, error) {
	ek, err := ReadPrivateEKFromFile(ekPath, EncodingPEM)
	if err != nil {
		return nil, fmt.Errorf("can't read private key file: %v", err)
	}

	raw, err := KeyExchange(ek, suk)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the member's leaf key: %v", err)
	}

	leafKey, err := UnmarshalPrivateX25519FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal the member's leaf key: %v", err)
	}

	return leafKey, nil
}

// DeriveLeafKeyOrFail is a wrapper for [DeriveLeafKey] that aborts the program
// on failure.
func DeriveLeafKeyOrFail(privKeyFile string, setupKey *ecdh.PublicKey) *ecdh.PrivateKey {
	leafKey, err := DeriveLeafKey(privKeyFile, setupKey)
	if err != nil {
		mu.Fatalf("error deriving the private leaf key: %v", err)
	}
	return leafKey
}

// MarshallTreeState prepars a TreeState to be marshalled as JSON.
func MarshallTreeState(state *TreeState) *treeJson {
	publicTree, err := state.PublicTree.MarshalKeys()
	if err != nil {
		mu.Fatalf("failed to marshal the public keys: %v", err)
	}

	sk, err := MarshalPrivateIKToPEM(state.Sk)
	if err != nil {
		mu.Fatalf("error marshaling private stage key: %v", err)
	}

	lk, err := MarshalPrivateEKToPEM(state.Lk)
	if err != nil {
		mu.Fatalf("error marshalling private leaf key: %v", err)
	}
	return &treeJson{publicTree, sk, lk, state.IKeys}
}

// UnmarshallTreeState converts the unmarshalled JSON state to a TreeState
func UnMarshallTreeState(tree *treeJson) *TreeState {
	var err error
	var treeState TreeState

	treeState.IKeys = tree.IKeys

	treeState.PublicTree, err = UnmarshalKeysToPublicTree(tree.PublicTree)
	if err != nil {
		mu.Fatalf("error unmarshalling private tree from TREE_FILE", err)
	}

	treeState.Sk, err = UnmarshalPrivateIKFromPEM(tree.Sk)
	if err != nil {
		mu.Fatalf("error unmarshalling private stage key from TREE_FILE: %v", err)
	}

	treeState.Lk, err = UnmarshalPrivateEKFromPEM(tree.Lk)
	if err != nil {
		mu.Fatalf("error unmarshalling private leaf key from TREE_FILE: %v", err)
	}

	return &treeState
}

// The UnMarshallTreeState method is like [UnmarshallTreeState], but
// initializes the receiver.
func (treeState *TreeState) UnMarshallTreeState(tree *treeJson) {
	var err error

	treeState.IKeys = tree.IKeys

	treeState.PublicTree, err = UnmarshalKeysToPublicTree(tree.PublicTree)
	if err != nil {
		mu.Fatalf("error unmarshalling private tree from TREE_FILE", err)
	}

	treeState.Sk, err = UnmarshalPrivateIKFromPEM(tree.Sk)
	if err != nil {
		mu.Fatalf("error unmarshalling private stage key from TREE_FILE: %v", err)
	}

	treeState.Lk, err = UnmarshalPrivateEKFromPEM(tree.Lk)
	if err != nil {
		mu.Fatalf("error unmarshalling private leaf key from TREE_FILE: %v", err)
	}
}

// ReadTreeState reads an unmarshalles a JSON tree state file.
func ReadTreeState(treeStateFile string) *TreeState {
	var tree treeJson

	treeFile, err := os.Open(treeStateFile)
	if err != nil {
		mu.Fatalf("error opening file %s", treeStateFile)
	}

	decoder := json.NewDecoder(treeFile)
	err = decoder.Decode(&tree)
	if err != nil {
		mu.Fatalf("error reading tree state from %s", treeStateFile)
	}

	defer treeFile.Close()

	return UnMarshallTreeState(&tree)
}

// UpdatePublicTree updates the full tree with the new leaf and path keys.
func UpdatePublicTree(pathKeys []*ecdh.PublicKey, root *PublicNode,
	idx int) *PublicNode {
	// height of 0 means we're at the leaf
	if root.Height == 0 {
		root.UpdatePk(pathKeys[0])
		// copathNodes = append(copathNodes, root)
		return root
	}

	// leaf is in the left subtree
	if idx <= int(math.Pow(2, float64(root.Height)))/2 {
		root.UpdatePk(pathKeys[len(pathKeys)-1])
		root.Left = UpdatePublicTree(pathKeys[:len(pathKeys)-1], root.Left, idx)

	} else { // leaf is in the right subtree
		idx = idx - int(math.Pow(2, float64(root.Height)))/2
		root.UpdatePk(pathKeys[len(pathKeys)-1])
		root.Right = UpdatePublicTree(pathKeys[:len(pathKeys)-1], root.Right, idx)
	}
	return root
}

// UpdateCoPathNodes updates the nodes on the copath for the group member at
// the given index.  It returns the private keys on the path from the member's
// leaf to the root.
func UpdateCoPathNodes(index int, state *TreeState) []*ecdh.PrivateKey {
	// get the copath nodes
	copathNodes := make([]*ecdh.PublicKey, 0)
	copathNodes = CoPath(state.PublicTree, index, copathNodes)

	// with the leaf key, derive the private keys on the path up to the root
	pathKeys, err := PathNodeKeys(state.Lk, copathNodes)
	if err != nil {
		mu.Fatalf("error deriving the new private path keys: %v", err)
	}

	return pathKeys
}

func generateTree(leafKeys []*ecdh.PrivateKey) (*ecdh.PrivateKey, *PublicNode) {
	treeRoot, err := CreateTree(leafKeys)
	if err != nil {
		mu.Fatalf("failed to create ART tree: %v", err)
	}

	treePublic := treeRoot.PublicKeys()
	treeSecret := treeRoot.GetSk() // TODO: rename to just treeRoot.Key(); // this is tk

	return treeSecret, treePublic
}
