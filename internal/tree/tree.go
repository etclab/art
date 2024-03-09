package tree

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"art/internal/keyutl"
	"art/internal/mu"
	"art/internal/proto"
)

type Node struct {
	sk     *ecdh.PrivateKey
	left   *Node
	right  *Node
	height int
}

type PublicNode struct {
	pk     *ecdh.PublicKey
	Left   *PublicNode
	Right  *PublicNode
	Height int // a height of zero indicates a leaf node
}

type treeJson struct {
	PublicTree [][]byte
	Sk         []byte
	Lk         []byte
	IKeys      [][]byte
}

type TreeState struct {
	// TODO: maybe add a tracker for the stage number to ensure updates
	// are processed in the correct order
	PublicTree *PublicNode        `json:"publicTree"`
	Sk         ed25519.PrivateKey `json:"stageKey"`
	Lk         *ecdh.PrivateKey   `json:"leafKey"`
	IKeys      [][]byte           `json:"identityKeys"`
}

// XXX: never called
func NodeIsLeaf(node *Node) bool {
	return node.left == nil && node.right == nil
}

// leftSubtreeSize computes the number of leaves in the leftsubtree of a
// tree with x leaves
func leftSubtreeSize(x int) int {
	// 2^{ ceil(log2(x))  -   1}
	exp := math.Ceil(math.Log2(float64(x))) - 1
	return int(math.Pow(2, exp))
}

func CreateTree(leafKeys []*ecdh.PrivateKey) (*Node, error) {
	// base case
	n := len(leafKeys)
	if n == 1 {
		return &Node{sk: leafKeys[0], left: nil, right: nil, height: 0}, nil
	}

	// recurse
	numLeaves := leftSubtreeSize(n)
	left, err := CreateTree(leafKeys[:numLeaves])
	if err != nil {
		return nil, err
	}
	right, err := CreateTree(leafKeys[numLeaves:])
	if err != nil {
		return nil, err
	}

	// compute current node's private key from its children's keys
	pkRight := right.sk.PublicKey()
	raw, err := left.sk.ECDH(pkRight)
	if err != nil {
		return nil, fmt.Errorf("ECDH for node failed: %v", err)
	}
	sk, err := keyutl.UnmarshalPrivateX25519FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal private x25519 key for node: %v", err)
	}

	// compute current node's height from it's children's height
	// it's a complete tree so every non-leaf node will have two children
	height := 0
	if left.height > right.height {
		height = left.height + 1
	} else {
		height = right.height + 1
	}

	return &Node{sk: sk, left: left, right: right, height: height}, nil
}

func (node *Node) PublicKeys() *PublicNode {
	if node == nil {
		return nil
	}

	left := node.left.PublicKeys()
	right := node.right.PublicKeys()
	pk := node.sk.PublicKey()
	// the tree structure is staying the same, so the node heights will be the same
	height := node.height

	return &PublicNode{pk: pk, Left: left, Right: right, Height: height}
}

/*
***
*** Helper functions for private trees ***
***
 */
func (node *Node) MarshalKeys() ([][]byte, error) {
	//key_list := make([]*ecdh.PublicKey, 0)
	marshalled_list := make([][]byte, 0)

	if node == nil {
		return marshalled_list, nil
	}

	node_list := make([](*Node), 0)
	node_list = append(node_list, node)

	for len(node_list) != 0 {
		current := node_list[0]
		//key_list = append(key_list, current.pk)

		marshalledPK, err := keyutl.MarshalPrivateEKToPEM(current.sk)
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

// constructing a private tree from a level-order list of marshalled keys
func UnmarshalKeysToPrivateTree(marshalledKeys [][]byte) (*Node, error) {
	root := &Node{sk: nil, left: nil, right: nil, height: 0}
	nodeQueue := make([]*Node, 0)

	for i := 0; i < len(marshalledKeys); i++ {
		// unmarshal the value
		pk, err := keyutl.UnmarshalPrivateEKFromPEM(marshalledKeys[i])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private EK: %v", err)
		}

		// insert it into the tree
		root, nodeQueue = insertNode(root, pk, nodeQueue)
	}

	updateHeights(root)
	return root, nil
}

func insertNode(root *Node, sk *ecdh.PrivateKey, nodeQueue []*Node) (*Node, []*Node) {
	node := &Node{sk: sk, left: nil, right: nil, height: 0}

	if root.sk == nil {
		root = node
	} else if nodeQueue[0].left == nil {
		nodeQueue[0].left = node
		nodeQueue[0].height = node.height + 1
	} else { //nodeQueue[0].right == nil
		nodeQueue[0].right = node
		if nodeQueue[0].left.height < node.height {
			nodeQueue[0].height = node.height + 1
		}
		nodeQueue = nodeQueue[1:]
	}

	nodeQueue = append(nodeQueue, node)
	return root, nodeQueue
}

func updateHeights(node *Node) *Node {
	if node.left == nil && node.right == nil {
		node.height = 0
		return node
	}

	left := updateHeights(node.left)
	right := updateHeights(node.right)

	if left.height > right.height {
		node.height = left.height + 1
	} else {
		node.height = right.height + 1
	}
	return node
}

// XXX: probably don't need this getter
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

		marshalledPK, err := keyutl.MarshalPublicEKToPEM(current.pk)
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

func (publicNode *PublicNode) GetPk() *ecdh.PublicKey {
	return publicNode.pk
}

func (publicNode *PublicNode) UpdatePk(newPK *ecdh.PublicKey) {
	publicNode.pk = newPK
}

// constructing a public tree from a level-order list of marshalled keys
func UnmarshalKeysToPublicTree(marshalledKeys [][]byte) (*PublicNode, error) {
	root := &PublicNode{pk: nil, Left: nil, Right: nil}
	nodeQueue := make([]*PublicNode, 0)

	for i := 0; i < len(marshalledKeys); i++ {
		// unmarshal the value
		pk, err := keyutl.UnmarshalPublicEKFromPEM(marshalledKeys[i])
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

func DeriveLeafKey(ekPath string, suk *ecdh.PublicKey) (*ecdh.PrivateKey, error) {
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

// TODO: this goes into proto.go
func PathNodeKeys(leafKey *ecdh.PrivateKey, copathKeys []*ecdh.PublicKey) ([]*ecdh.PrivateKey, error) {
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

func MarshallTreeState(state *TreeState) *treeJson {
	publicTree, err := state.PublicTree.MarshalKeys()
	if err != nil {
		mu.Die("failed to marshal the public keys: %v", err)
	}

	sk, err := keyutl.MarshalPrivateIKToPEM(state.Sk)
	if err != nil {
		mu.Die("error marshaling private stage key: %v", err)
	}

	lk, err := keyutl.MarshalPrivateEKToPEM(state.Lk)
	if err != nil {
		mu.Die("error marshalling private leaf key: %v", err)
	}
	return &treeJson{publicTree, sk, lk, state.IKeys}
}

func SaveTreeState(outStateFile string, state *TreeState) {
	treeFile, err := os.Create(outStateFile)
	if err != nil {
		mu.Die("error creating out-state file %v: %v", outStateFile, err)
	}
	defer treeFile.Close()

	enc := json.NewEncoder(treeFile)
	treeJson := MarshallTreeState(state)
	enc.Encode(treeJson)
}

func UnMarshallTreeState(tree *treeJson) *TreeState {
	var err error
	var treeState TreeState

	treeState.IKeys = tree.IKeys

	treeState.PublicTree, err = UnmarshalKeysToPublicTree(tree.PublicTree)
	if err != nil {
		mu.Die("error unmarshalling private tree from TREE_FILE", err)
	}

	treeState.Sk, err = keyutl.UnmarshalPrivateIKFromPEM(tree.Sk)
	if err != nil {
		mu.Die("error unmarshalling private stage key from TREE_FILE: %v", err)
	}

	treeState.Lk, err = keyutl.UnmarshalPrivateEKFromPEM(tree.Lk)
	if err != nil {
		mu.Die("error unmarshalling private leaf key from TREE_FILE: %v", err)
	}

	return &treeState
}

func ReadTreeState(treeStateFile string) *TreeState {
	var tree treeJson

	treeFile, err := os.Open(treeStateFile)
	if err != nil {
		mu.Die("error opening file %s", treeStateFile)
	}

	decoder := json.NewDecoder(treeFile)
	err = decoder.Decode(&tree)
	if err != nil {
		mu.Die("error reading tree state from %s", treeStateFile)
	}

	defer treeFile.Close()

	return UnMarshallTreeState(&tree)
}
