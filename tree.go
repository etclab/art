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

// PublicNode is a node in teh public ART tree
type PublicNode struct {
	pk    *ecdh.PublicKey
	Left  *PublicNode
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

// TODO:
type TreeState struct {
	PublicTree *PublicNode
	Sk         ed25519.PrivateKey
	Lk         *ecdh.PrivateKey
	IKeys      [][]byte
}

// TODO:
func (treeState *TreeState) Save(fileName string) {
	treeJson := MarshallTreeState(treeState)
	jsonutl.Encode(fileName, treeJson)
}

// TODO:
func (treeState *TreeState) SaveStageKey(fileName string) {
	stageKey := treeState.Sk

	err := WritePrivateIKToFile(stageKey, fileName, EncodingPEM)
	if err != nil {
		mu.Fatalf("error saving stage key: %v", err)
	}
}

// TODO:
func (treeState *TreeState) StageKey() ed25519.PrivateKey {
	return treeState.Sk
}

// TODO:
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

// TODO:
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

// TODO:
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

// TODO:
func CreateTree(leafKeys []*ecdh.PrivateKey) (*Node, error) {
	return createTree(leafKeys, 0, 0)
}

// TODO:
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

// TODO:
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

// TODO:
// constructing a private tree from a level-order list of marshalled keys
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

// TODO:
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

// TODO:
func (publicNode *PublicNode) GetPk() *ecdh.PublicKey {
	return publicNode.pk
}

// TODO:
func (publicNode *PublicNode) UpdatePk(newPK *ecdh.PublicKey) {
	publicNode.pk = newPK
}

// TODO:
// constructing a public tree from a level-order list of marshalled keys
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

// TODO:
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

// TODO:
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

// TODO:
func DeriveLeafKeyOrFail(privKeyFile string, setupKey *ecdh.PublicKey) *ecdh.PrivateKey {
	leafKey, err := DeriveLeafKey(privKeyFile, setupKey)
	if err != nil {
		mu.Fatalf("error deriving the private leaf key: %v", err)
	}
	return leafKey
}

// TODO:
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

// TODO:
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

// TODO:
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

// TODO:
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

// TODO:
// update the full tree with the new leaf and path keys
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

// TODO:
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
