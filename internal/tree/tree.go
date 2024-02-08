package tree

import (
	"crypto/ecdh"
	"fmt"
	"math"

	"art/internal/keyutl"
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
