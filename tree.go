// Implements the eXtended Naor-Yung Signature Scheme (XNYSS).
package xnyss

import (
	"errors"
	"github.com/Re0h/wotscoin/gocoin/lib/xnyss/wotsp256"
	"bytes"
)

const (
	MsgLen = 32
	SigLen = wotsp256.SigLen
	PubKeyLen = wotsp256.PubKeyLen
)

// Denotes the amount of confirmations (or block depth) that are required before
// a node can be used to create new signatures.
var ConfirmsRequired uint8 = 6

var (
	ErrInvalidMsgLen     = errors.New("invalid message length (must be 32 bytes)")
	ErrTreeInvalidInput  = errors.New("invalid input, must contain at least a private and a public seed")
	ErrTreeNoneAvailable = errors.New("no signature nodes available")
)

type NYTree struct {
	nodes       []*nyNode
	rootSeed    []byte
	rootPubSeed []byte
	// TODO make thread safe by using a mutex
}

// Creates a new Naor-Yung chain tree using the given secret and public seeds.
func New(seed, pubSeed []byte) *NYTree {
	root := &nyNode{
		privSeed: make([]byte, 32),
		pubSeed:  make([]byte, 32),
		txid:     make([]byte, 32),
		input:    0,
		confirms: ConfirmsRequired, // We can use the root node immediately
	}

	copy(root.privSeed, seed)
	copy(root.pubSeed, pubSeed)

	tree := &NYTree{
		nodes:       make([]*nyNode, 0, 32),
		rootSeed:    make([]byte, 32),
		rootPubSeed: make([]byte, 32),
	}

	copy(tree.rootSeed, seed)
	copy(tree.rootPubSeed, pubSeed)

	tree.nodes = append(tree.nodes, root)

	return tree
}

// Returns the long-term public key of a tree.
func (t *NYTree) PublicKey() []byte {
	return wotsp256.GenPublicKey(t.rootSeed, t.rootPubSeed, wotsp256.Address{})
}

// Searches for a node in the tree that can be used to create a new signature.
// A node can be used if it has been confirmed (has at least ConfirmsRequired
// confirmations), or if it's txid matches the txid we want to create a
// signature for. If no nodes are available, an ErrTreeNoneAvailable error is
// returned.
//
// First goes through all nodes to find whether there is a node with matching
// txid, so that inputs in the same transaction are all signed in one subtree
// and thus effectively use up only one node in the tree. If no nodes have a
// matching txid, we try to find a confirmed node.
func (t *NYTree) getSignNode(txid []byte) int {
	// Find nodes with the same txid
	for i := range t.nodes {
		if bytes.Equal(t.nodes[i].txid, txid) {
			return i
		}
	}
	// Find confirmed nodes
	for i := range t.nodes {
		if t.nodes[i].confirms >= ConfirmsRequired {
			return i
		}
	}

	return -1
}

// Creates a signature for the given message. The txid and input are used to
// create new nodes in the tree. Returns an error if no nodes are available to
// create new signatures, of if the input message is longer than 32 bytes.
//
// Whenever a signature is created, two new nodes are added to the tree. These
// new nodes can be used in the future to create new signatures. The returned
// signature signs the message H(msg||H(pk1)||H(pk2)) where msg is the original
// message passed to this function. Both H(pk1) and H(pk2) are included in the
// returned signature structure.
func (t *NYTree) Sign(msg, txid []byte, input uint8) (*Signature, error) {
	if len(msg) > MsgLen {
		return nil, ErrInvalidMsgLen
	}

	index := t.getSignNode(txid)
	if index < 0 {
		return nil, ErrTreeNoneAvailable
	}

	// Create a signature, retrieving the next nodes to add to the tree
	sig, leftChild, rightChild, err := t.nodes[index].sign(msg, txid, input)
	if err != nil {
		return nil, err
	}

	// Remove used node from the tree, and add child nodes to the tree
	t.nodes = append(t.nodes[:index], t.nodes[index+1:]...)
	t.nodes = append(t.nodes, leftChild, rightChild)

	return sig, nil
}

// Returns a list of unconfirmed txids present in the tree.
// TODO make thread safe
func (t *NYTree) Unconfirmed() (txids [][]byte) {
	for _, node := range t.nodes {
		if node.confirms >= ConfirmsRequired {
			continue
		}

		present := false
		for _, txid := range txids {
			if bytes.Equal(node.txid, txid) {
				present = true
				break
			}
		}

		if !present {
			newTxid := make([]byte, 32)
			copy(newTxid, node.txid)
			txids = append(txids, newTxid)
		}
	}

	return
}

// Sets the confirmation count of all nodes in the tree with the given txid to
// the given number of confirmations.
// TODO make thread safe
func (t *NYTree) Confirm(txid []byte, confirms uint8) {
	for _, node := range t.nodes {
		if bytes.Equal(node.txid, txid) {
			node.confirms = confirms
		}
	}
}

// Returns the amount of signatures that can be created with the tree t. If txid
// is not nil, nodes with a matching txid are counted as valid even if they do
// not have enough confirmations. This is useful when a transaction includes
// multiple inputs: these can all be signed in one subtree.
func (t *NYTree) Available(txid []byte) (n int) {
	for i := range t.nodes {
		if bytes.Equal(t.nodes[i].txid, txid) ||
			t.nodes[i].confirms >= ConfirmsRequired {
			n++
		}
	}

	return
}

// Wipes secret data. Ignores any errors that occur when validating nodes.
// TODO make thread safe
func (t *NYTree) Wipe() {
	for _, node := range t.nodes {
		node.wipe()
	}

	for i := range t.rootSeed {
		t.rootSeed[i] = 0
	}
}

// Returns the byte representation of the tree t.
// TODO make thread safe
func (t *NYTree) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(t.rootSeed)
	buf.Write(t.rootPubSeed)

	for _, node := range t.nodes {
		buf.Write(node.bytes())
	}

	return buf.Bytes()
}

// Loads an existing Naor-Yung chain tree.
func Load(b []byte) (*NYTree, error) {
	if len(b) < 64 {
		return nil, ErrTreeInvalidInput
	}

	tree := &NYTree{
		nodes:       make([]*nyNode, 0, (len(b) - 64)/nodeByteLen),
		rootSeed:    make([]byte, 32),
		rootPubSeed: make([]byte, 32),
	}

	copy(tree.rootSeed, b[:32])
	copy(tree.rootPubSeed, b[32:64])

	for offset := 64; offset < len(b); {
		node, bytesRead, err := loadNode(b[offset:])
		if err != nil {
			return nil, err
		}

		tree.nodes = append(tree.nodes, node)
		offset += bytesRead
	}

	return tree, nil
}
