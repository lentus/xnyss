// Implements the eXtended Naor-Yung Signature Scheme (XNYSS). Note that the
// NYTree struct is not thread safe.
package xnyss

import (
	wotsp "github.com/Re0h/xnyss/wotsp256"
	"errors"
	"bytes"
	"crypto/sha256"
)

const (
	MsgLen    = 32
	SigLen    = wotsp.SigLen
	PubKeyLen = wotsp.PubKeyLen
)

// Denotes the amount of confirmations (or block depth) that are required before
// a node can be used to create new signatures.
var ConfirmsRequired uint8 = 1

// Denotes the branching factor when using long-term keys
var Branches = 3

var (
	ErrInvalidMsgLen     = errors.New("invalid message length (must be 32 bytes)")
	ErrTreeInvalidInput  = errors.New("invalid input, must contain at least a private and a public seed")
	ErrTreeNoneAvailable = errors.New("no signature nodes available")
	ErrTreeBackupOneTime = errors.New("cannot create a backup of a one-time tree")
	ErrTreeBackupFailed  = errors.New("more backup nodes requested than are available")
)

type NYTree struct {
	nodes       []*nyNode
	rootSeed    []byte
	rootPubSeed []byte
	ots         bool
}

// Creates a new Naor-Yung chain tree using the given secret and public seeds.
func New(seed, pubSeed []byte, ots bool) *NYTree {
	root := &nyNode{
		privSeed: make([]byte, 32),
		pubSeed:  make([]byte, 32),
		txid:     make([]byte, 32),
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
	tree.ots = ots

	return tree
}

// Returns the long-term public key of a tree.
func (t *NYTree) PublicKey() []byte {
	return wotsp.GenPublicKey(t.rootSeed, t.rootPubSeed, &wotsp.Address{})
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
func (t *NYTree) Sign(msg, txid []byte) (*Signature, error) {
	if len(msg) > MsgLen {
		return nil, ErrInvalidMsgLen
	}

	index := t.getSignNode(txid)
	if index < 0 {
		return nil, ErrTreeNoneAvailable
	}

	// Create a signature, retrieving the next nodes to add to the tree
	sig, childNodes, err := t.nodes[index].sign(msg, txid, t.ots)
	if err != nil {
		return nil, err
	}

	// Remove used node from the tree
	t.nodes = append(t.nodes[:index], t.nodes[index+1:]...)

	// Add child nodes to the tree
	if !t.ots && childNodes != nil {
		for i := range childNodes {
			t.nodes = append(t.nodes, childNodes[i])
		}
	}

	return sig, nil
}

// Returns a list of public key hashes of unconfirmed nodes present in the tree.
func (t *NYTree) Unconfirmed() (pkhashes [][]byte) {
	idxs := make([]int, 0, len(t.nodes))
	for idx, node := range t.nodes {
		if node.confirms >= ConfirmsRequired {
			continue
		}

		idxs = append(idxs, idx)
	}

	pkhashes = make([][]byte, len(idxs))
	for i, idx := range idxs {
		pkh := sha256.Sum256(t.nodes[idx].genPubKey())

		pkhashes[i] = make([]byte, 32)
		copy(pkhashes[i], pkh[:])
	}

	return
}

// Sets the confirmation count of all nodes in the tree with the given txid to
// the given number of confirmations.
//
// Because we have to calculate the public key hash for every node on the fly,
// this function can be a performance hog if you need to confirm many nodes. We
// can speed this up by saving the public key hash of every (unconfirmed) node,
// which would increase the size of every node with 32 bytes. Depending on the
// amount of (unconfirmed) nodes that are in the state, this could be an
// acceptable tradeoff. An ameliorating factor is that when we are confirming a
// batch of nodes, the performance of this function will improve after every
// call since each time an additional node will be confirmed.
func (t *NYTree) Confirm(pkh []byte, confirms uint8) {
	for _, node := range t.nodes {
		if node.confirms >= ConfirmsRequired {
			continue
		}

		nodePkh := sha256.Sum256(node.genPubKey())
		if bytes.Equal(pkh, nodePkh[:]) {
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

// Create a backup of the tree t by moving 'count' nodes of t to a new tree. A
// backup can only be created if the original tree contains more than one node
// that is available for signing (i.e. has at least ConfirmsRequired
// confirmations).
func (t *NYTree) Backup(count int) (*NYTree, error) {
	if t.ots {
		return nil, ErrTreeBackupOneTime
	}

	backup := &NYTree{
		ots:         t.ots,
		rootSeed:    make([]byte, 32),
		rootPubSeed: make([]byte, 32),
		nodes:       make([]*nyNode, 0, count),
	}

	// When not enough nodes are available, return a backup tree without nodes.
	// This can be useful to make sure deterministic wallets using this backup
	// correctly see no signatures are available, and do not create a new state
	// including a root node (which might have already been used).
	if count >= t.Available(nil) {
		return backup, ErrTreeBackupFailed
	}

	copy(backup.rootSeed, t.rootSeed)
	copy(backup.rootPubSeed, t.rootPubSeed)
	// After removing a node from t.nodes, start from the beginning again to
	// prevent issues with indexing.
	for added := 0; added < count; added++ {
		for i := range t.nodes {
			if t.nodes[i].confirms >= ConfirmsRequired {
				node := t.nodes[i]
				// Remove node i from t's node list ...
				t.nodes = append(t.nodes[:i], t.nodes[i+1:]...)
				// ... and add it to the backup tree.
				backup.nodes = append(backup.nodes, node)
				break
			}
		}
	}

	return backup, nil
}

// Wipes secret data.
func (t *NYTree) Wipe() {
	for _, node := range t.nodes {
		node.wipe()
	}

	for i := range t.rootSeed {
		t.rootSeed[i] = 0
	}
}

// Returns a byte representation of the tree t.
func (t *NYTree) Bytes() []byte {
	buf := &bytes.Buffer{}

	if t.ots {
		buf.WriteByte(0x01)
	} else {
		buf.WriteByte(0x00)
	}

	buf.Write(t.rootSeed)
	buf.Write(t.rootPubSeed)

	for _, node := range t.nodes {
		buf.Write(node.bytes())
	}

	return buf.Bytes()
}

// Loads an existing Naor-Yung chain tree from bytes.
func Load(b []byte) (*NYTree, error) {
	if len(b) < 65 {
		return nil, ErrTreeInvalidInput
	}

	tree := &NYTree{
		nodes:       make([]*nyNode, 0, (len(b)-65)/nodeByteLen),
		rootSeed:    make([]byte, 32),
		rootPubSeed: make([]byte, 32),
	}

	tree.ots = b[0] == 0x01
	copy(tree.rootSeed, b[1:33])
	copy(tree.rootPubSeed, b[33:65])

	for offset := 65; offset < len(b); {
		node, bytesRead, err := loadNode(b[offset:])
		if err != nil {
			return nil, err
		}

		tree.nodes = append(tree.nodes, node)
		offset += bytesRead
	}

	return tree, nil
}
