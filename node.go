package xnyss

import (
	"github.com/Re0h/wotscoin/gocoin/lib/xnyss/wotsp256"
	"crypto/sha256"
	"crypto/rand"
	"errors"
	"bytes"
)

const nodeByteLen = 32 + 32 + 32 + 1 + 1

var (
	ErrNodeInvalidInput = errors.New("input is not a valid node")
)

// Represents a node in the signature tree
type nyNode struct {
	txid     []byte
	input    uint8
	pubSeed  []byte
	privSeed []byte
	confirms uint8
}

func loadNode(b []byte) (*nyNode, int, error) {
	if len(b) < nodeByteLen {
		return nil, 0, ErrNodeInvalidInput
	}

	return &nyNode{
		privSeed: b[0:32],
		pubSeed:  b[32:64],
		txid:     b[64:96],
		input:    b[96],
		confirms: b[97],
	}, nodeByteLen, nil
}

// Generates child nodes of the current node.
func (n *nyNode) childNodes(txid []byte, input uint8) (leftChild, rightChild *nyNode, err error) {
	r := make([]byte, 128)
	_, err = rand.Read(r)
	if err != nil {
		return
	}

	// Generate left child node
	leftChild = &nyNode{
		txid:     txid,
		input:    input,
		privSeed: r[:32],
		pubSeed:  r[32:64],
		confirms: 0,
	}

	// Generate right child node
	rightChild = &nyNode{
		txid:     txid,
		input:    input,
		privSeed: r[64:96],
		pubSeed:  r[96:128],
		confirms: 0,
	}

	return
}

func (n *nyNode) genPubKey() []byte {
	return wotsp256.GenPublicKey(n.privSeed, n.pubSeed, wotsp256.Address{})
}

func genPubKeyHash(node *nyNode, c chan []byte) {
	pubKey := node.genPubKey()
	s := sha256.New()
	s.Write(pubKey)
	c <- s.Sum(nil)
}

func (n *nyNode) sign(msg, txid []byte, input uint8) (sig *Signature, leftChild, rightChild *nyNode, err error) {
	leftChild, rightChild, err = n.childNodes(txid, input)
	if err != nil {
		err = errors.New("failed to create child nodes " + err.Error())
		return
	}

	// Calculate the child nodes' public keys concurrently
	c := make(chan []byte)
	go genPubKeyHash(leftChild, c)
	go genPubKeyHash(rightChild, c)
	leftHash, rightHash := <-c, <-c

	// Write message to be signed
	buf := &bytes.Buffer{}
	buf.Write(msg)
	buf.Write(leftHash)
	buf.Write(rightHash)

	s:= sha256.New()
	s.Write(buf.Bytes())
	sigBytes := wotsp256.Sign(s.Sum(nil), n.privSeed, n.pubSeed, wotsp256.Address{})

	sig = &Signature{
		PubSeed:     n.pubSeed,
		Message:     msg,
		LeftHash:    leftHash,
		RightHash:   rightHash,
		SigBytes:    sigBytes,
		ParentTxid:  n.txid,
		ParentInput: n.input,
	}

	return
}

func (n *nyNode) bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(n.privSeed)
	buf.Write(n.pubSeed)
	buf.Write(n.txid)
	buf.WriteByte(n.input)
	buf.WriteByte(n.confirms)

	return buf.Bytes()
}

func (n *nyNode) wipe() {
	for i := range n.privSeed {
		n.privSeed[i] = 0
	}
}
