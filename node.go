package xnyss

import (
	wotsp "github.com/Re0h/xnyss/wotsp256"
	"crypto/sha256"
	"crypto/rand"
	"errors"
	"bytes"
)

const nodeByteLen = 32 + 32 + 32 + 1

var (
	ErrNodeInvalidInput = errors.New("input is not a valid node")
)

// Represents a node in the signature tree
type nyNode struct {
	txid     []byte
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
		confirms: b[96],
	}, nodeByteLen, nil
}

// Generates child nodes of the current node.
func (n *nyNode) childNodes(txid []byte) (children []*nyNode, err error) {
	r := make([]byte, 64*Branches)
	_, err = rand.Read(r)
	if err != nil {
		return
	}
	// TODO generate seeds by hashing n.*seed | randBytes
	children = make([]*nyNode, Branches)
	offset := 0
	for i := range children {
		child := &nyNode{
			txid:     txid,
			privSeed: r[offset:offset+32],
			pubSeed:  r[offset+32:offset+64],
			confirms: 0,
		}

		children[i] = child
		offset += 64
	}

	return
}

func (n *nyNode) genPubKey() []byte {
	return wotsp.GenPublicKey(n.privSeed, n.pubSeed, &wotsp.Address{})
}

func (n *nyNode) sign(msg, txid []byte, ots bool) (sig *Signature, childNodes []*nyNode, err error) {
	childNodes, err = n.childNodes(txid)
	if err != nil {
		err = errors.New("failed to create child nodes " + err.Error())
		return
	}
	childHashes := make([][]byte, len(childNodes))

	// Write message to be signed
	s:= sha256.New()

	// Calculate the child nodes' public key hashes if required
	if !ots {
		for i := range childNodes {
			pubKey := childNodes[i].genPubKey()

			s.Write(pubKey)
			childHashes[i] = s.Sum(nil)
			s.Reset()
		}

	}

	s.Write(msg)
	for i := range childNodes {
		s.Write(childHashes[i])
	}

	sigBytes := wotsp.Sign(s.Sum(nil), n.privSeed, n.pubSeed, &wotsp.Address{})

	sig = &Signature{
		PubSeed:     n.pubSeed,
		Message:     msg,
		SigBytes:    sigBytes,
	}

	if !ots { // If we use a one-time key, we want sig.ChildHashes to be nil
		sig.ChildHashes = childHashes
	}

	return
}

func (n *nyNode) bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(n.privSeed)
	buf.Write(n.pubSeed)
	buf.Write(n.txid)
	buf.WriteByte(n.confirms)

	return buf.Bytes()
}

func (n *nyNode) wipe() {
	for i := range n.privSeed {
		n.privSeed[i] = 0
	}
}
