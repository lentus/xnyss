package xnyss

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"fmt"
	"github.com/Re0h/wotscoin/gocoin/lib/xnyss/wotsp256"
	"bytes"
)

func genSeeds() (seed, pubs []byte, err error) {
	r := make([]byte, 64)
	_, err = rand.Read(r)
	if err != nil {
		return
	}

	return r[:32], r[32:], nil
}

func signMessage(msg string, tree *NYTree) (*Signature, []byte, error) {
	txid := make([]byte, 32)
	if _, err := rand.Read(txid); err != nil {
		return nil, nil, err
	}

	msgHash := sha256.Sum256([]byte(msg))
	sig, err := tree.Sign(msgHash[:], txid, 0)
	if err != nil {
		return nil, nil, err
	}

	return sig, txid, nil
}

func TestNew(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}

	tree := New(seed, pubSeed)
	if len(tree.nodes) != 1 {
		t.Fatal(fmt.Printf("%d nodes added, should be 1", len(tree.nodes)))
	}

	treePubKey := tree.PublicKey()
	wotsPubKey := wotsp256.GenPublicKey(seed, pubSeed, wotsp256.Address{})

	if !bytes.Equal(treePubKey, wotsPubKey) {
		t.Fatal("Wrong long-term public key was generated")
	}

	if !bytes.Equal(tree.nodes[0].genPubKey(), wotsPubKey) {
		t.Fatal("First node generated the wrong public key")
	}
}

func TestNYTree_Sign(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed)

	// 1 - Sign with root node
	sigRoot, txid, err := signMessage("first signature test", tree)
	if err != nil {
		t.Fatal("Failed to sign msg with root -", err)
	}

	sigPubKey, _ := sigRoot.PublicKey()
	if !bytes.Equal(tree.PublicKey(), sigPubKey) {
		t.Fatal("Verification of root signature failed")
	}
	if len(tree.nodes) != 2 {
		t.Fatal("Failed to add new nodes correctly")
	}

	// 2 - Create another signature without confirming the previous one
	_, _, err = signMessage("Sign test with node 1", tree)
	if err != ErrTreeNoneAvailable {
		t.Fatal("Signing should have failed (no available nodes)")
	}

	// 3 - Create another signature with the same txid
	msgHash := sha256.Sum256([]byte("test message 2"))
	sig2, err := tree.Sign(msgHash[:], txid, 0)
	if err != nil {
		t.Fatal("Failed to sign with existing txid -", err)
	}
	if len(tree.nodes) != 3 {
		t.Fatal("Failed to add new nodes correctly (second signature)")
	}

	sig2PubKey, _ := sig2.PublicKey()
	sig2PubKeyHash := sha256.Sum256(sig2PubKey)
	if !bytes.Equal(sig2PubKeyHash[:], sigRoot.LeftHash) &&
		!bytes.Equal(sig2PubKeyHash[:], sigRoot.RightHash) {
		t.Fatal("Invalid public key generated from second signature")
	}
}

func TestNYTree_Confirm(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed)

	_, txid, err := signMessage("first signature test", tree)
	if err != nil {
		t.Fatal("Failed to sign msg with root -", err)
	}

	tree.Confirm(txid, ConfirmsRequired)

	_, _, err = signMessage("test message 2", tree)
	if err != nil {
		t.Fatal("Failed to sign msg after confirming txid -", err)
	}
}

func TestNYTree_Unconfirmed(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed)

	// 1 - check unconfirmed txids after creating a new tree
	txids := tree.Unconfirmed()
	if len(txids) > 0 {
		t.Fatal(len(txids), "unconfirmed txid(s), should be 0")
	}

	// 2 - check unconfirmed txids after signing a message
	_, txid, err := signMessage("first signature test", tree)
	if err != nil {
		t.Fatal("Failed to sign msg with root -", err)
	}

	txids = tree.Unconfirmed()
	if len(txids) != 1 && !bytes.Equal(txids[0], txid) {
		t.Fatal("Retrieved wrong txids")
	}

	// 3 - check unconfirmed txids after signing two more messages
	tree.Confirm(txid, ConfirmsRequired)

	_, txid1, err := signMessage("second test message", tree)
	if err != nil {
		t.Fatal("Failed to sign second msg -", err)
	}
	_, txid2, err := signMessage("third test message", tree)
	if err != nil {
		t.Fatal("Failed to sign third msg -", err)
	}

	txids = tree.Unconfirmed()
	if len(txids) != 2 && !bytes.Equal(txids[0], txid1) && !bytes.Equal(txids[1], txid2) {
		t.Fatal("Retrieved wrong txids")
	}
}

func TestNYTree_Available(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed)

	// 1 - Verify that 1 node is available
	if tree.Available(nil) != 1 {
		t.Fatal(fmt.Printf("%d nodes available, should be 1", tree.Available(nil)))
	}

	// 2 - Sign a message
	_, txid, err := signMessage("second signature test", tree)
	if err != nil {
		t.Fatal("Failed to sign -", err)
	}

	// 3 - Verify that no nodes are available
	if tree.Available(nil) != 0 {
		t.Fatal(fmt.Printf("%d nodes available, should be 0", tree.Available(nil)))
	}

	// 4 - Verify that nodes are available for signing with txid
	if tree.Available(txid) != 2 {
		t.Fatal(fmt.Printf("%d nodes available, should be 2", tree.Available(txid)))
	}

	// 5 - Verify that after confirming txid 2 nodes are available
	tree.Confirm(txid, ConfirmsRequired)
	if tree.Available(txid) != 2 {
		t.Fatal(fmt.Printf("%d nodes available, should be 2", tree.Available(txid)))
	}
}

func TestNYTree_Bytes(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed)

	// Serialise empty tree
	empty := tree.Bytes()
	if !bytes.Equal(tree.rootSeed, empty[:32]) ||
		!bytes.Equal(tree.rootPubSeed, empty[32:64]) {
		t.Fatal("Serialisation of empty tree failed")
	}

	// Create a few signatures
	_, txid, err := signMessage("first signature", tree)
	if err != nil {
		t.Fatal("Failed to sign -", err)
	}

	tree.Confirm(txid, ConfirmsRequired)
	if err != nil {
		t.Fatal("Failed to confirm txid -", err)
	}
	_, _, err = signMessage("second signature", tree)
	if err != nil {
		t.Fatal("Failed to sign -", err)
	}

	// Check serialisation
	treeBytes := tree.Bytes()
	if !bytes.Equal(treeBytes[:32], tree.rootSeed) ||
		!bytes.Equal(treeBytes[32:64], tree.rootPubSeed) {
		t.Fatal("Invalid seeds")
	}

	offset := 64
	for _, node := range tree.nodes {
		if !bytes.Equal(node.privSeed, treeBytes[offset:offset+32]) ||
			!bytes.Equal(node.pubSeed, treeBytes[offset+32:offset+64]) ||
			!bytes.Equal(node.txid, treeBytes[offset+64:offset+96]) ||
			node.input != treeBytes[offset+96] ||
			node.confirms != treeBytes[offset+97] {
			t.Fatal("Invalid serialized node")
		}
		offset += 98
	}
}

func TestLoad(t *testing.T) {
	empty := make([]byte, 64)
	_, err := rand.Read(empty)
	if err != nil {
		t.Fatal("Failed to create empty tree -", err)
	}

	emptyTree, err := Load(empty)
	if err != nil {
		t.Fatal("Failed to load empty tree -", err)
	}
	if !bytes.Equal(emptyTree.rootSeed, empty[:32]) ||
		!bytes.Equal(emptyTree.rootPubSeed, empty[32:]) ||
		len(emptyTree.nodes) != 0 {
			t.Fatal("Loaded empty tree incorrectly")
	}

	nodeBytes := make([]byte, 98)
	_, err = rand.Read(nodeBytes[:97])
	if err != nil {
		t.Fatal("Failed to create node -", err)
	}
	nodeBytes[97] = ConfirmsRequired

	oneNode, err := Load(append(empty, nodeBytes...))
	if err != nil {
		t.Fatal("Failed to load empty tree -", err)
	}
	if len(oneNode.nodes) != 1 {
		t.Fatal("Failed to load tree node there should be 1, there are ", len(oneNode.nodes))
	}

	node := oneNode.nodes[0]
	if !bytes.Equal(node.privSeed, nodeBytes[:32]) ||
		!bytes.Equal(node.pubSeed, nodeBytes[32:64]) ||
		!bytes.Equal(node.txid, nodeBytes[64:96]) ||
		node.input != nodeBytes[96] ||
		node.confirms != nodeBytes[97] {
		t.Fatal("Invalid loaded node")
	}
}

func benchmarkNYTree_Sign(n int, b *testing.B) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		b.Fatal("Failed to generate seeds -", err)
	}

	s := sha256.New()
	s.Write([]byte("a message to sign"))
	msgHash := s.Sum(nil)

	txid := make([]byte, 32)
	_, err = rand.Read(txid)
	if err != nil {
		b.Fatal("Failed to generate txid -", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree := New(seed, pubSeed)
		for i := 0; i < n; i++ {
			_, _ = tree.Sign(msgHash, txid, 0)
		}
	}
}

func BenchmarkNYTree_Sign1(b *testing.B) {
	benchmarkNYTree_Sign(1, b)
}

func BenchmarkNYTree_Sign10(b *testing.B) {
	benchmarkNYTree_Sign(10, b)
}

func BenchmarkNYTree_Sign100(b *testing.B) {
	benchmarkNYTree_Sign(100, b)
}

func BenchmarkNYTree_Sign1000(b *testing.B) {
	benchmarkNYTree_Sign(1000, b)
}
