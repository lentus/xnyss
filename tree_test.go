package xnyss

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"fmt"
	wotsp "github.com/Re0h/xnyss/wotsp256"
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
	sig, err := tree.Sign(msgHash[:], txid)
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

	tree := New(seed, pubSeed, false)
	if len(tree.nodes) != 1 {
		t.Fatal(fmt.Printf("%d nodes added, should be 1", len(tree.nodes)))
	}
	if tree.ots {
		t.Fatal("Tree was incorrectly labeled as one-time")
	}

	treePubKey := tree.PublicKey()
	wotsPubKey := wotsp.GenPublicKey(seed, pubSeed, &wotsp.Address{})

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
	tree := New(seed, pubSeed, false)

	// 1 - Sign with root node
	sigRoot, txid, err := signMessage("first signature test", tree)
	if err != nil {
		t.Fatal("Failed to sign msg with root -", err)
	}

	sigPubKey, _ := sigRoot.PublicKey()
	if !bytes.Equal(tree.PublicKey(), sigPubKey) {
		t.Fatal("Verification of root signature failed")
	}
	if len(tree.nodes) != Branches {
		t.Fatal("Failed to add new nodes correctly")
	}

	// 2 - Create another signature without confirming the previous one
	_, _, err = signMessage("Sign test with node 1", tree)
	if err != ErrTreeNoneAvailable {
		t.Fatal("Signing should have failed (no available nodes)")
	}

	// 3 - Create another signature with the same txid
	msgHash := sha256.Sum256([]byte("test message 2"))
	sig2, err := tree.Sign(msgHash[:], txid)
	if err != nil {
		t.Fatal("Failed to sign with existing txid -", err)
	}
	if len(tree.nodes) != 2*Branches-1 {
		t.Fatal("Failed to add new nodes correctly (second signature)")
	}

	sig2PubKey, _ := sig2.PublicKey()
	sig2PubKeyHash := sha256.Sum256(sig2PubKey)
	// 4 - Check that sig2's public key hash matches one of sigRoot's child hashes
	foundMatch := false
	for i := range sigRoot.ChildHashes {
		if bytes.Equal(sig2PubKeyHash[:], sigRoot.ChildHashes[i]) {
			foundMatch = true
		}
	}
	if !foundMatch {
		t.Fatal("Invalid public key generated from second signature")
	}
}

func TestNYTree_Confirm(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed, false)

	sig, _, err := signMessage("first signature test", tree)
	if err != nil {
		t.Fatal("Failed to sign msg with root -", err)
	}

	tree.Confirm(sig.ChildHashes[0], ConfirmsRequired)

	_, _, err = signMessage("test message 2", tree)
	if err != nil {
		t.Fatal("Failed to sign msg after confirming upkh -", err)
	}
}

func TestNYTree_Unconfirmed(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed, false)

	// 1 - check unconfirmed txids after creating a new tree
	if len(tree.Unconfirmed()) > 0 {
		t.Fatal(len(tree.Unconfirmed()), "unconfirmed upkh(s), should be 0")
	}

	// 2 - check unconfirmed txids after signing a message
	sig, _, err := signMessage("first signature test", tree)
	if err != nil {
		t.Fatal("Failed to sign msg with root -", err)
	}

	if len(tree.Unconfirmed()) != Branches {
		t.Fatal(len(tree.Unconfirmed()), "unconfirmed upkh(s), should be", Branches)
	}

	// 3 - check unconfirmed txids after signing two more messages
	for _, pkh := range sig.ChildHashes {
		tree.Confirm(pkh[:], ConfirmsRequired)
	}

	_, _, err = signMessage("second test message", tree)
	if err != nil {
		t.Fatal("Failed to sign second msg -", err)
	}

	_, _, err = signMessage("third test message", tree)
	if err != nil {
		t.Fatal("Failed to sign third msg -", err)
	}

	pkhs := tree.Unconfirmed()
	if len(pkhs) != 2*Branches {
		t.Fatal(len(pkhs), "unconfirmed upkh(s), should be", 2*Branches)
	}
}

func TestNYTree_Available(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed, false)

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
	if tree.Available(txid) != Branches {
		t.Fatal(fmt.Printf("%d nodes available, should be 2", tree.Available(txid)))
	}

	// 5 - Verify that after confirming txid 2 nodes are available
	tree.Confirm(txid, ConfirmsRequired)
	if tree.Available(txid) != Branches {
		t.Fatal(fmt.Printf("%d nodes available, should be 2", tree.Available(txid)))
	}
}

func TestNYTree_Bytes(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed, false)

	// Serialise empty tree
	empty := tree.Bytes()
	if empty[0] != 0x00 || !bytes.Equal(tree.rootSeed, empty[1:33]) ||
		!bytes.Equal(tree.rootPubSeed, empty[33:65]) {
		t.Fatal("Serialisation of empty tree failed")
	}

	// Create a few signatures
	sig, _, err := signMessage("first signature", tree)
	if err != nil {
		t.Fatal("Failed to sign -", err)
	}

	tree.Confirm(sig.ChildHashes[0], ConfirmsRequired)
	if err != nil {
		t.Fatal("Failed to confirm upkh -", err)
	}
	_, _, err = signMessage("second signature", tree)
	if err != nil {
		t.Fatal("Failed to sign -", err)
	}

	// Check serialisation
	treeBytes := tree.Bytes()
	if !bytes.Equal(treeBytes[1:33], tree.rootSeed) ||
		!bytes.Equal(treeBytes[33:65], tree.rootPubSeed) {
		t.Fatal("Invalid seeds")
	}

	offset := 65
	for _, node := range tree.nodes {
		if !bytes.Equal(node.privSeed, treeBytes[offset:offset+32]) ||
			!bytes.Equal(node.pubSeed, treeBytes[offset+32:offset+64]) ||
			!bytes.Equal(node.txid, treeBytes[offset+64:offset+96]) ||
			node.confirms != treeBytes[offset+96] {
			t.Fatal("Invalid serialized node")
		}
		offset += 97
	}
}

func TestLoad(t *testing.T) {
	empty := make([]byte, 65)
	_, err := rand.Read(empty)
	if err != nil {
		t.Fatal("Failed to create empty tree -", err)
	}
	empty[0] = 0x00

	emptyTree, err := Load(empty)
	if err != nil {
		t.Fatal("Failed to load empty tree -", err)
	}
	if emptyTree.ots || !bytes.Equal(emptyTree.rootSeed, empty[1:33]) ||
		!bytes.Equal(emptyTree.rootPubSeed, empty[33:]) ||
		len(emptyTree.nodes) != 0 {
		t.Fatal("Loaded empty tree incorrectly")
	}

	nodeBytes := make([]byte, 97)
	_, err = rand.Read(nodeBytes[:96])
	if err != nil {
		t.Fatal("Failed to create node -", err)
	}
	nodeBytes[96] = ConfirmsRequired

	oneNode, err := Load(append(empty, nodeBytes...))
	if err != nil {
		t.Fatal("Failed to load tree with only root node -", err)
	}
	if len(oneNode.nodes) != 1 {
		t.Fatal("Failed to load tree node there should be 1, there are ", len(oneNode.nodes))
	}

	node := oneNode.nodes[0]
	if !bytes.Equal(node.privSeed, nodeBytes[:32]) ||
		!bytes.Equal(node.pubSeed, nodeBytes[32:64]) ||
		!bytes.Equal(node.txid, nodeBytes[64:96]) ||
		node.confirms != nodeBytes[96] {
		t.Fatal("Invalid loaded node")
	}
}

func TestOneTime(t *testing.T) {
	seed, pubSeed, err := genSeeds()
	if err != nil {
		t.Fatal(err)
	}
	tree := New(seed, pubSeed, true)

	if !tree.ots {
		t.Fatal("One-time flag was not set")
	}

	sig, _, err := signMessage("Sign test with node 1", tree)
	if err != nil {
		t.Fatal("Failed to sign message")
	}
	if sig.ChildHashes != nil {
		t.Fatal("Child hashes were set, they should not be")
	}
	if sigpk, err := sig.PublicKey(); err != nil || !bytes.Equal(tree.PublicKey(), sigpk) {
		t.Fatal("Invalid public key", err)
	}

	if tree.Available(nil) != 0 {
		t.Fatal("0 nodes should be available, is", tree.Available(nil))
	}

	_, _, err = signMessage("Sign test with node 1", tree)
	if err != ErrTreeNoneAvailable {
		t.Fatal("Signing should have failed with ErrTreeNoneAvailable, err was", err)
	}
}

func benchmarkSign(n int, ots bool, b *testing.B) {
	b.ReportAllocs()

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
		tree := New(seed, pubSeed, ots)
		for i := 0; i < n; i++ {
			_, _ = tree.Sign(msgHash, txid)
		}
	}
}

func BenchmarkSignOnetime(b *testing.B) {
	benchmarkSign(1, true, b)
}

func BenchmarkSignLongterm(b *testing.B) {
	benchmarkSign(1, false, b)
}

/*
func BenchmarkSign10(b *testing.B) {
	benchmarkSign(10, false, b)
}

func BenchmarkSign100(b *testing.B) {
	benchmarkSign(100, false, b)
}

func BenchmarkSign1000(b *testing.B) {
	benchmarkSign(1000, false, b)
}
*/

func BenchmarkKeyGen(b *testing.B) {
	b.ReportAllocs()

	seed, pubSeed, err := genSeeds()
	if err != nil {
		b.Fatal("Failed to generate seeds")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree := New(seed, pubSeed, true)
		_ = tree.PublicKey()
	}
}

func BenchmarkPkFromSig(b *testing.B) {
	b.ReportAllocs()

	seed, pubSeed, err := genSeeds()
	if err != nil {
		b.Fatal("Failed to generate seeds -", err)
	}
	tree := New(seed, pubSeed, true)

	sig, _, err := signMessage("a message to sign", tree)
	if err != nil {
		b.Fatal("Failed to sign message -", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sig.PublicKey()
	}
}
