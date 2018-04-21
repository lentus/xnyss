package wotsp256

import (
	"testing"
	"crypto/rand"
	"github.com/Re0h/wotsp256/testdata"
)

func TestAll(t *testing.T) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		t.Fatal(err)
	}

	pubSeed := make([]byte, 32)
	_, err = rand.Read(pubSeed)
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	if err != nil {
		t.Fatal(err)
	}

	pubKey := GenPublicKey(seed, pubSeed, Address{})
	signed := Sign(msg, seed, pubSeed, Address{})

	t.Log("Sig len", len(signed))
	t.Log("Pk  len", len(pubKey))

	if !Verify(pubKey, signed, msg, pubSeed, Address{}) {
		t.Fail()
	}
}

func BenchmarkGenPublicKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GenPublicKey(testdata.Seed, testdata.PubSeed, Address{})
	}
}

func BenchmarkSign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Sign(testdata.Message, testdata.Seed, testdata.PubSeed, Address{})
	}
}

func BenchmarkPkFromSig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = PkFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, Address{})
	}
}


