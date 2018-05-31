package xnyss

import (
	wotsp "github.com/Re0h/xnyss/wotsp256"
	"crypto/sha256"
	"errors"
	"bytes"
)

var (
	ErrInvalidSigEncoding = errors.New("invalid signature encoding")
	ErrSigMsgNotSet       = errors.New("signature message is not set")
)

type Signature struct {
	PubSeed     []byte
	Message     []byte
	ChildHashes [][]byte
	SigBytes    []byte
}

func NewSignature(sigBytes, msg []byte) (sig *Signature, err error) {
	if len(sigBytes) < wotsp.SigLen+32 || (len(sigBytes) - (wotsp.SigLen+32)) % 32 != 0 {
		err = ErrInvalidSigEncoding
		return
	}

	sig = &Signature{
		SigBytes:   make([]byte, wotsp.SigLen),
		PubSeed:    make([]byte, 32),
		Message:    make([]byte, 32),
	}

	copy(sig.Message, msg)
	copy(sig.SigBytes, sigBytes)
	copy(sig.PubSeed, sigBytes[wotsp.SigLen:])

	childBytes := sigBytes[wotsp.SigLen+32:]
	if len(childBytes) > 0 {
		sig.ChildHashes = make([][]byte, len(childBytes) / 32)

		for i := range sig.ChildHashes {
			sig.ChildHashes[i] = make([]byte, 32)
			copy(sig.ChildHashes[i], childBytes[i*32:])
		}
	}

	return
}

func (sig *Signature) PublicKey() ([]byte, error) {
	if len(sig.Message) == 0 {
		return nil, ErrSigMsgNotSet
	}

	s := sha256.New()
	s.Write(sig.Message)

	if sig.ChildHashes != nil {
		for i := range sig.ChildHashes {
			s.Write(sig.ChildHashes[i])
		}
	}

	return wotsp.PkFromSig(sig.SigBytes, s.Sum(nil), sig.PubSeed, &wotsp.Address{}), nil
}

func (sig *Signature) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(sig.SigBytes)
	buf.Write(sig.PubSeed)

	if sig.ChildHashes != nil {
		for i := range sig.ChildHashes {
			buf.Write(sig.ChildHashes[i])
		}
	}

	return buf.Bytes()
}
