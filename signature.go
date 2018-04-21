package xnyss

import (
	"github.com/Re0h/wotscoin/gocoin/lib/xnyss/wotsp256"
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
	LeftHash    []byte
	RightHash   []byte
	ParentTxid  []byte
	ParentInput uint8
	SigBytes    []byte
}

func NewSignature(sigBytes, msg []byte) (sig *Signature, err error) {
	if len(sigBytes) < wotsp256.SigLen+32+32+1+32+32 {
		err = ErrInvalidSigEncoding
		return
	}

	sig = &Signature{
		SigBytes:   make([]byte, wotsp256.SigLen),
		PubSeed:    make([]byte, 32),
		Message:    make([]byte, 32),
		LeftHash:   make([]byte, 32),
		RightHash:  make([]byte, 32),
		ParentTxid: make([]byte, 32),
	}

	copy(sig.Message, msg)
	copy(sig.SigBytes, sigBytes)
	copy(sig.PubSeed, sigBytes[wotsp256.SigLen:])
	copy(sig.ParentTxid, sigBytes[wotsp256.SigLen+32:])
	sig.ParentInput = sigBytes[wotsp256.SigLen+64]
	copy(sig.LeftHash, sigBytes[wotsp256.SigLen+65:])
	copy(sig.RightHash, sigBytes[wotsp256.SigLen+97:])

	return
}

func (sig *Signature) PublicKey() ([]byte, error) {
	if len(sig.Message) == 0 {
		return nil, ErrSigMsgNotSet
	}

	s := sha256.New()
	s.Write(sig.Message)
	s.Write(sig.LeftHash)
	s.Write(sig.RightHash)

	return wotsp256.PkFromSig(sig.SigBytes, s.Sum(nil), sig.PubSeed, wotsp256.Address{}), nil
}

func (sig *Signature) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(sig.SigBytes)
	buf.Write(sig.PubSeed)
	buf.Write(sig.ParentTxid)
	buf.WriteByte(sig.ParentInput)
	buf.Write(sig.LeftHash)
	buf.Write(sig.RightHash)

	return buf.Bytes()
}
