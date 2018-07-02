package wotsp256

import (
	"encoding/binary"
	"bytes"
)

const n = 32
const w = 256
const l1 = 32
const l2 = 2
const l = l1 + l2

const MsgLen = n
const SigLen = l * n
const PubKeyLen = l * n

// Computes the base-256 representation of a binary input.
func base256(x []byte, outlen int) []uint8 {
	baseW := make([]uint8, outlen)
	copy(baseW, x)

	return baseW
}

// Performs the chaining operation using an n-byte input and n-byte seed.
// Assumes the input is the <start>-th element in the chain, and performs
// <steps> iterations.
//
// Scratch is used as a scratch pad: it is pre-allocated to precent every call
// to chain from allocating slices for keys and bitmask. It is used as:
// 		scratch = output || key || bitmask.
func chain(h *hasher, in, scratch []byte, start, steps uint8, adrs *Address) {
	copy(scratch, in)

	for i := start; i < start+steps; i++ {
		adrs.setHash(uint32(i))

		adrs.setKeyAndMask(0)
		h.prfPubSeed(adrs, scratch[32:64])
		adrs.setKeyAndMask(1)
		h.prfPubSeed(adrs, scratch[64:])

		for j := 0; j < n; j++ {
			scratch[j] = scratch[j] ^ scratch[64+j]
		}

		h.hashF(scratch[32:64], scratch[:32])
	}
}

// Expands a 32-byte seed into an (l*n)-byte private key.
func expandSeed(h *hasher) []byte {
	privKey := make([]byte, l*n)
	ctr := make([]byte, 32)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		h.prfPrivSeed(ctr, privKey[i*n:])
	}

	return privKey
}

// Computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed, pubSeed []byte, adrs *Address) []byte {
	h := precompute(seed, pubSeed)

	privKey := expandSeed(h)
	pubKey := make([]byte, l*n)

	// Allocate space for output, key and bit-mask of the chain function calls
	scratch := make([]byte, 96)
	for i := 0; i < l; i++ {
		adrs.setChain(uint32(i))
		chain(h, privKey[i*n:], scratch,0, w-1, adrs)
		copy(pubKey[i*n:(i+1)*n], scratch)
	}

	return pubKey
}

func checksum(msg []uint8) []uint8 {
	csum := uint32(0)
	for i := 0; i < l1; i++ {
		csum += uint32(w - 1 - msg[i])
	}
	csum <<= 8 // 8 - ((l2 * logw) % 8)

	// Length of the checksum is (l2*logw + 7) / 8
	csumBytes := make([]byte, 2)
	// Since bytesLen is always 2, we can truncate it to a uint16.
	binary.BigEndian.PutUint16(csumBytes, uint16(csum))

	return base256(csumBytes, l2)
}

// Signs message msg using the private key generated using the given seed.
func Sign(msg, seed, pubSeed []byte, adrs *Address) []byte {
	h := precompute(seed, pubSeed)

	privKey := expandSeed(h)

	// Compute chain lengths
	lengths := base256(msg, l1)

	// Compute checksum
	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	// Allocate space for output, key and bit-mask of the chain function calls
	scratch := make([]byte, 96)

	// Compute signature
	sig := make([]byte, l*n)
	for i := 0; i < l; i++ {
		adrs.setChain(uint32(i))
		chain(h, privKey[i*n:], scratch,0, lengths[i], adrs)
		copy(sig[i*n:(i+1)*n], scratch)
	}

	return sig
}

// Generates a public key from the given signature
func PkFromSig(sig, msg, pubSeed []byte, adrs *Address) []byte {
	h := precompute(nil, pubSeed)

	// Compute chain lengths
	lengths := base256(msg, l1)

	// Compute checksum
	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	// Allocate space for output, key and bit-mask of the chain function calls
	scratch := make([]byte, 96)

	// Compute public key
	pubKey := make([]byte, l*n)
	for i := 0; i < l; i++ {
		adrs.setChain(uint32(i))
		chain(h, sig[i*n:], scratch, lengths[i], w-1-lengths[i], adrs)
		copy(pubKey[i*n:(i+1)*n], scratch)
	}

	return pubKey
}

// Verifies the given signature on the given message.
func Verify(pk, sig, msg, pubSeed []byte, adrs *Address) bool {
	return bytes.Equal(pk, PkFromSig(sig, msg, pubSeed, adrs))
}

