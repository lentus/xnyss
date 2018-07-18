// Implements WOTSP-SHA2_256 as documented in the IETF XMSS draft
// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)
package wotsp

import (
	"encoding/binary"
	"bytes"
	"runtime"
	"sync"
)

const n = 32
const w = 16
const l1 = 64
const l2 = 3
const l = l1 + l2

const MsgLen = n
const SigLen = l * n
const PubKeyLen = l * n

// Computes the base-16 representation of a binary input.
func base16(x []byte, outlen int) []uint8 {
	var total byte
	in := 0
	out := 0
	bits := uint(0)
	baseW := make([]uint8, outlen)

	for consumed := 0; consumed < outlen; consumed++ {
		if bits == 0 {
			total = x[in]
			in++
			bits += 8
		}

		bits -= 4
		baseW[out] = uint8((total >> bits) & byte(15))
		out++
	}

	return baseW
}

// Performs the chaining operation using an n-byte input and n-byte seed.
// Assumes the input is the <start>-th element in the chain, and performs
// <steps> iterations.
//
// Scratch is used as a scratch pad: it is pre-allocated to precent every call
// to chain from allocating slices for keys and bitmask. It is used as:
// 		scratch = output || key || bitmask.
func chain(h *hasher, routineNr int, in, out, scratch []byte, start, steps uint8, adrs *Address) {
	copy(out, in)

	for i := start; i < start+steps; i++ {
		adrs.setHash(uint32(i))

		adrs.setKeyAndMask(0)
		h.prfPubSeed(routineNr, adrs, scratch[:32])
		adrs.setKeyAndMask(1)
		h.prfPubSeed(routineNr, adrs, scratch[32:64])

		for j := 0; j < n; j++ {
			out[j] = out[j] ^ scratch[32+j]
		}

		h.hashF(routineNr, scratch[:32], out)
	}
}

// Distributes the chains that must be computed between GOMAXPROCS goroutines.
//
// When fromSig is true, in contains a signature and out must be a public key;
// in this case the routines must complete the signature chains so they use
// lengths as start indices. If fromSig is false, we are either computing a
// public key from a private key, or a signature from a private key, so the
// routines use lengths as the amount of iterations to perform.
func computeChains(h *hasher, numRoutines int, in, out []byte, lengths []uint8, adrs *Address, fromSig bool) {
	chainsPerRoutine := (l-1)/numRoutines + 1

	// Initialise scratch pad
	scratch := make([]byte, numRoutines * 64)

	wg := new(sync.WaitGroup)
	for i := 0; i < numRoutines; i++ {
		// Copy address structure
		chainAdrs := new(Address)
		copy(chainAdrs.data[:], adrs.data[:])

		wg.Add(1)
		go func(nr int, scratch []byte, adrs *Address) {
			firstChain := nr * chainsPerRoutine
			lastChain := firstChain + chainsPerRoutine - 1

			// Make sure the last routine ends at the right chain
			if lastChain >= l {
				lastChain = l - 1
			}

			// Compute the hash chains
			for j := firstChain; j <= lastChain; j++ {
				adrs.setChain(uint32(j))
				if fromSig {
					chain(h, nr, in[j*n:(j+1)*n], out[j*n:(j+1)*n], scratch, lengths[j], w-1-lengths[j], adrs)
				} else {
					chain(h, nr, in[j*n:(j+1)*n], out[j*n:(j+1)*n], scratch, 0, lengths[j], adrs)
				}
			}
			wg.Done()
		}(i, scratch[i*64:(i+1)*64], chainAdrs)
	}

	wg.Wait()
}

// Expands a 32-byte seed into an (l*n)-byte private key.
func expandSeed(h *hasher) []byte {
	privKey := make([]byte, l*n)
	ctr := make([]byte, 32)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		h.prfPrivSeed(0, ctr, privKey[i*n:])
	}

	return privKey
}

// Computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed, pubSeed []byte, adrs *Address) []byte {
	numRoutines := runtime.GOMAXPROCS(-1)
	h := precompute(seed, pubSeed, numRoutines)

	// Initialise private key
	privKey := expandSeed(h)

	// Initialise list of chain lengths for full chains
	lengths := make([]uint8, l)
	for i := range lengths {
		lengths[i] = w-1
	}

	// Compute public key
	pubKey := make([]byte, l*n)
	computeChains(h, numRoutines, privKey, pubKey, lengths, adrs, false)

	return pubKey
}

func checksum(msg []uint8) []uint8 {
	csum := uint32(0)
	for i := 0; i < l1; i++ {
		csum += uint32(w - 1 - msg[i])
	}
	csum <<= 4 // 8 - ((l2 * logw) % 8)

	// Length of the checksum is (l2*logw + 7) / 8
	csumBytes := make([]byte, 2)
	// Since bytesLen is always 2, we can truncate csum to a uint16.
	binary.BigEndian.PutUint16(csumBytes, uint16(csum))

	return base16(csumBytes, l2)
}

// Signs message msg using the private key generated using the given seed.
func Sign(msg, seed, pubSeed []byte, adrs *Address) []byte {
	numRoutines := runtime.GOMAXPROCS(-1)
	h := precompute(seed, pubSeed, numRoutines)

	// Initialise private key
	privKey := expandSeed(h)

	// Compute chain lengths
	lengths := base16(msg, l1)

	// Compute checksum
	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	// Compute signature
	sig := make([]byte, l*n)
	computeChains(h, numRoutines, privKey, sig, lengths, adrs, false)

	return sig
}

// Generates a public key from the given signature
func PkFromSig(sig, msg, pubSeed []byte, adrs *Address) []byte {
	numRoutines := runtime.GOMAXPROCS(-1)
	h := precompute(nil, pubSeed, numRoutines)

	lengths := base16(msg, l1)

	// Compute checksum
	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	// Compute public key
	pubKey := make([]byte, l*n)
	computeChains(h, numRoutines, sig, pubKey, lengths, adrs, true)

	return pubKey
}

// Verifies the given signature on the given message.
func Verify(pk, sig, msg, pubSeed []byte, adrs *Address) bool {
	return bytes.Equal(pk, PkFromSig(sig, msg, pubSeed, adrs))
}
