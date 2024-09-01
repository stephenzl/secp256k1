package secp256k1

/*
#cgo CFLAGS: -Isrc
#define USE_BASIC_CONFIG
#define ENABLE_MODULE_GENERATOR
#define ENABLE_MODULE_BULLETPROOF
#include <string.h>
#include "basic-config.h"
#include "secp256k1.c"
#include "precomputed_ecmult.c"
#include "precomputed_ecmult_gen.c"
*/
import "C"

import (
	"crypto/rand"
	"sync"
)

type RangeProof [675]byte

var (
	mu sync.RWMutex

	context = C.secp256k1_context_create(
		C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)
	generators = C.secp256k1_bulletproof_generators_create(
		context, &C.secp256k1_generator_const_g, 256)
)

func makeRandomBytes() (b [32]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return
}

func randomizeContext() {
	seed := makeRandomBytes()
	if C.secp256k1_context_randomize(context, (*C.uchar)(&seed[0])) != 1 {
		panic("secp256k1_context_randomize failed")
	}
}

func NewRangeProof(value uint64, blind [32]byte,
	message, extraData []byte) (proof RangeProof) {

	mu.Lock()
	defer mu.Unlock()
	randomizeContext()

	var (
		scratch      = C.secp256k1_scratch_space_create(context, 1<<28)
		proofLen     = C.size_t(len(proof))
		blindPtr     = C.CBytes(blind[:])
		blinds       = []*C.uchar{(*C.uchar)(blindPtr)}
		nonce        = makeRandomBytes()
		privateNonce = makeRandomBytes()
	)

	ret := C.secp256k1_bulletproof_rangeproof_prove(context,
		scratch, generators, (*C.uchar)(&proof[0]), &proofLen,
		nil, nil, nil, (*C.uint64_t)(&value), nil, &blinds[0], nil, 1,
		&C.secp256k1_generator_const_h, 64, (*C.uchar)(&nonce[0]),
		(*C.uchar)(&privateNonce[0]), (*C.uchar)(&extraData[0]),
		C.size_t(len(extraData)), (*C.uchar)(&message[0]))

	C.free(blindPtr)
	C.secp256k1_scratch_space_destroy(context, scratch)

	if ret != 1 {
		panic("secp256k1_bulletproof_rangeproof_prove failed")
	}
	return
}

func (proof *RangeProof) Verify(commit [33]byte, extraData []byte) bool {
	mu.RLock()
	defer mu.RUnlock()

	var (
		scratch = C.secp256k1_scratch_space_create(context, 1<<28)
		com     C.secp256k1_pedersen_commitment
	)

	ret := C.secp256k1_pedersen_commitment_parse(
		context, &com, (*C.uchar)(&commit[0]))
	if ret != 1 {
		panic("secp256k1_pedersen_commitment_parse failed")
	}

	ret = C.secp256k1_bulletproof_rangeproof_verify(context, scratch,
		generators, (*C.uchar)(&proof[0]), C.size_t(len(proof)),
		nil, &com, 1, 64, &C.secp256k1_generator_const_h,
		(*C.uchar)(&extraData[0]), C.size_t(len(extraData)))

	C.secp256k1_scratch_space_destroy(context, scratch)

	return ret == 1
}
