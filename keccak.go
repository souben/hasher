package hasher

import (
	"C"
	"fmt"
	"os"
	"unsafe"

	utils "github.com/souben/hasher/utils"
)

const (
	HASH_SIZE         = 32
	HASH_DATA_AREA    = 136
	KECCAK_FINALIZED  = 0x80000000
	KECCAK_BLOCKLEN   = 136
	KECCAK_WORDS      = 17
	KECCAK_DIGESTSIZE = 32
)

func local_abort(msg *byte) {
	fmt.Fprintf(os.Stderr, "%s\n", msg)
	panic("abort")
}

const KECCAK_ROUNDS = 24

type KECCAK_CTX struct {
	Hash    [25]uint64
	Message [17]uint64
	Rest    uint64
}

var keccakf_rndc [24]uint64 = [24]uint64{1, 0x8082, 0x800000000000808A, 0x8000000080008000, 0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009, 138, 136, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008}
var keccakf_rotc [24]int = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
var keccakf_piln [24]int = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func keccakf(st [25]uint64) {
	for round := uint64(0); round < 24; round++ {
		var (
			t0  uint64
			t1  uint64
			bc0 uint64
			bc1 uint64
			bc2 uint64
			bc3 uint64
			bc4 uint64
		)
		bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20]
		bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21]
		bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22]
		bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23]
		bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24]
		t0 = bc0
		t1 = bc1
		bc0 ^= (bc2 << 1) | bc2>>(64-1)
		bc1 ^= (bc3 << 1) | bc3>>(64-1)
		bc2 ^= (bc4 << 1) | bc4>>(64-1)
		bc3 ^= (t0 << 1) | t0>>(64-1)
		bc4 ^= (t1 << 1) | t1>>(64-1)
		t0 = st[1] ^ bc0
		st[0] ^= bc4
		st[1] = ((st[6] ^ bc0) << 44) | (st[6]^bc0)>>(64-44)
		st[6] = ((st[9] ^ bc3) << 20) | (st[9]^bc3)>>(64-20)
		st[9] = ((st[22] ^ bc1) << 61) | (st[22]^bc1)>>(64-61)
		st[22] = ((st[14] ^ bc3) << 39) | (st[14]^bc3)>>(64-39)
		st[14] = ((st[20] ^ bc4) << 18) | (st[20]^bc4)>>(64-18)
		st[20] = ((st[2] ^ bc1) << 62) | (st[2]^bc1)>>(64-62)
		st[2] = ((st[12] ^ bc1) << 43) | (st[12]^bc1)>>(64-43)
		st[12] = ((st[13] ^ bc2) << 25) | (st[13]^bc2)>>(64-25)
		st[13] = ((st[19] ^ bc3) << 8) | (st[19]^bc3)>>(64-8)
		st[19] = ((st[23] ^ bc2) << 56) | (st[23]^bc2)>>(64-56)
		st[23] = ((st[15] ^ bc4) << 41) | (st[15]^bc4)>>(64-41)
		st[15] = ((st[4] ^ bc3) << 27) | (st[4]^bc3)>>(64-27)
		st[4] = ((st[24] ^ bc3) << 14) | (st[24]^bc3)>>(64-14)
		st[24] = ((st[21] ^ bc0) << 2) | (st[21]^bc0)>>(64-2)
		st[21] = ((st[8] ^ bc2) << 55) | (st[8]^bc2)>>(64-55)
		st[8] = ((st[16] ^ bc0) << 45) | (st[16]^bc0)>>(64-45)
		st[16] = ((st[5] ^ bc4) << 36) | (st[5]^bc4)>>(64-36)
		st[5] = ((st[3] ^ bc2) << 28) | (st[3]^bc2)>>(64-28)
		st[3] = ((st[18] ^ bc2) << 21) | (st[18]^bc2)>>(64-21)
		st[18] = ((st[17] ^ bc1) << 15) | (st[17]^bc1)>>(64-15)
		st[17] = ((st[11] ^ bc0) << 10) | (st[11]^bc0)>>(64-10)
		st[11] = ((st[7] ^ bc1) << 6) | (st[7]^bc1)>>(64-6)
		st[7] = ((st[10] ^ bc4) << 3) | (st[10]^bc4)>>(64-3)
		st[10] = (t0 << 1) | t0>>(64-1)
		bc0 = st[0]
		bc1 = st[1]
		st[0] ^= (^st[1]) & st[2]
		st[1] ^= (^st[2]) & st[3]
		st[2] ^= (^st[3]) & st[4]
		st[3] ^= (^st[4]) & bc0
		st[4] ^= (^bc0) & bc1
		bc0 = st[5]
		bc1 = st[6]
		st[5] ^= (^st[6]) & st[7]
		st[6] ^= (^st[7]) & st[8]
		st[7] ^= (^st[8]) & st[9]
		st[8] ^= (^st[9]) & bc0
		st[9] ^= (^bc0) & bc1
		bc0 = st[10]
		bc1 = st[11]
		st[10] ^= (^st[11]) & st[12]
		st[11] ^= (^st[12]) & st[13]
		st[12] ^= (^st[13]) & st[14]
		st[13] ^= (^st[14]) & bc0
		st[14] ^= (^bc0) & bc1
		bc0 = st[15]
		bc1 = st[16]
		st[15] ^= (^st[16]) & st[17]
		st[16] ^= (^st[17]) & st[18]
		st[17] ^= (^st[18]) & st[19]
		st[18] ^= (^st[19]) & bc0
		st[19] ^= (^bc0) & bc1
		bc0 = st[20]
		bc1 = st[21]
		bc2 = st[22]
		bc3 = st[23]
		bc4 = st[24]
		st[20] ^= (^bc1) & bc2
		st[21] ^= (^bc2) & bc3
		st[22] ^= (^bc3) & bc4
		st[23] ^= (^bc4) & bc0
		st[24] ^= (^bc0) & bc1
		st[0] ^= keccakf_rndc[round]
	}
}

func keccakf_2(st [25]uint64, rounds int) {
	var (
		i     int
		j     int
		round int
		t     uint64
		bc    [5]uint64
	)
	for round = 0; round < rounds; round++ {
		for i = 0; i < 5; i++ {
			bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
		}
		for i = 0; i < 5; i++ {
			t = bc[(i+4)%5] ^ (((bc[(i+1)%5]) << 1) | (bc[(i+1)%5])>>(64-1))
			for j = 0; j < 25; j += 5 {
				st[j+i] ^= t
			}
		}
		t = st[1]
		for i = 0; i < 24; i++ {
			j = keccakf_piln[i]
			bc[0] = st[j]
			st[j] = (t << uint64(keccakf_rotc[i])) | t>>uint64(64-(keccakf_rotc[i]))
			t = bc[0]
		}
		for j = 0; j < 25; j += 5 {
			for i = 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i = 0; i < 5; i++ {
				st[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}
		st[0] ^= keccakf_rndc[round]
	}
}

type state_t [25]uint64

func Keccak(in *uint8, inlen uint64, md *uint8, mdlen int) {
	var (
		st    state_t
		temp  [144]uint8
		i     uint64
		rsiz  uint64
		rsizw uint64
	)
	if mdlen <= 0 || mdlen > 100 && uint64(mdlen) != uint64(unsafe.Sizeof(state_t{})) {
		local_abort(utils.CString("Bad keccak use"))
	}
	if mdlen == int(unsafe.Sizeof(state_t{})) {
		rsiz = uint64(HASH_DATA_AREA)
	} else {
		rsiz = uint64(200 - mdlen*2)
	}
	rsizw = rsiz / 8

	*(*state_t)(unsafe.Pointer(&st[0])) = state_t{}

	for ; inlen >= rsiz; func() *uint8 {
		inlen -= rsiz
		return func() *uint8 {
			in = (*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(in)) + uintptr(rsiz)))
			return in
		}()
	}() {
		for i = 0; i < rsizw; i++ {
			st[i] ^= *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer((*uint64)(unsafe.Pointer(in)))) + unsafe.Sizeof(uint64(0))*uintptr(i)))
		}
		keccakf(([25]uint64)(st))
	}
	if inlen+1 >= uint64(unsafe.Sizeof([144]uint8{})) || inlen > rsiz || rsiz-inlen+inlen+1 >= uint64(unsafe.Sizeof([144]uint8{})) || rsiz == 0 || rsiz-1 >= uint64(unsafe.Sizeof([144]uint8{})) || rsizw*8 > uint64(unsafe.Sizeof([144]uint8{})) {
		local_abort(utils.CString("Bad keccak use"))
	}
	utils.MemCpy(unsafe.Pointer(&temp[0]), unsafe.Pointer(in), int(inlen))
	temp[func() uint64 {
		p := &inlen
		x := *p
		*p++
		return x
	}()] = 1
	utils.MemSet(unsafe.Pointer(&temp[inlen]), 0, int(rsiz-inlen))
	temp[rsiz-1] |= 128
	for i = 0; i < rsizw; i++ {
		st[i] ^= *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer((*uint64)(unsafe.Pointer(&temp[0])))) + unsafe.Sizeof(uint64(0))*uintptr(i)))
	}
	keccakf(([25]uint64)(st))
	utils.MemCpy(unsafe.Pointer(md), unsafe.Pointer(&st[0]), mdlen)
}
func Keccak_init(ctx *KECCAK_CTX) {
	*ctx = KECCAK_CTX{}
}

func Keccak_finish(ctx *KECCAK_CTX, md *uint8) {
	if (ctx.Rest & KECCAK_FINALIZED) == 0 {
		utils.MemSet(unsafe.Pointer(uintptr(unsafe.Pointer((*byte)(unsafe.Pointer(&ctx.Message[0]))))+uintptr(ctx.Rest)), 0, int(KECCAK_BLOCKLEN-ctx.Rest))
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer((*byte)(unsafe.Pointer(&ctx.Message[0])))) + uintptr(ctx.Rest))) |= 1
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer((*byte)(unsafe.Pointer(&ctx.Message[0])))) + uintptr(int(KECCAK_BLOCKLEN-1)))) |= 128
		for i_ := int(0); i_ < KECCAK_WORDS; i_++ {
			ctx.Hash[i_] ^= ctx.Message[i_]
		}
		keccakf_2(ctx.Hash, KECCAK_ROUNDS)
		ctx.Rest = KECCAK_FINALIZED
	}
	if md != nil {
		utils.MemCpy(unsafe.Pointer(md), unsafe.Pointer(&ctx.Hash[0]), KECCAK_DIGESTSIZE)
	}
}
