package unittesting

import (
	"testing"
	"unsafe"

	keccak "github.com/souben/hasher"
)

func TEST_KECCAK(t *testing.T, sz uint64, chunks []uint64) {
	data := make([]uint64, sz)
	var i uint64
	for i = 0; i < uint64(len(data)); i++ {
		data[i] = i * 17
	}
	i = 0
	var md0 [32]uint8
	keccak.Keccak((*uint8)(unsafe.Pointer(&data)), sz, (*uint8)(unsafe.Pointer(&md0)), 32)
	var offset uint64 = 0
	t.Logf("%v, %v", chunks, data)
	for i = 0; i < uint64(len(chunks)); i++ {
		ASSERT_LEES_OR_EQUAL(t, offset+chunks[i], uint64(len(data)))
		offset += chunks[i]
		t.Log("offset", offset, chunks[i])
	}
	t.Log(offset, len(data))
	ASSERT_EQUAL(t, offset, uint64(len(data)))
}

func ASSERT_LEES_OR_EQUAL(t *testing.T, a uint64, b uint64) {
	if a <= b {
		return
	}
	t.Fatalf("ALE Test has been failed for a=%d , b=%d", a, b)
}

func ASSERT_EQUAL(t *testing.T, a uint64, b uint64) {
	if a == b {
		return
	}
	t.Fatalf("AE Test has been failed for a=%d , b=%d", a, b)
}

func TestKeccak(t *testing.T) {
	// TEST_KECCAK(t, 0, []uint64{0})
	TEST_KECCAK(t, 4, []uint64{0, 0, 1, 0, 2, 1, 0})
}
