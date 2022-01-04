package utils

import (
	"bytes"
	"unsafe"
)

func MemCpy(dst, src unsafe.Pointer, sz int) unsafe.Pointer {
	if dst == nil {
		panic("nil destination")
	}
	if sz == 0 || src == nil {
		return dst
	}
	bdst := unsafe.Slice((*byte)(dst), sz)
	bsrc := unsafe.Slice((*byte)(src), sz)
	copy(bdst, bsrc)
	return dst
}

func MemSet(p unsafe.Pointer, ch byte, sz int) unsafe.Pointer {
	b := unsafe.Slice((*byte)(p), sz)
	if ch == 0 {
		copy(b, make([]byte, len(b)))
	} else {
		copy(b, bytes.Repeat([]byte{ch}, len(b)))
	}
	return p
}

func CString(s string) *byte {
	p := makePad(len(s)+1, 0)
	copy(p, s)
	return &p[0]
}

func makePad(sz int, pad int) []byte {
	if sz <= 0 {
		panic("size should be > 0")
	}
	if pad == 0 {
		pad = int(unsafe.Sizeof(uintptr(0)))
	}
	p := make([]byte, sz+pad*2)
	p = p[pad:]
	p = p[:sz:sz]
	return p
}
