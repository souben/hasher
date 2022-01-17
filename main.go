package main

import (
	"encoding/json"
	"hash"
	"os"
	"strconv"

	utils "github.com/souben/keccak/keccaktest"
)

func keccakf_test() {

	st := [25]uint64{}
	var i uint64

	for i = 0; i < 25; i++ {
		st[i] = i
	}
	utils.Keccakf(&st)

	data := ""
	for _, v := range st {
		data += strconv.FormatUint(v, 10) + " "
	}

	keccakf_data := map[string]string{"result": data}

	b, err := json.Marshal(keccakf_data)
	if err != nil {
		panic("error while writing to file ...")
	}

	os.WriteFile("keccakf_go.json", b, 0666)
}

func keccak_test() {

	type test struct {
		length int
		input  []byte
	}

	test_one := test{32, []byte{}}
	//test_two := test{32, []byte("Keccak-256 Test Hash")}

	data := ""
	var h hash.Hash = utils.New256()

	h.Write(test_one.input)
	d := h.Sum(nil)
	for _, b := range d {
		data += strconv.FormatUint(uint64(b), 10) + " "
	}

	keccak_data := map[string]string{"result": data}

	b, err := json.Marshal(keccak_data)
	if err != nil {
		panic("error while writing to file ...")
	}

	os.WriteFile("keccak_go.json", b, 0666)
}

func main() {

	// keccacf test
	keccakf_test()
	//keccak test:
	keccak_test()

}
