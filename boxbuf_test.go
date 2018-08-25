package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"
)

// TestSecureBuffers verifies that data can be encrypted and decrypted at
// various sizes using EncWriters and DecReaders.
func TestSecureBuffers(t *testing.T) {
	tests := []struct {
		sourceData []byte
	}{
		{[]byte("this is a test")},
		{make([]byte, maxChunkSize-1)},
		{make([]byte, maxChunkSize+1)},
		{make([]byte, maxChunkSize*10)},
		{make([]byte, maxChunkSize)},
		{func() []byte {
			res := make([]byte, 300e6) // 300 mb
			_, err := io.ReadFull(rand.Reader, res)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}()},
	}
	for _, test := range tests {
		t.Log("testing with", len(test.sourceData), "B of data")
		result := new(bytes.Buffer)
		skb := make([]byte, 32)
		_, err := rand.Read(skb)
		if err != nil {
			t.Fatal(err)
		}
		var sk [32]byte
		copy(sk[:], skb)
		encWriter := NewWriter(sk, result)
		if len(encWriter.buf) > maxChunkSize*3 { // there should never be more than 3 chunks buffered in memory
			t.Fatal("encWriter is leaking chunks")
		}
		n, err := encWriter.Write(test.sourceData)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(test.sourceData) {
			t.Fatal("output was not the correct length got", n, "wanted", len(test.sourceData))
		}
		if !sufficientEntropy(result.Bytes()) {
			t.Fatal("resulting output was not uniformly random")
		}
		if nonceReuse(result.Bytes()) {
			t.Fatal("resulting ciphertext has re-used nonces!")
		}
		decReader := NewReader(sk, result)
		decryptedData := make([]byte, len(test.sourceData))
		_, err = decReader.Read(decryptedData)
		if err != nil {
			t.Fatal(err)
		}
		if len(decReader.buf) > maxChunkSize*3 { // there should never be more than 3 chunks buffered in memory
			t.Fatal("decReader is leaking chunks")
		}
		if !bytes.Equal(decryptedData, test.sourceData) {
			t.Fatal("data decrypt mismatch got", decryptedData, "wanted", test.sourceData)
		}
	}
}

func nonceReuse(ciphertext []byte) bool {
	buf := bytes.NewBuffer(ciphertext)
	seenNonces := make(map[[sha256.Size]byte]struct{})
	for {
		var nonce [24]byte
		_, err := buf.Read(nonce[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		sum := sha256.Sum256(nonce[:])
		if _, seen := seenNonces[sum]; seen {
			return true
		}
		seenNonces[sum] = struct{}{}
		var chunkSize uint64
		err = binary.Read(buf, binary.LittleEndian, &chunkSize)
		if err != nil {
			panic(err)
		}
		chunk := make([]byte, chunkSize)
		_, err = buf.Read(chunk)
		if err != nil {
			panic(err)
		}
	}
	return false
}

func sufficientEntropy(data []byte) bool {
	b := new(bytes.Buffer)
	zip, _ := gzip.NewWriterLevel(b, gzip.BestCompression)
	if _, err := zip.Write(data); err != nil {
		panic(err)
	}
	if err := zip.Close(); err != nil {
		panic(err)
	}
	if b.Len() < len(data) {
		return false
	}
	return true
}
