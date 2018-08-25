package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestFileEncryptDecrypt(t *testing.T) {
	testDatumz := make([]byte, maxChunkSize*16)
	io.ReadFull(rand.Reader, testDatumz)
	ciphertextFile, err := ioutil.TempFile("", "enctest-ciphertext")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(ciphertextFile.Name())
	plaintextFile, err := ioutil.TempFile("", "enctest-plaintext")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(plaintextFile.Name())
	plaintextFile.Write(testDatumz)

	passphrase := []byte("hunter2")
	err = encryptFile(passphrase, plaintextFile, ciphertextFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	ciphertextFile, err = os.OpenFile(ciphertextFile.Name(), os.O_RDWR, 0666)
	if err != nil {
		t.Fatal(err)
	}
	outFile, err := ioutil.TempFile("", "enctest-out")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outFile.Name())
	err = decryptFile(passphrase, ciphertextFile, outFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	outFile, err = os.Open(outFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(out, outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), testDatumz) {
		t.Fatal("decryption resulted in different plaintexts")
	}

	// let's cleanly lop off a chunk to verify that the entire-file BLAKE mac
	// detects this.
	stat, _ := ciphertextFile.Stat()
	ciphertextFile.Seek(0, 0)
	err = ciphertextFile.Truncate(stat.Size() - int64(maxChunkSize+16+24+8))
	if err != nil {
		t.Fatal(err)
	}
	err = decryptFile(passphrase, ciphertextFile, outFile.Name())
	if err == nil {
		t.Fatal("undetected modification")
	}
	if err != errBadMAC {
		t.Fatal(err)
	}
}
