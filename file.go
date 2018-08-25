package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

// KDF constants
const (
	// the choice of parameters here is aggressive, since `enc` is meant to be used
	// as a form of at-rest encryption. 4 passes over 4GB.
	defaultArgonTime   = 4   // 4 passes
	defaultArgonMemory = 4e6 // 4GB

	saltSize = 32 // bytes
	keyLen   = 32
	macLen   = 32
)

type fileHeader struct {
	Salt        [32]byte
	ArgonTime   uint32
	ArgonMemory uint32
	ArgonLanes  uint8
	Tag         [64]byte
}

var errBadMAC = errors.New("authentication failed")

func decryptFile(passphrase []byte, input *os.File, finalOutput string) error {
	output, err := os.Create(finalOutput + ".temp")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	_, err = input.Seek(0, 0)
	if err != nil {
		return err
	}
	header := fileHeader{}
	err = binary.Read(input, binary.LittleEndian, &header)
	if err != nil {
		return err
	}
	// grab the offset where the ciphertext starts, after decoding the header
	ciphertextOffset, err := input.Seek(0, 1)
	if err != nil {
		return err
	}

	var sk [32]byte
	var macKey [32]byte
	skb := argon2.IDKey(passphrase, header.Salt[:], header.ArgonTime, header.ArgonMemory, header.ArgonLanes, keyLen+macLen)
	copy(sk[:], skb[:32])
	copy(macKey[:], skb[32:])

	// verify the authenticity of the entire ciphertext before performing any
	// decryption operations.
	hash, err := blake2b.New512(macKey[:])
	if err != nil {
		return err
	}
	_, err = io.Copy(hash, input)
	if err != nil {
		return err
	}
	var mac [64]byte
	copy(mac[:], hash.Sum(nil))
	if subtle.ConstantTimeCompare(mac[:], header.Tag[:]) != 1 {
		return errBadMAC
	}

	// seek back to the start of the ciphertext, and decrypt the data.
	_, err = input.Seek(ciphertextOffset, 0)
	if err != nil {
		return err
	}
	inputReader := NewReader(sk, input)
	_, err = io.Copy(output, inputReader)
	if err != nil {
		return err
	}
	err = output.Sync()
	if err != nil {
		return err
	}
	err = output.Close()
	if err != nil {
		return err
	}
	err = os.Rename(output.Name(), finalOutput)
	return err
}

func generateKey(passphrase []byte) ([]byte, fileHeader, error) {
	var salt [32]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		return nil, fileHeader{}, err
	}
	header := fileHeader{
		Salt:        salt,
		ArgonTime:   defaultArgonTime,
		ArgonMemory: defaultArgonMemory,
		ArgonLanes:  uint8(runtime.NumCPU() * 2),
	}
	return argon2.IDKey(passphrase, header.Salt[:], header.ArgonTime, header.ArgonMemory, header.ArgonLanes, keyLen+macLen), header, nil
}

func encryptFile(passphrase []byte, input *os.File, finalOutput string) error {
	output, err := os.Create(finalOutput + ".temp")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	_, err = input.Seek(0, 0)
	if err != nil {
		return err
	}
	skb, header, err := generateKey(passphrase)
	if err != nil {
		return fmt.Errorf("could not generate secret key")
	}
	var sk [32]byte
	var macKey [32]byte
	copy(sk[:], skb[:32])
	copy(macKey[:], skb[32:])
	err = binary.Write(output, binary.LittleEndian, header)
	if err != nil {
		return err
	}

	hash, err := blake2b.New512(macKey[:])
	if err != nil {
		return err
	}
	encWriter := NewWriter(sk, io.MultiWriter(hash, output))
	_, err = io.Copy(encWriter, input)
	if err != nil {
		return err
	}
	var mac [64]byte
	copy(mac[:], hash.Sum(nil))
	header.Tag = mac
	_, err = output.Seek(0, 0)
	if err != nil {
		return err
	}
	err = binary.Write(output, binary.LittleEndian, header)
	if err != nil {
		return err
	}
	err = output.Sync()
	if err != nil {
		return err
	}
	err = output.Close()
	if err != nil {
		return err
	}
	err = os.Rename(output.Name(), finalOutput)
	return err
}
