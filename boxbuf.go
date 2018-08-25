package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

//
// maxChunkSize determines the amount of data written to an EncWriter before a
// new chunk is written.
//
// Refer to the following excerpt from NACL's documentation as to why this chunking behavior is used:
//
//  Messages should be small because:
//
// 1. The whole message needs to be held in memory to be processed.
//
// 2. Using large messages pressures implementations on small machines to decrypt and process plaintext before authenticating it. This is very dangerous, and this API does not allow it, but a protocol that uses excessive message sizes might present some implementations with no other choice.
//
// 3. Fixed overheads will be sufficiently amortised by messages as small as 8KB.
//
// 4. Performance may be improved by working with messages that fit into data caches.
//
// Thus large amounts of data should be chunked so that each message is small. (Each message still needs a unique nonce.) If in doubt, 16KB is a reasonable chunk size.
//
// See also: https://www.imperialviolet.org/2014/06/27/streamingencryption.html
//

const maxChunkSize = 16384 // 16kb

// EncWriter is an io.Writer that can be used to encrypt data with a secret key.
// EncWriter uses golang.org/x/crypto/nacl/secretbox to perform symmetric
// encryption.
type EncWriter struct {
	out        io.Writer
	buf        []byte
	usedNonces map[[24]byte]struct{}

	secretKey [32]byte
}

// DecReader is an io.Reader that can be used to decrypt data using a secret
// key. DecWriter uses golang.org/x/crypto/nacl/secretbox to perform symmetric
// decryption.
type DecReader struct {
	in    io.Reader
	buf   []byte
	index int

	secretKey [32]byte
}

// NewWriter creates a new EncWriter using the provided secretKey to encrypt
// data as needed to out.
func NewWriter(secretKey [32]byte, out io.Writer) *EncWriter {
	return &EncWriter{
		usedNonces: make(map[[24]byte]struct{}),
		secretKey:  secretKey,
		out:        out,
	}
}

// NewReader creates a new DecReader using secretKey to decrypt the data as
// needed from in.
func NewReader(secretKey [32]byte, in io.Reader) *DecReader {
	return &DecReader{
		secretKey: secretKey,
		in:        in,
	}
}

// Write writes the entirety of p to the underlying io.Writer, encrypting the
// data with the public key and chunking as needed.
func (w *EncWriter) Write(p []byte) (int, error) {
	for i, b := range p {
		if len(w.buf) == maxChunkSize {
			err := w.writeChunk()
			if err != nil {
				return i, err
			}
		}
		w.buf = append(w.buf, b)
	}
	err := w.writeChunk()
	return len(p), err
}

// writeChunk writes a chunk using EncWriter's buf and resets the buffer.
func (w *EncWriter) writeChunk() error {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic("could not read entropy for encryption")
	}
	_, seen := w.usedNonces[nonce]
	if seen {
		panic("nonce reuse")
	}
	w.usedNonces[nonce] = struct{}{}
	aead, err := chacha20poly1305.NewX(w.secretKey[:])
	if err != nil {
		return err
	}
	encryptedData := aead.Seal(nil, nonce[:], w.buf, nil)
	w.buf = nil

	_, err = w.out.Write(nonce[:])
	if err != nil {
		return err
	}
	chunkSize := uint64(len(encryptedData))
	err = binary.Write(w.out, binary.LittleEndian, chunkSize)
	if err != nil {
		return err
	}
	_, err = w.out.Write(encryptedData)
	return err
}

// Read reads from the underlying io.Reader, decrypting bytes as needed, until
// len(p) byte have been read or the underlying stream is exhausted.
func (b *DecReader) Read(p []byte) (int, error) {
	read := 0
	for i := range p {
		if b.index == 0 {
			err := b.nextChunk()
			if err != nil {
				return read, err
			}
		}
		p[i] = b.buf[b.index]
		b.index++
		read++
		if b.index >= len(b.buf) {
			b.index = 0
		}
	}
	return read, nil
}

// nextChunk reads the next chunk into DecReader's buf.
func (b *DecReader) nextChunk() error {
	var nonce [24]byte
	_, err := io.ReadFull(b.in, nonce[:])
	if err != nil {
		return err
	}
	var chunkSize uint64
	err = binary.Read(b.in, binary.LittleEndian, &chunkSize)
	if err != nil {
		return err
	}
	if chunkSize > maxChunkSize+16 {
		return errors.New("chunk too large")
	}
	chunkData := make([]byte, chunkSize)
	_, err = io.ReadFull(b.in, chunkData)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(b.secretKey[:])
	if err != nil {
		return err
	}
	decryptedBytes, err := aead.Open(nil, nonce[:], chunkData, nil)
	if err != nil {
		return err
	}
	b.buf = decryptedBytes
	return nil
}
