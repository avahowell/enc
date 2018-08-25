package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func askPassphrase(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	res, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	return res, err
}

func main() {
	decryptMode := flag.Bool("d", false, "decrypt mode")
	fileOutput := flag.String("o", "", "output")
	flag.Parse()

	if *fileOutput == "" {
		flag.Usage()
		os.Exit(-1)
	}

	passphrase, err := askPassphrase("Enter passphrase:")
	if err != nil {
		fmt.Println("could not read passphrase")
		os.Exit(-1)
	}
	passphrase2, err := askPassphrase("Again, please: ")
	if err != nil {
		fmt.Println("could not read passphrase")
		os.Exit(-1)
	}
	if !bytes.Equal(passphrase, passphrase2) {
		fmt.Println("passphrases did not match")
		os.Exit(-1)
	}
	fname := flag.Args()[0]
	f, err := os.Open(fname)
	if err != nil {
		fmt.Println("could not open file", fname)
		os.Exit(-1)
	}
	if *decryptMode {
		err = decryptFile(passphrase, f, *fileOutput)
	} else {
		err = encryptFile(passphrase, f, *fileOutput)
	}
	if err != nil {
		log.Fatal(err)
	}
}
