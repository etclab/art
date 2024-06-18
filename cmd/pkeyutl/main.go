package main

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/etclab/art"
	"github.com/etclab/mu"
)

func doSign(privPath string, keyform art.KeyEncoding, msgData []byte, sigfile string) error {
	privKey, err := art.ReadPrivateIKFromFile(privPath, keyform)
	if err != nil {
		return fmt.Errorf("can't read private key file: %v", err)
	}

	// regular Ed25519
	sigData, err := privKey.Sign(nil, msgData, &ed25519.Options{Hash: 0})
	if err != nil {
		return fmt.Errorf("can't sign message: %v", err)
	}

	err = os.WriteFile(sigfile, sigData, 0440)
	if err != nil {
		return fmt.Errorf("can't write signature file: %v", err)
	}

	return nil
}

func doVerify(pubPath string, keyform art.KeyEncoding, msgData []byte, sigfile string) (bool, error) {
	pubKey, err := art.ReadPublicIKFromFile(pubPath, keyform)
	if err != nil {
		return false, fmt.Errorf("can't read public key file: %v", err)
	}

	sigData, err := os.ReadFile(sigfile)
	if err != nil {
		return false, fmt.Errorf("can't read sigfile: %v", err)
	}

	// regular Ed25519
	valid := ed25519.Verify(pubKey, msgData, sigData)
	return valid, nil
}

func main() {
	var err error
	var valid bool

	opts := parseOptions()

	msgData, err := os.ReadFile(opts.msgPath)
	if err != nil {
		mu.Fatalf("error: can't read message file: %v", err)
	}

	if opts.sign {
		err = doSign(opts.key, opts.encoding, msgData, opts.sigfile)
	} else {
		valid, err = doVerify(opts.key, opts.encoding, msgData, opts.sigfile)
	}

	if err != nil {
		mu.Fatalf("error: %v", err)
	}

	if opts.verify {
		if valid {
			fmt.Printf("signature verification passed.\n")
			os.Exit(0)
		} else {
			fmt.Printf("signature verification failed.\n")
			os.Exit(1)
		}
	}
}
