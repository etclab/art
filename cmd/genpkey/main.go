package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/syslab-wm/art"
	"github.com/syslab-wm/mu"
)

func createKeyNames(basePath, format, keyType string) (string, string) {
	pubPath := fmt.Sprintf("%s-%s-pub.%s", basePath, keyType, format)
	privPath := fmt.Sprintf("%s-%s.%s", basePath, keyType, format)
	return pubPath, privPath
}

func generateIKPair(pubPath, privPath string, encoding art.KeyEncoding) error {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	err = art.WritePublicIKToFile(pubKey, pubPath, encoding)
	if err != nil {
		return err
	}

	err = art.WritePrivateIKToFile(privKey, privPath, encoding)
	if err != nil {
		return err
	}

	return nil
}

func generateEKPair(pubPath, privPath string, encoding art.KeyEncoding) error {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	pubKey := privKey.PublicKey()
	err = art.WritePublicEKToFile(pubKey, pubPath, encoding)
	if err != nil {
		return err
	}

	err = art.WritePrivateEKToFile(privKey, privPath, encoding)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	var err error

	opts := parseOptions()

	pubPath, privPath := createKeyNames(opts.basePath, opts.outform, opts.keytype)

	if opts.keytype == "ik" {
		err = generateIKPair(pubPath, privPath, opts.encoding)
	} else {
		err = generateEKPair(pubPath, privPath, opts.encoding)
	}

	if err != nil {
		mu.Fatalf("failed to generate keypair: %v", err)
	}
}
