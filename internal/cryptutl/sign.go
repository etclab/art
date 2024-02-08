package cryptutl

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"art/internal/keyutl"
)

func SignFile(privIKFile string, msgFile string) ([]byte, error) {
	sk, err := keyutl.ReadPrivateIKFromFile(privIKFile, keyutl.PEM)
	if err != nil {
		return nil, fmt.Errorf("can't read private key file: %v", err)
	}

	msgData, err := os.ReadFile(msgFile)
	if err != nil {
		return nil, fmt.Errorf("error: can't read message file: %v", err)
	}

	// regular Ed25519
	sig, err := sk.Sign(nil, msgData, &ed25519.Options{Hash: 0})
	if err != nil {
		return nil, fmt.Errorf("can't sign message: %v", err)
	}

	return sig, nil
}

func VerifySignature(pkPath, msgFile, sigFile string) (bool, error) {
	pk, err := keyutl.ReadPublicIKFromFile(pkPath, keyutl.PEM)
	if err != nil {
		return false, fmt.Errorf("can't read public key file: %v", err)
	}

	msgData, err := os.ReadFile(msgFile)
	if err != nil {
		return false, fmt.Errorf("can't read message file: %v", err)
	}

	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		return false, fmt.Errorf("can't read signature file: %v", err)
	}

	valid := ed25519.Verify(pk, msgData, sigData)
	return valid, nil
}
