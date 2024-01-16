package cryptutl

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"art/internal/keyutl"
)

func SignFile(privIKFile string, msgFile string) ([]byte, error) {
	encoding, err := keyutl.StringToKeyEncoding("pem")
	if err != nil {
		panic(err)
	}

	sk, err := keyutl.ReadPrivateIKFromFile(privIKFile, encoding)
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
