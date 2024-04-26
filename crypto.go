package art

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"

	"github.com/syslab-wm/mu"
)

func NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

func SignFile(privIKFile string, msgFile string) ([]byte, error) {
	sk, err := ReadPrivateIKFromFile(privIKFile, EncodingPEM)
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
	pk, err := ReadPublicIKFromFile(pkPath, EncodingPEM)
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

func VerifyMessageSignature(publicKeyPath, msgFile, sigFile string) {
	valid, err := VerifySignature(publicKeyPath, msgFile, sigFile)
	if err != nil {
		mu.Fatalf("error: %v", err)
	}
	if !valid {
		mu.Fatalf("error: message signature verification failed for %v", msgFile)
	}
}
