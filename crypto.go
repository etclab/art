package art

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"

	"github.com/etclab/mu"
)

// NewHMAC is a wrapper for the standard library's [hmac.New] that
// uses SHA256 as its hash function.
func NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// SignFile signs the msgFile using the ed25519 private key in privIKFile.
// The function expects privIKFile to be a PEM-encoding (type "ED25519
// PRIVATE KEY") of the PKCS8 #8, ASN.1 DER form.  On success, the function
// returns the signature; otherwise, it returns an error.
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

// VerifySignature verifies that sigFile is a signature for msgFile using
// the public ed25519 key in pkPath.  The function assumes that pkPath is
// a PEM-encoding (type "ED25519 Public Key") of the PKIX, ASN.1 DER form.
// If the signature is valid, the function returns true; otherwise it returns
// false.  If there was a problem reading any of the files, the function also
// returns an error.
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

// VerifyMessageSignature is a wrapper for [VerifySignature]: it terminates the
// program is there was an error reading any of the files or the signature was
// invalid.
func VerifyMessageSignature(publicKeyPath, msgFile, sigFile string) {
	valid, err := VerifySignature(publicKeyPath, msgFile, sigFile)
	if err != nil {
		mu.Fatalf("error: %v", err)
	}
	if !valid {
		mu.Fatalf("error: message signature verification failed for %v", msgFile)
	}
}
