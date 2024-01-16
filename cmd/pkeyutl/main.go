package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"art/internal/keyutl"
	"art/internal/mu"
)

const shortUsage = "Usage: pkeyutl [options] MSGFILE"
const usage = `Usage: pkeyutl [options] MSGFILE

Create and verify signatures.

positional arguments:
  MSGFILE
    The file to either sign or verify.

options:
  Note: 
    * exactly one of -sign or -verify must be specified.
    * The -key and -sigfile options must always be specified.

  -sign
    Sign MSGFILE.  The signature is written to SIGFILE.

  -verify
    Verify SIGFILE is a valid signature for MSGFILE using KEYFILE, which must
    be an ED25519 public key. The process prints a message with the
    verification results, and has an exit status of 0 if verification
    succeeded, and 1 if it failed.

  -key KEYFILE
    For signing, an ED25519 private key.  For verifying, an ED25519 signing
    key.

  -keyform raw|der|pem  (default: pem)
    The encoding for KEYFILE.

  -sigfile SIGFILE
    For signing, the signature is written to SIGFILE.  For verifying, SIGFILE
    should contain the signature to verify.  This option must always be
    specified.

examples:
  ./pkeyutl -sign -key alice-ik.pem -sigfile foo.sig foo
  ./pkeyutl -verify -key alice-ik-pub.pem -sigfile foo.sig foo`

type options struct {
	sign    bool
	verify  bool
	key     string
	keyform string
	sigfile string
}

func printUsage() {
	fmt.Println(usage)
}

func doSign(privPath string, keyform keyutl.KeyEncoding, msgData []byte, sigfile string) error {
	privKey, err := keyutl.ReadPrivateIKFromFile(privPath, keyform)
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

func doVerify(pubPath string, keyform keyutl.KeyEncoding, msgData []byte, sigfile string) (bool, error) {
	pubKey, err := keyutl.ReadPublicIKFromFile(pubPath, keyform)
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
	opts := options{}

	flag.Usage = printUsage
	flag.BoolVar(&opts.sign, "sign", false, "")
	flag.BoolVar(&opts.verify, "verify", false, "")
	flag.StringVar(&opts.key, "key", "", "")
	flag.StringVar(&opts.keyform, "keyform", "pem", "")
	flag.StringVar(&opts.sigfile, "sigfile", "", "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Die(shortUsage)
	}

	if !opts.sign && !opts.verify {
		mu.Die("error: must specify -sign or -verify")
	}

	if opts.sign && opts.verify {
		mu.Die("error: can't specify both -sign and -verify")
	}

	encoding, err := keyutl.StringToKeyEncoding(opts.keyform)
	if err != nil {
		mu.Die("%v", err)
	}

	if opts.key == "" {
		mu.Die("error: must specify -key")
	}

	if opts.sigfile == "" {
		mu.Die("error: must specify -sigfile")
	}

	msgPath := flag.Arg(0)
	msgData, err := os.ReadFile(msgPath)
	if err != nil {
		mu.Die("error: can't read message file: %v", err)
	}

	if opts.sign {
		err = doSign(opts.key, encoding, msgData, opts.sigfile)
	} else {
		valid, err = doVerify(opts.key, encoding, msgData, opts.sigfile)
	}

	if err != nil {
		mu.Die("error: %v", err)
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
