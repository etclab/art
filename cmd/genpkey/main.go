package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"strings"

	"art/internal/keyutl"
	"art/internal/mu"
)

const shortUsage = "Usage: genpkey [options] KEYPATH"
const usage = `Usage: genpkey [options] KEYPATH

Generate an identity keypair (ED25519 keys) or an ECDH keypair (X25519 keys).

positional arguments:
  KEYPATH
    The output path for the private key.  The private key is written to a file
    called KEYPATH-KEYTYPE.OUTFORM and the public key to
    KEYPATH-KEYTYPE-pub.OUTFORM.  For instance, if KEYPATH is /foo/bar/alice,
    then "genpkey -type ek -outform pem" creates the private key file
    "/foo/bar/alice-ek.pem" and the public key file "/foo/bar/alice-ek-pub.pem"

options:
  -h, -help
    Show this usage statement and exit.

  -keytype ik|ek       (default: ik)
    The type of key.
      * ik keys ("identity keys") are ED25519 keys that can be used for
         signing and verifying.
      * ek keys ("ephemeral keys") are X25519 keys for elliptic curve
         Diffie-Hellman key exchanges.  These are also called pre-keys.
         The setup key is also an example of an ek key.

  -outform raw|der|pem  (default: pem)
    The encoding for the key files.

examples:
    # generate an emphemeral ECDH (X25519) keypair for alice
  ./genpkey -outform der -keytype ek alice`

type options struct {
	outform string
	keytype string
}

func printUsage() {
	fmt.Println(usage)
}

func createKeyNames(basePath, format, keyType string) (string, string) {
	pubPath := fmt.Sprintf("%s-%s-pub.%s", basePath, keyType, format)
	privPath := fmt.Sprintf("%s-%s.%s", basePath, keyType, format)
	return pubPath, privPath
}

func generateIKPair(pubPath, privPath string, encoding keyutl.KeyEncoding) error {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	err = keyutl.WritePublicIKToFile(pubKey, pubPath, encoding)
	if err != nil {
		return err
	}

	err = keyutl.WritePrivateIKToFile(privKey, privPath, encoding)
	if err != nil {
		return err
	}

	return nil
}

func generateEKPair(pubPath, privPath string, encoding keyutl.KeyEncoding) error {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	pubKey := privKey.PublicKey()
	err = keyutl.WritePublicEKToFile(pubKey, pubPath, encoding)
	if err != nil {
		return err
	}

	err = keyutl.WritePrivateEKToFile(privKey, privPath, encoding)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	var err error

	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.keytype, "keytype", "ik", "")
	flag.StringVar(&opts.outform, "outform", "pem", "")
	flag.Parse()

	if flag.NArg() != 1 {
		mu.Die(shortUsage)
	}
	basePath := flag.Arg(0)

	opts.keytype = strings.ToLower(opts.keytype)
	if opts.keytype != "ik" && opts.keytype != "ek" {
		mu.Die("error: -keytype invalid value %q (must be ik|ek)", opts.keytype)
	}

	encoding, err := keyutl.StringToKeyEncoding(opts.outform)
	if err != nil {
		mu.Die("%v", err)
	}

	pubPath, privPath := createKeyNames(basePath, opts.outform, opts.keytype)

	if opts.keytype == "ik" {
		err = generateIKPair(pubPath, privPath, encoding)
	} else {
		err = generateEKPair(pubPath, privPath, encoding)
	}

	if err != nil {
		mu.Die("failed to generate keypair: %v", err)
	}
}
