package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/etclab/art"
	"github.com/etclab/mu"
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
    # generate an ephemeral ECDH (X25519) keypair for alice
  ./genpkey -outform der -keytype ek alice`

type options struct {
	// positional
	basePath string

	//optional
	outform  string
	encoding art.KeyEncoding // derived from outform
	keytype  string
}

func printUsage() {
	fmt.Println(usage)
}

func parseOptions() *options {
	var err error

	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.keytype, "keytype", "ik", "")
	flag.StringVar(&opts.outform, "outform", "pem", "")
	flag.Parse()

	opts.keytype = strings.ToLower(opts.keytype)
	if opts.keytype != "ik" && opts.keytype != "ek" {
		mu.Fatalf("error: -keytype invalid value %q (must be ik|ek)", opts.keytype)
	}

	opts.outform = strings.ToLower(opts.outform)
	opts.encoding, err = art.StringToKeyEncoding(opts.outform)
	if err != nil {
		mu.Fatalf("error: %v", err)
	}

	if flag.NArg() != 1 {
		mu.Fatalf(shortUsage)
	}
	opts.basePath = flag.Arg(0)

	return &opts
}
