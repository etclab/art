package main

import (
	"flag"
	"fmt"

	"github.com/syslab-wm/art/internal/keyutl"
	"github.com/syslab-wm/mu"
)

const shortUsage = "Usage: pkeyutl [options] MSGFILE"
const usage = `Usage: pkeyutl [options] MSGFILE

Create and verify signatures.

positional arguments:
  MSGFILE
    The file to either sign or verify.

options:
  Note: 
    * Exactly one of -sign or -verify must be specified.
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
	// positional
	msgPath string

	// options
	sign    bool
	verify  bool
	key     string
	keyform string
	sigfile string

	// derived
	encoding keyutl.KeyEncoding
}

func printUsage() {
	fmt.Println(usage)
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.BoolVar(&opts.sign, "sign", false, "")
	flag.BoolVar(&opts.verify, "verify", false, "")
	flag.StringVar(&opts.key, "key", "", "")
	flag.StringVar(&opts.keyform, "keyform", "pem", "")
	flag.StringVar(&opts.sigfile, "sigfile", "", "")

	flag.Parse()

	if !opts.sign && !opts.verify {
		mu.Fatalf("error: must specify -sign or -verify")
	}

	if opts.sign && opts.verify {
		mu.Fatalf("error: can't specify both -sign and -verify")
	}

	opts.encoding, err = keyutl.StringToKeyEncoding(opts.keyform)
	if err != nil {
		mu.Fatalf("%v", err)
	}

	if opts.key == "" {
		mu.Fatalf("error: must specify -key")
	}

	if opts.sigfile == "" {
		mu.Fatalf("error: must specify -sigfile")
	}

	if flag.NArg() != 1 {
		mu.Fatalf(shortUsage)
	}
	opts.msgPath = flag.Arg(0)

	return &opts
}
