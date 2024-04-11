package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/syslab-wm/mu"
)

const shortUsage = `Usage: process_setup_message [options] INDEX PRIV_EK_FILE \ 
	INITIATOR_PUB_IK_FILE SETUP_MSG_FILE`
const usage = `Usage: process_setup_message [options] INDEX PRIV_EK_FILE \
	INITIATOR_PUB_IK_FILE SETUP_MSG_FILE

Process a group setup message as a group member at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is processing the setup
	message, this index is based off the member's position in the group config
	file, where the first entry is at index 1.

  PRIV_EK_FILE
	The 'current' group member's private ephemeral key file (also called a prekey).  
	This is a PEM-encoded X25519 private key.

  INITIATOR_PUB_IK_FILE
    The initiator's public identity key.  This is a PEM-encoded ED25519 key.

  SETUP_MSG_FILE
	The file containing the group setup message.

options:
  -h, -help
    Show this usage statement and exit.

  -sig-file SETUP_MSG_SIG_FILE
    The setup message's corresponding signature file (signed with the initiator's IK).
    If not provided, the tool will look for a file SETUP_MSG_FILE.sig.

  -out-state STATE_FILE
    The file to output the node's state after processing the setup message. If
    not provided, the default is state.json. 


examples:
  ./process_setup_message -out-state bob-state.json 2 bob-ek.pem \
		alice-ik-pub.pem setup.msg`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional arguments
	index              int
	privEKFile         string
	initiatorPubIKFile string
	setupMessageFile   string

	// options
	sigFile       string
	treeStateFile string
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.sigFile, "sig-file", "", "")
	flag.StringVar(&opts.treeStateFile, "out-state", "state.json", "")
	flag.Parse()

	if flag.NArg() != 4 {
		mu.Fatalf(shortUsage)
	}

	opts.index, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Fatalf("error converting positional argument INDEX to int: %v", err)
	}
	// TODO: check that position is >= 1
	opts.privEKFile = flag.Arg(1)
	opts.initiatorPubIKFile = flag.Arg(2)
	opts.setupMessageFile = flag.Arg(3)

	if opts.sigFile == "" {
		opts.sigFile = opts.setupMessageFile + ".sig"
	}

	return &opts
}
