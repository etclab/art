package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/etclab/mu"
)

const shortUsage = `Usage: process_update_message [options] INDEX \ 
	PRIVATE_EK_FILE TREE_FILE UPDATE_MSG_FILE`
const usage = `Usage: process_update_message [options] INDEX \ 
	PRIVATE_EK_FILE TREE_FILE UPDATE_MSG_FILE

Process a key update message as a group member at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is processing the key 
	update message, this index is based off the member's position in the group 
	config file, where the first entry is at index 1.

  PRIVATE_EK_KEY_FILE
	The 'current' group member's private ephemeral key file (also called a 
	prekey). This is a PEM-encoded X25519 private key.

  STATE_FILE
  	The file that contains the current state of the tree. This state will be 
	used as a starting point to process the update message. This file will be 
	overwritten with the new current state of the tree after all updates have 
	been processed.

  UPDATE_MSG_FILE
	The file that contains the update message that needs to be processed.

options:
  -mac-file UPDATE_MSG_MAC_FILE
	The update message's corresponding mac file. If omitted a default file is 
	UPDATE_MSG_FILE.mac.

  -h, -help
    Show this usage statement and exit.

examples:
  ./process_update_message 2 bob-ek.pem bob-state cici_update_key`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional arguments
	index             int
	privEKFile        string
	treeStateFile     string
	updateMessageFile string

	// options
	macFile string
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() != 4 {
		mu.Fatalf(shortUsage)
	}

	opts.index, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Fatalf("error converting positional argument INDEX to int: %v", err)
	}
	opts.privEKFile = flag.Arg(1)
	opts.treeStateFile = flag.Arg(2)
	opts.updateMessageFile = flag.Arg(3)

	if opts.macFile == "" {
		opts.macFile = opts.updateMessageFile + ".mac"
	}

	return &opts
}
