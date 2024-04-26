package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/syslab-wm/mu"
)

const shortUsage = "Usage: update_key [options] INDEX TREE_FILE"
const usage = `Usage: update_key [options] INDEX TREE_FILE

Update an agent's key at position INDEX

positional arguments:
  INDEX
	The index position of the 'current' group member that is updating the key, 
	this index is based off the member's position in the group config
	file, where the first entry is at index 1.

  TREE_FILE
	The file that contains the current state of the tree. This state will be 
	used as a starting point to process key updates and update messages. This 
	file will be overwritten with the new current state of the tree after all 
	updates have been processed.

options:
  -h, -help
    Show this usage statement and exit.

  -update-file UPDATE_FILE 
	If specified, the current member will update their leaf key, the tree, and 
	the stage key. The update message containing the leaf index and path of 
	updated keys will be written to UPDATE_FILE. If omitted, the update message
	is saved to file update_key.msg

  -mac-file MAC_FILE
  	The MAC for the update message will be written to MAC_FILE. If omitted, the 
	MAC is saved to file UPDATE_FILE.mac

examples:  
  ./update_key -update-file cici_update_key 3 cici-ek.pem cici-state`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional args
	index         int
	treeStateFile string

	// options
	updateFile string
	macFile    string
}

func parseOptions() *options {
	var err error
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.updateFile, "update-file", "update_key.msg", "")
	flag.StringVar(&opts.macFile, "mac-file", "", "")
	flag.Parse()

	if flag.NArg() != 2 {
		mu.Fatalf(shortUsage)
	}

	opts.index, err = strconv.Atoi(flag.Arg(0))
	if err != nil {
		mu.Fatalf("error converting positional argument INDEX to int: %v", err)
	}

	opts.treeStateFile = flag.Arg(1)

	if opts.macFile == "" {
		opts.macFile = opts.updateFile + ".mac"
	}

	return &opts
}
