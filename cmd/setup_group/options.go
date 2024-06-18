package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/etclab/mu"
)

const shortUsage = "setup_group [options] CONFIG_FILE PRIV_IK_FILE"

const usage = `setup_group [options] CONFIG_FILE PRIV_IK_FILE

Setup the ART group.

positional arguments:
  CONFIG_FILE
    The config file has one line per group member (including the initiator).
    Each line consists of three whitespace-separated fields:

      NAME PUB_IK_FILE PUB_EK_FILE

    where,
      NAME: 
        The member's name (e.g., alice)

      PUB_IK_FILE:
        The member's identity key file.  This is a PEM-encoded ED25519
        public key

      PUB_EK_FILE:
        The member's ephemeral key file (also called a prekey).  This is
        a PEM-encoded X25519 public key.

    Empty lines are ignored, as are lines that start with a '#'.

  PRIV_IK_FILE
    The initiator's private identity key file.  This is a PEM-encoded ED25519
    key.  This key signs the setup message; the signature is written to
    SIG_FILE.

options:
  -initiator NAME
    The name of the initiator (e.g. alice).  This must match one of the
    names in CONFIG_FILE.  If this option is not provided, the initiator
    is the first entry in the CONFIG_FILE.

  -out-dir OUT_DIR
    The output directory.  The program will place various output files
    in this directory, such as the leaf key for each member.  If not
    provided, the program sets out-dir to basename(CONFIG_FILE).dir.
    If the out-dir does not exist, the program creates it.

  -out-state STATE_FILE
    The file to output the node's state. If not provided, the default is 
	state.json. 

  -msg-file MSG_FILE
    The message file. If omitted, the message is saved to file setup.msg

  -sig-file SIG_FILE
	The signature file. If omitted, the signature is saved to file MSG_FILE.sig

example:
    ./setup_group -initiator alice -out-dir group.d -msg-file setup.msg \
		-sig-file setup.msg.sig group.cfg alice-ik.pem`

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional
	configFile string
	privIKFile string

	// options
	initiator     string
	outDir        string
	msgFile       string
	sigFile       string
	treeStateFile string
}

func parseOptions() *options {
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.initiator, "initiator", "", "")
	flag.StringVar(&opts.outDir, "out-dir", "", "")
	flag.StringVar(&opts.msgFile, "msg-file", "setup.msg", "")
	flag.StringVar(&opts.sigFile, "sig-file", "", "")
	flag.StringVar(&opts.treeStateFile, "out-state", "state.json", "")
	flag.Parse()

	if flag.NArg() != 2 {
		mu.Fatalf(shortUsage)
	}

	opts.configFile = flag.Arg(0)
	opts.privIKFile = flag.Arg(1)

	if opts.outDir == "" {
		opts.outDir = filepath.Base(opts.configFile) + ".dir"
	}

	if opts.sigFile == "" {
		opts.sigFile = opts.msgFile + ".sig"
	}

	opts.msgFile = filepath.Join(opts.outDir, opts.msgFile)
	opts.sigFile = filepath.Join(opts.outDir, opts.sigFile)
	opts.treeStateFile = filepath.Join(opts.outDir, opts.treeStateFile)

	return &opts
}
