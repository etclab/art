package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/gob"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"art/internal/cryptutl"
	"art/internal/keyutl"
	"art/internal/mu"
	"art/internal/proto"
	"art/internal/tree"
)

const shortUsage = "setup_group [options] CONFIG_FILE PRIV_IK_FILE"

const usage = `setup_group [options] CONFIG_FILE PRIV_IK_FILE

Setup the ART group.

positional arguments:
  CONFIG_FILE
    The config file has one line per group member (including the initiator).
    Each line consists of three whitespace-seperated fields:

      NAME IK_FILE EK_FILE

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
    MSG_FILE.sig.

options:
  -initiator NAME
    The name of the initiator (e.g. alice).  This must match one of the
    names in CONFIG_FILE.  If this option is not provided, the initiator
    is the first entry in the CONFIG_FILE.

  -outdir OUTDIR
    The output directory.  The program will place various output files
    in this directory, such as the leaf key for each member.  If not
    provided, the program sets outdir to basename(CONFIG_FILE).dir.
    If the outdir does not exist, the program creates it.

example:
    ./setup_group -initiator alice -outdir group.d group.cfg alice-ik.pem`

/* Group is size n (the initiator, and the n-1 peers) */

func printUsage() {
	fmt.Println(usage)
}

type options struct {
	// positional
	configFile string
	privIKFile string

	// options
	initiator string
	outdir    string

	// TODO
	sigFile string
}

type member struct {
	name      string
	pubIKFile string
	pubIK     ed25519.PublicKey
	pubEKFile string
	pubEK     *ecdh.PublicKey  // X25519
	leafKey   *ecdh.PrivateKey // X25519
}

type group struct {
	members   []*member
	initiator *member
}

// TODO: move to proto
type message struct {
	IKeys    [][]byte
	EKeys    [][]byte
	Suk      []byte
	TreeKeys [][]byte
}

func newMember(name, pubIKFile, pubEKFile string) (*member, error) {
	var err error

	m := &member{name: name, pubIKFile: pubIKFile, pubEKFile: pubEKFile}

	m.pubIK, err = keyutl.ReadPublicIKFromFile(m.pubIKFile, keyutl.PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to read public IK for %q from %q: %v", m.name, m.pubIKFile, err)
	}

	m.pubEK, err = keyutl.ReadPublicEKFromFile(m.pubEKFile, keyutl.PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to read public EK for %q from %q: %v", m.name, m.pubEKFile, err)
	}

	return m, nil
}

func (g *group) addMember(m *member) {
	g.members = append(g.members, m)
}

func (g *group) printMembers() {
	for i, m := range g.members {
		fmt.Printf("%d: %s %s %s\n", i, m.name, m.pubIKFile, m.pubEKFile)
	}
}

func (g *group) member(name string) *member {
	for _, m := range g.members {
		if m.name == name {
			return m
		}
	}
	return nil
}

func (g *group) first() *member {
	return g.members[0]
}

func (g *group) setInitiator(name string) {
	if name == "" {
		g.initiator = g.first()
		return
	}

	g.initiator = g.member(name)
	if g.initiator == nil {
		mu.Die("error: initiator %q not found in config file", name)
	}
}

func (g *group) setup(opts *options) {
	var err error

	g.setInitiator(opts.initiator)
	g.initiator.leafKey, err = proto.DHKeyGen()
	if err != nil {
		mu.Die("failed to generate initiator's leaf key: %v", err)
	}
	suk, err := proto.KeyExchangeKeyGen()
	if err != nil {
		mu.Die("failed to generate the setup key (suk): %v", err)
	}

	leafKeys := make([]*ecdh.PrivateKey, 0, len(g.members))
	for _, member := range g.members {
		if member.name == g.initiator.name {
			leafKeys = append(leafKeys, g.initiator.leafKey)
			continue
		}

		raw, err := proto.KeyExchange(suk, member.pubEK)
		if err != nil {
			mu.Die("failed to generate leafKey")
		}

		member.leafKey, err = keyutl.UnmarshalPrivateX25519FromRaw(raw)
		if err != nil {
			mu.Die("failed to unmarshal leafKey")
		}
		leafKeys = append(leafKeys, member.leafKey)
	}

	treeSecret, err := tree.CreateTree(leafKeys)
	if err != nil {
		mu.Die("failed to create ART tree: %v", err)
	}

	//// for debugging that the tree key here matches the one derived in process_setup_message
	fmt.Println(keyutl.MarshalPrivateEKToPEM(treeSecret.GetSk()))
	fmt.Println()

	// creating the message to be used by the other members
	treePublic := treeSecret.PublicKeys()
	msg := g.createMessage(opts, suk.PublicKey(), treePublic)

	// deriving the stage key
	stageInfo := proto.StageKeyInfo{IKeys: msg.IKeys, TreeKeys: msg.TreeKeys}
	stageKey, err := proto.DeriveStageKey(treeSecret.GetSk(), &stageInfo)
	if err != nil {
		mu.Die("DeriveStageKey failed: %v", err)
	}
	fmt.Printf("stage key: %v", stageKey)
}

func (g *group) createMessage(opts *options, suk *ecdh.PublicKey, treePublic *tree.PublicNode) message {
	// marshalling all the keys
	marshalledEKS := make([][]byte, 0, len(g.members))
	marshalledIKS := make([][]byte, 0, len(g.members))

	for _, member := range g.members {
		marshalledEK, err := keyutl.MarshalPublicEKToPEM(member.pubEK)
		if err != nil {
			mu.Die("failed to marshal public EK: %v", err)
		}
		marshalledEKS = append(marshalledEKS, marshalledEK)

		marshalledIK, err := keyutl.MarshalPublicIKToPEM(member.pubIK)
		if err != nil {
			mu.Die("failed to marshal public IK: %v", err)
		}
		marshalledIKS = append(marshalledIKS, marshalledIK)
	}

	marshalledsuk, err := keyutl.MarshalPublicEKToPEM(suk)
	if err != nil {
		mu.Die("failed to marshal public SUK: %v", err)
	}

	// creating the message file
	msgPath := filepath.Join(opts.outdir, "setup.msg")
	msgFile, err := os.Create(msgPath)
	if err != nil {
		mu.Die("error creating message file: %v", err)
	}

	// encoding the message
	enc := gob.NewEncoder(msgFile)

	treeMarshalledKeys, err := treePublic.MarshalKeys()
	if err != nil {
		mu.Die("failed to marshal the tree's public keys: %v", err)
	}
	msg := message{marshalledIKS, marshalledEKS, marshalledsuk, treeMarshalledKeys}
	enc.Encode(msg)
	msgFile.Close()

	// sign message file with the initiator's private key
	sig, err := cryptutl.SignFile(opts.privIKFile, msgPath)
	if err != nil {
		mu.Die("error signing message file: %v", err)
	}

	sigFile := filepath.Join(opts.outdir, "setup.msg.sig")
	err = os.WriteFile(sigFile, sig, 0440)
	if err != nil {
		mu.Die("can't write signature file: %v", err)
	}

	return msg
}

func newGroupFromFile(configFile string) *group {
	var err error
	var m *member
	g := &group{}
	nameSet := make(map[string]bool)

	f, err := os.Open(configFile)
	if err != nil {
		mu.Die("error: can't open config file: %v", err)
	}
	defer f.Close()

	lineNum := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		numFields := len(fields)
		if numFields == 0 {
			continue
		}
		if numFields != 3 {
			mu.Die("error: config file line %d has %d fields; expected 3", lineNum, numFields)
		}

		name, pubIKFile, pubEKFile := fields[0], fields[1], fields[2]
		if exists := nameSet[name]; exists {
			mu.Die("error: config file has multiple entries for %q", name)
		}
		nameSet[name] = true

		pubIKFile = mu.ResolvePath(pubIKFile, configFile)
		pubEKFile = mu.ResolvePath(pubEKFile, configFile)

		m, err = newMember(name, pubIKFile, pubEKFile)
		if err != nil {
			mu.Die("error: %v", err)
		}
		g.addMember(m)
	}

	if err := scanner.Err(); err != nil {
		mu.Die("error: failed to read config file: %v", err)
	}

	numMembers := len(nameSet)
	if numMembers == 0 {
		mu.Die("error: config file has zero entries")
	}

	if !mu.IsPowerOfTwo(uint(numMembers)) {
		mu.Die("error: config file must have a power of two number of members, but has %d", numMembers)
	}

	return g
}

func parseOptions() *options {
	opts := options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.initiator, "initiator", "", "")
	flag.StringVar(&opts.outdir, "outdir", "", "")
	flag.Parse()

	if flag.NArg() != 2 {
		mu.Die(shortUsage)
	}

	opts.configFile = flag.Arg(0)
	opts.privIKFile = flag.Arg(1)

	if opts.outdir == "" {
		opts.outdir = filepath.Base(opts.configFile) + ".dir"
	}

	return &opts
}

func main() {
	opts := parseOptions()

	g := newGroupFromFile(opts.configFile)
	//g.printMembers()

	err := os.MkdirAll(opts.outdir, 0750)
	if err != nil {
		mu.Die("error: can't create outdir: %v", err)
	}

	g.setup(opts)
}
