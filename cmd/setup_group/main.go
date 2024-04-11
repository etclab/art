package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/syslab-wm/art"
	"github.com/syslab-wm/art/internal/cryptutl"
	"github.com/syslab-wm/art/internal/jsonutl"
	"github.com/syslab-wm/art/internal/keyutl"
	"github.com/syslab-wm/mu"
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

func newMember(name, pubIKFile, pubEKFile string) (*member, error) {
	var err error

	m := &member{name: name, pubIKFile: pubIKFile, pubEKFile: pubEKFile}

	m.pubIK, err = keyutl.ReadPublicIKFromFile(m.pubIKFile, keyutl.PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to read public IK for %q from %q: %v",
			m.name, m.pubIKFile, err)
	}

	m.pubEK, err = keyutl.ReadPublicEKFromFile(m.pubEKFile, keyutl.PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to read public EK for %q from %q: %v",
			m.name, m.pubEKFile, err)
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
		mu.Fatalf("error: initiator %q not found in config file", name)
	}
}

func (g *group) generateLeafKeys(setupKey *ecdh.PrivateKey) []*ecdh.PrivateKey {
	leafKeys := make([]*ecdh.PrivateKey, 0, len(g.members))
	for _, member := range g.members {
		if member.name == g.initiator.name {
			leafKeys = append(leafKeys, g.initiator.leafKey)
			continue
		}

		raw, err := art.KeyExchange(setupKey, member.pubEK)
		if err != nil {
			mu.Fatalf("failed to generate leafKey")
		}

		member.leafKey, err = keyutl.UnmarshalPrivateX25519FromRaw(raw)
		if err != nil {
			mu.Fatalf("failed to unmarshal leafKey")
		}
		leafKeys = append(leafKeys, member.leafKey)
	}
	return leafKeys
}

func (g *group) generateInitiatorKeys(initiator string) *ecdh.PrivateKey {
	var err error

	g.setInitiator(initiator)
	g.initiator.leafKey, err = art.DHKeyGen()
	if err != nil {
		mu.Fatalf("failed to generate initiator's leaf key: %v", err)
	}

	setupKey, err := art.KeyExchangeKeyGen()
	if err != nil {
		mu.Fatalf("failed to generate the setup key (suk): %v", err)
	}

	return setupKey
}

func generateTree(leafKeys []*ecdh.PrivateKey) (*ecdh.PrivateKey,
	*art.PublicNode) {
	treeRoot, err := art.CreateTree(leafKeys)
	if err != nil {
		mu.Fatalf("failed to create ART tree: %v", err)
	}

	treePublic := treeRoot.PublicKeys()
	treeSecret := treeRoot.GetSk()

	return treeSecret, treePublic
}

func deriveStageKey(treeSecret *ecdh.PrivateKey, msg *art.Message) []byte {
	stageInfo := art.StageKeyInfo{
		PrevStageKey:  make([]byte, art.StageKeySize),
		TreeSecretKey: treeSecret.Bytes(),
		IKeys:         msg.IKeys,
		TreeKeys:      msg.TreeKeys,
	}
	stageKey, err := art.DeriveStageKey(&stageInfo)
	if err != nil {
		mu.Fatalf("DeriveStageKey failed: %v", err)
	}

	return stageKey
}

func (g *group) setup(opts *options, state *art.TreeState) {

	suk := g.generateInitiatorKeys(opts.initiator)
	leafKeys := g.generateLeafKeys(suk)
	state.Lk = g.initiator.leafKey

	treeSecret, treePublic := generateTree(leafKeys)
	state.PublicTree = treePublic

	secretBytes, _ := keyutl.MarshalPrivateEKToPEM(treeSecret)
	fmt.Printf("Tree Secret:\n%v\n", string(secretBytes))

	msg := g.createSetupMessage(suk.PublicKey(), treePublic)
	g.saveSetupMessage(opts, msg)
	state.IKeys = msg.IKeys

	state.Sk = deriveStageKey(treeSecret, msg)

	fmt.Printf("Stage key: %v\n", state.Sk)
}

func (g *group) createSetupMessage(suk *ecdh.PublicKey,
	treePublic *art.PublicNode) *art.Message {
	// marshall identity keys, ephemeral keys, suk and tree public keys
	marshalledEKS := make([][]byte, 0, len(g.members))
	marshalledIKS := make([][]byte, 0, len(g.members))

	for _, member := range g.members {
		marshalledEK, err := keyutl.MarshalPublicEKToPEM(member.pubEK)
		if err != nil {
			mu.Fatalf("failed to marshal public EK: %v", err)
		}
		marshalledEKS = append(marshalledEKS, marshalledEK)

		marshalledIK, err := keyutl.MarshalPublicIKToPEM(member.pubIK)
		if err != nil {
			mu.Fatalf("failed to marshal public IK: %v", err)
		}
		marshalledIKS = append(marshalledIKS, marshalledIK)
	}

	marshalledSuk, err := keyutl.MarshalPublicEKToPEM(suk)
	if err != nil {
		mu.Fatalf("failed to marshal public SUK: %v", err)
	}

	marshalledPubKeys, err := treePublic.MarshalKeys()
	if err != nil {
		mu.Fatalf("failed to marshal the tree's public keys: %v", err)
	}
	msg := art.Message{
		IKeys:    marshalledIKS,
		EKeys:    marshalledEKS,
		Suk:      marshalledSuk,
		TreeKeys: marshalledPubKeys,
	}

	return &msg
}

// sign message file with initiator's private identity key
func signFile(msgFile, privateIKFile, sigFile string) {

	sig, err := cryptutl.SignFile(privateIKFile, msgFile)
	if err != nil {
		mu.Fatalf("error signing message file: %v", err)
	}

	err = os.WriteFile(sigFile, sig, 0440)
	if err != nil {
		mu.Fatalf("can't write signature file: %v", err)
	}
}

// ResolvePath resolves the rel path relative to the start path.
// The resolution is purely lexical.
func resolvePath(rel, start string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	dir := filepath.Dir(start)
	file := filepath.Base(rel)
	return filepath.Join(dir, file)
}

func (g *group) saveSetupMessage(opts *options, msg *art.Message) {

	err := os.MkdirAll(opts.outDir, 0750)
	if err != nil {
		mu.Fatalf("error: can't create out-dir: %v", err)
	}

	jsonutl.Encode(opts.msgFile, msg)

	privIKFile := resolvePath(opts.privIKFile, opts.configFile)

	signFile(opts.msgFile, privIKFile, opts.sigFile)
}

func getNewMember(fields []string, configDir string) *member {
	name, pubIKFile, pubEKFile := fields[0], fields[1], fields[2]

	pubIKFile = resolvePath(pubIKFile, configDir)
	pubEKFile = resolvePath(pubEKFile, configDir)

	member, err := newMember(name, pubIKFile, pubEKFile)
	if err != nil {
		mu.Fatalf("error: creating new group member %v", err)
	}

	return member
}

func validateMember(fields []string, lineNum int, nameSet map[string]bool) {
	numFields := len(fields)

	if numFields != 3 {
		mu.Fatalf("error: config file line %d has %d fields; expected 3", lineNum,
			numFields)
	}

	name := fields[0]
	if exists := nameSet[name]; exists {
		mu.Fatalf("error: config file has multiple entries for %q", name)
	}
	nameSet[name] = true
}

func addMembersFromFile(file *os.File) *group {
	g := &group{}
	nameSet := make(map[string]bool)

	lineNum := 0
	scanner := bufio.NewScanner(file)
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

		validateMember(fields, lineNum, nameSet)
		g.addMember(getNewMember(fields, file.Name()))
	}

	if err := scanner.Err(); err != nil {
		mu.Fatalf("error: failed to read config file: %v", err)
	}

	return g
}

func newGroupFromFile(configFile string) *group {
	f, err := os.Open(configFile)
	if err != nil {
		mu.Fatalf("error: can't open config file: %v", err)
	}
	defer f.Close()

	g := addMembersFromFile(f)

	numMembers := len(g.members)
	if numMembers == 0 {
		mu.Fatalf("error: config file has zero entries")
	}

	return g
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

func main() {
	opts := parseOptions()
	var state art.TreeState

	g := newGroupFromFile(opts.configFile)
	g.printMembers()

	g.setup(opts, &state)

	art.SaveTreeState(opts.treeStateFile, &state)
}
