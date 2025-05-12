package art

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/etclab/mu"
)

type Member struct {
	Name      string
	PubIKFile string
	PubIK     ed25519.PublicKey
	PrivIK    ed25519.PrivateKey // XXX: only for benchmarking purposes
	PubEKFile string
	PubEK     *ecdh.PublicKey  // X25519
	PrivEK    *ecdh.PrivateKey // X25519; XXX: only for benchmarking purposes
	LeafKey   *ecdh.PrivateKey // X25519
}

type Group struct {
	members   []*Member
	initiator *Member
}

func (g *Group) AddMember(m *Member) {
	g.members = append(g.members, m)
}

func (g *Group) Member(name string) *Member {
	for _, m := range g.members {
		if m.Name == name {
			return m
		}
	}
	return nil
}

func (g *Group) First() *Member {
	return g.members[0]
}

func (g *Group) SetInitiator(name string) {
	if name == "" {
		g.initiator = g.First()
		return
	}

	g.initiator = g.Member(name)
	if g.initiator == nil {
		mu.Fatalf("error: initiator %q not found in config file", name)
	}
}

func (g *Group) GenerateLeafKeys(setupKey *ecdh.PrivateKey) []*ecdh.PrivateKey {
	leafKeys := make([]*ecdh.PrivateKey, 0, len(g.members))
	for _, member := range g.members {
		if member.Name == g.initiator.Name {
			leafKeys = append(leafKeys, g.initiator.LeafKey)
			continue
		}

		raw, err := KeyExchange(setupKey, member.PubEK)
		if err != nil {
			mu.Fatalf("failed to generate leafKey")
		}

		member.LeafKey, err = UnmarshalPrivateX25519FromRaw(raw)
		if err != nil {
			mu.Fatalf("failed to unmarshal leafKey")
		}
		leafKeys = append(leafKeys, member.LeafKey)
	}
	return leafKeys
}

func (g *Group) GenerateInitiatorKeys(initiator string) *ecdh.PrivateKey {
	var err error

	g.SetInitiator(initiator)
	g.initiator.LeafKey, err = DHKeyGen()
	if err != nil {
		mu.Fatalf("failed to generate initiator's leaf key: %v", err)
	}

	setupKey, err := KeyExchangeKeyGen()
	if err != nil {
		mu.Fatalf("failed to generate the setup key (suk): %v", err)
	}

	return setupKey
}

func (g *Group) CreateSetupMessage(suk *ecdh.PublicKey, treePublic *PublicNode) *SetupMessage {
	// marshall identity keys, ephemeral keys, suk and tree public keys
	marshalledEKS := make([][]byte, 0, len(g.members))
	marshalledIKS := make([][]byte, 0, len(g.members))

	for _, member := range g.members {
		marshalledEK, err := MarshalPublicEKToPEM(member.PubEK)
		if err != nil {
			mu.Fatalf("failed to marshal public EK: %v", err)
		}
		marshalledEKS = append(marshalledEKS, marshalledEK)

		marshalledIK, err := MarshalPublicIKToPEM(member.PubIK)
		if err != nil {
			mu.Fatalf("failed to marshal public IK: %v", err)
		}
		marshalledIKS = append(marshalledIKS, marshalledIK)
	}

	marshalledSuk, err := MarshalPublicEKToPEM(suk)
	if err != nil {
		mu.Fatalf("failed to marshal public SUK: %v", err)
	}

	marshalledPubKeys, err := treePublic.MarshalKeys()
	if err != nil {
		mu.Fatalf("failed to marshal the tree's public keys: %v", err)
	}
	msg := SetupMessage{
		IKeys:    marshalledIKS,
		EKeys:    marshalledEKS,
		Suk:      marshalledSuk,
		TreeKeys: marshalledPubKeys,
	}

	return &msg
}

func (g *Group) AddMembers(members []*Member) *Group {
	for _, m := range members {
		g.AddMember(m)
	}

	return g
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

func newMember(name, pubIKFile, pubEKFile string) (*Member, error) {
	var err error

	m := &Member{Name: name, PubIKFile: pubIKFile, PubEKFile: pubEKFile}

	m.PubIK, err = ReadPublicIKFromFile(m.PubIKFile, EncodingPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to read public IK for %q from %q: %v",
			m.Name, m.PubIKFile, err)
	}

	m.PubEK, err = ReadPublicEKFromFile(m.PubEKFile, EncodingPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to read public EK for %q from %q: %v",
			m.Name, m.PubEKFile, err)
	}

	return m, nil
}

func NewMember(name string) *Member {
	var err error

	m := new(Member)

	m.PubIK, m.PrivIK, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		mu.Fatalf("ed25519.GenerateKey failed: %v", err)
	}

	curve := ecdh.X25519()
	m.PrivEK, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		mu.Fatalf("ecdh.X25519 curve.GenerateKey failed: %v", err)
	}

	m.PubEK = m.PrivEK.PublicKey()

	return m
}

func GetNewMember(fields []string, configDir string) *Member {
	name, pubIKFile, pubEKFile := fields[0], fields[1], fields[2]

	// expects pubIKFile, pubEKFile and config file are in the same directory
	pubIKFile = resolvePath(pubIKFile, configDir)
	pubEKFile = resolvePath(pubEKFile, configDir)

	member, err := newMember(name, pubIKFile, pubEKFile)
	if err != nil {
		mu.Fatalf("error: creating new group member %v", err)
	}

	return member
}

func ValidateMember(fields []string, lineNum int, nameSet map[string]bool) {
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

func GetAllMembers(file *os.File) []*Member {
	members := make([]*Member, 0)
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
		if len(fields) == 0 {
			continue
		}

		ValidateMember(fields, lineNum, nameSet)
		members = append(members, GetNewMember(fields, file.Name()))
	}

	if err := scanner.Err(); err != nil {
		mu.Fatalf("error: failed to read config file: %v", err)
	}

	if len(members) == 0 {
		mu.Fatalf("error: no members in the group")
	}

	return members
}

func GetMembersFromFile(configFile string) []*Member {
	file, err := os.Open(configFile)
	if err != nil {
		mu.Fatalf("error: can't open config file: %v", err)
	}
	defer file.Close()

	return GetAllMembers(file)
}
