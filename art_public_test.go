package art_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/etclab/art"
	"github.com/etclab/mu"
)

const updaterIndex = 2

type Updater struct {
	index int
	m     *art.Member
	state *art.TreeState
}

func NewUpdater(index int) *Updater {
	u := new(Updater)
	u.index = index
	return u
}

func (u *Updater) DeriveLeafKeyOrFail(suk *ecdh.PublicKey) {
	raw, err := art.KeyExchange(u.m.PrivEK, suk)
	if err != nil {
		mu.Fatalf("failed to generate the updater's leaf key: %v", err)
	}

	leafKey, err := art.UnmarshalPrivateX25519FromRaw(raw)
	if err != nil {
		mu.Fatalf("failed to unmarshal the updater's leaf key: %v", err)
	}

	u.m.LeafKey = leafKey
	u.state.Lk = leafKey
}

func (u *Updater) ProcessSetupMsg(setupMsg *art.SetupMessage) {
	u.state = new(art.TreeState)

	suk := setupMsg.GetSetupKey()
	u.state.PublicTree = setupMsg.GetPublicTree()
	u.DeriveLeafKeyOrFail(suk)
	u.state.IKeys = setupMsg.IKeys

	treeSecret := u.state.DeriveTreeKey(u.index)
	u.state.Sk = setupMsg.DeriveStageKey(treeSecret)
}

func (u *Updater) UpdateKey() (*art.UpdateMessage, *ed25519.PrivateKey) {
	var err error

	u.state.Lk, err = art.DHKeyGen()
	if err != nil {
		mu.Fatalf("error creating the new leaf key: %v", err)
	}

	pathKeys := art.UpdateCoPathNodes(u.index, u.state)
	treeSecret := pathKeys[len(pathKeys)-1]
	publicPathKeys := art.GetPublicKeys(pathKeys)
	updateMsg := art.CreateUpdateMessage(u.index, pathKeys)

	// replace the updated nodes in the full tree representation
	u.state.PublicTree = art.UpdatePublicTree(publicPathKeys, u.state.PublicTree, u.index)

	prevStageKey := u.state.Sk
	u.state.DeriveStageKey(treeSecret)

	return &updateMsg, &prevStageKey
}

func setupGroup(numMembers int) (*art.SetupMessage, *Updater) {
	updater := NewUpdater(updaterIndex)
	g := &art.Group{}

	for i := 0; i < numMembers; i++ {
		m := art.NewMember(fmt.Sprintf("member-%d", i))
		g.AddMember(m)

		if i == updaterIndex {
			updater.m = m
		}
	}

	suk := g.GenerateInitiatorKeys("")
	leafKeys := g.GenerateLeafKeys(suk)
	treeSecret, treePublic := art.GenerateTree(leafKeys)
	mu.UNUSED(treeSecret)
	setupMsg := g.CreateSetupMessage(suk.PublicKey(), treePublic)

	return setupMsg, updater
}

var blackholeMsg *art.UpdateMessage
var blackholeStageKey *ed25519.PrivateKey

func BenchmarkUpdate(b *testing.B) {
	// benchark [2^2, 2^20 = 1,048,576]
	for numMembers := 4; numMembers < 2097152; numMembers *= 2 {
		setupMsg, updater := setupGroup(numMembers)
		updater.ProcessSetupMsg(setupMsg)
		b.Run(fmt.Sprintf("Update-%d", numMembers), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				blackholeMsg, blackholeStageKey = updater.UpdateKey()
			}
		})
	}
}
