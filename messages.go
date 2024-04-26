package art

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/syslab-wm/art/internal/jsonutl"
	"github.com/syslab-wm/mu"
)

type SetupMessage struct {
	IKeys    [][]byte `json:"iKeys"`
	EKeys    [][]byte `json:"eKeys"`
	Suk      []byte   `json:"suk"`
	TreeKeys [][]byte `json:"treeKeys"`
}

func (sm *SetupMessage) Save(fileName string) {
	jsonutl.Encode(fileName, sm)
}

// TODO: why is this part of the SetupMessage struct?
func (sm *SetupMessage) SaveSign(sigFile, msgFile, privIKFile string) {
	sig, err := SignFile(privIKFile, msgFile)
	if err != nil {
		mu.Fatalf("error signing message file: %v", err)
	}

	err = os.WriteFile(sigFile, sig, 0440)
	if err != nil {
		mu.Fatalf("can't write signature file: %v", err)
	}

}

func (sm *SetupMessage) Decode(file *os.File) {
	dec := json.NewDecoder(file)
	err := dec.Decode(&sm)
	if err != nil {
		mu.Fatalf("error decoding message from file:", err)
	}
}

func (sm *SetupMessage) Read(msgFilePath string) {
	msgFile, err := os.Open(msgFilePath)
	if err != nil {
		mu.Fatalf("error opening message file:", err)
	}
	defer msgFile.Close()

	sm.Decode(msgFile)
}

func (sm *SetupMessage) GetSetupKey() *ecdh.PublicKey {
	suk, err := UnmarshalPublicEKFromPEM(sm.Suk)
	if err != nil {
		mu.Fatalf("failed to unmarshal public SUK")
	}
	return suk
}

func (sm *SetupMessage) GetPublicTree() *PublicNode {
	tree, err := UnmarshalKeysToPublicTree(sm.TreeKeys)
	if err != nil {
		mu.Fatalf("error unmarshalling the public tree keys: %v", err)
	}
	return tree
}

func (sm *SetupMessage) DeriveStageKey(treeSecret *ecdh.PrivateKey) []byte {
	stageInfo := StageKeyInfo{
		PrevStageKey:  make([]byte, StageKeySize),
		TreeSecretKey: treeSecret.Bytes(),
		IKeys:         sm.IKeys,
		TreeKeys:      sm.TreeKeys,
	}
	stageKey, err := DeriveStageKey(&stageInfo)
	if err != nil {
		mu.Fatalf("DeriveStageKey failed: %v", err)
	}

	return stageKey
}

type UpdateMessage struct {
	Idx            int
	PathPublicKeys [][]byte
}

func (um *UpdateMessage) Save(fileName string) {
	jsonutl.Encode(fileName, um)
}

func (um *UpdateMessage) SaveMac(sk ed25519.PrivateKey, macFile string) {
	// converting the update message contents into a byte array
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(um.Idx))
	MACBytes := bytes.Join(um.PathPublicKeys, []byte(" "))
	MACBytes = append(MACBytes, bs...)

	// creating the MAC
	mac := NewHMAC(sk)
	mac.Write(MACBytes)
	macData := mac.Sum(nil)

	err := os.WriteFile(macFile, macData, 0440)
	if err != nil {
		mu.Fatalf("can't write MAC signature file: %v", err)
	}
}

func (um *UpdateMessage) Decode(file *os.File) {
	dec := json.NewDecoder(file)
	err := dec.Decode(&um)
	if err != nil {
		mu.Fatalf("error decoding message from file:", err)
	}
}

func (um *UpdateMessage) Read(msgFilePath string) {
	msgFile, err := os.Open(msgFilePath)
	if err != nil {
		mu.Fatalf("error opening message file:", err)
	}
	defer msgFile.Close()

	um.Decode(msgFile)
}

func (um *UpdateMessage) verifyMAC(sk ed25519.PrivateKey, macFile string) (bool,
	error) {
	// convert the update message contents into a byte array
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(um.Idx))
	MACBytes := bytes.Join(um.PathPublicKeys, []byte(" "))
	MACBytes = append(MACBytes, bs...)

	// create the MAC
	mac := NewHMAC(sk)
	mac.Write(MACBytes)
	macData := mac.Sum(nil)

	// get the expected MAC data from the MAC file
	expectedMAC, err := os.ReadFile(macFile)
	if err != nil {
		return false, fmt.Errorf("can't read MAC signature file: %v", err)
	}

	return hmac.Equal(macData, expectedMAC), nil
}

// verify the message signature with the current stage key
func (um *UpdateMessage) VerifyUpdateMessage(sk ed25519.PrivateKey,
	macFile string) {
	valid, err := um.verifyMAC(sk, macFile)
	if err != nil {
		mu.Fatalf("error verifying update message file signature: %v", err)
	}
	if !valid {
		mu.Fatalf("update message failed to pass signature verification")
	}
}
