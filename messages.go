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

	"github.com/etclab/art/internal/jsonutl"
	"github.com/etclab/mu"
)

// SetupMessage represents the ART Setup message.
//
// Section 5.1 and Algorithm 1 of the "On Ends-to-Ends Encryption" [paper]
// describe the message.
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
type SetupMessage struct {
	// IKeys is the ed25519 public identity keys for all ART group members.  Each key is
	// the PEM encoding of the PKIX, ASN.1 DER form.
	IKeys [][]byte `json:"iKeys"`

	// Ekeys is the ECHD (x25519) ephemeral keys (aka, setup keys)
	// for the ART group members.  Each key is the PEM endoing of the PKIX,
	// ASN.1 DER form.
	EKeys [][]byte `json:"eKeys"`

	// Suk is the ART initiator's public setup key.  The key is an ECDH
	// (x25519) public key, represented as the PEM encoding of the PKIX, ASN.1
	// DER form.
	Suk []byte `json:"suk"`

	// TreeKeys is the breadth-first serialization of the ART tree's public
	// keys.  Each key is an ECHD (x25519) public key, represented as the PEM
	// encoding of the PKIX, ASN.1 DER form.
	TreeKeys [][]byte `json:"treeKeys"`
}

// Save writes the Setup message to a file in JSON format.
func (sm *SetupMessage) Save(fileName string) {
	jsonutl.Encode(fileName, sm)
}

// TODO: SaveSign: why is this part of the SetupMessage struct?

// SaveSign signs a setup message using the initiator's private identity key
// and writes the signature to a file.  This corresponds to line 13 of
// Algorithm 1 in the  Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// Decode reads a Setup message from an open file.  The file represents the
// message in JSON form.
func (sm *SetupMessage) Decode(file *os.File) {
	dec := json.NewDecoder(file)
	err := dec.Decode(&sm)
	if err != nil {
		mu.Fatalf("error decoding message from file:", err)
	}
}

// Read reads a Setup message from a JSON file.
func (sm *SetupMessage) Read(msgFilePath string) {
	msgFile, err := os.Open(msgFilePath)
	if err != nil {
		mu.Fatalf("error opening message file:", err)
	}
	defer msgFile.Close()

	sm.Decode(msgFile)
}

// GetSetupKey returns the *[ecdh.PublicKey] for the PEM-encoded
// [SetupMessage.Suk] field.
func (sm *SetupMessage) GetSetupKey() *ecdh.PublicKey {
	suk, err := UnmarshalPublicEKFromPEM(sm.Suk)
	if err != nil {
		mu.Fatalf("failed to unmarshal public SUK")
	}
	return suk
}

// GetPublicTree unmarshals the [SetupMessage.TreeKeys] field and returns the
// root of the public ART tree.
func (sm *SetupMessage) GetPublicTree() *PublicNode {
	tree, err := UnmarshalKeysToPublicTree(sm.TreeKeys)
	if err != nil {
		mu.Fatalf("error unmarshalling the public tree keys: %v", err)
	}
	return tree
}

// DeriveStageKey derives the stage key (group key) from the ART tree.  This
// function corresponds to Algorithm 2's DeriveStageKey function in the "On
// Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// UpdateMessage represents the ART Update Key Message.
// Section 5.2 and Algorithm 3 of the "On Ends-to-Ends Encryption" [paper]
// describe the message.
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
type UpdateMessage struct {
	Idx            int
	PathPublicKeys [][]byte
}

// Save writes the Update message to a file in JSON format.
func (um *UpdateMessage) Save(fileName string) {
	jsonutl.Encode(fileName, um)
}

// SaveMac computes a MAC for an update message.  sk is the current stage key.
//
// This corresponds to line 8 of algorithm 4 in the "On Ends-to-Ends
// Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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

// Decode reads an Update message from an open file.  The file represents the
// message in JSON form.
func (um *UpdateMessage) Decode(file *os.File) {
	dec := json.NewDecoder(file)
	err := dec.Decode(&um)
	if err != nil {
		mu.Fatalf("error decoding message from file:", err)
	}
}

// Read reads an Update message from a JSON file.
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

// VerifyUpdateMessage verifies the MAC on the Update message.  sk is the
// current stage key.
//
// The function corresponds to the MACVerify step in Algorithm 5's
// ProcessUpdateMessage in the "On Ends-to-Ends Encryption" [paper].
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
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
