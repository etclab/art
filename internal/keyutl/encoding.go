package keyutl

import (
	"fmt"
	"strings"
)

type KeyEncoding int

const (
	Unknown = iota
	Raw
	DER
	PEM
)

const (
	PublicIKPEMTypeString  = "ED25519 PUBLIC KEY"
	PrivateIKPEMTypeString = "ED25519 PRIVATE KEY"
	PublicEKPEMTypeString  = "X25519 PUBLIC KEY"
	PrivateEKPEMTypeString = "X25519 PRIVATE KEY"
)

const (
	PublicKeyFileMode  = 0440
	PrivateKeyFileMode = 0400
)

func StringToKeyEncoding(keyform string) (KeyEncoding, error) {
	keyform = strings.ToLower(keyform)
	switch keyform {
	case "raw":
		return Raw, nil
	case "der":
		return DER, nil
	case "pem":
		return PEM, nil
	default:
		return Unknown, fmt.Errorf("unknown key encoding %q", keyform)
	}
}
