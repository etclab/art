package art

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

type KeyEncoding int

const (
	EncodingUnknown KeyEncoding = iota
	EncodingRaw
	EncodingDER
	EncodingPEM
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
		return EncodingRaw, nil
	case "der":
		return EncodingDER, nil
	case "pem":
		return EncodingPEM, nil
	default:
		return EncodingUnknown, fmt.Errorf("unknown key encoding %q", keyform)
	}
}

//////////////////////////////////////////////////////////////////////////////
// MARSHALING/WRITING
//////////////////////////////////////////////////////////////////////////////

/********************************************************************
 * Public Identity Key (IK) - ed25519
 ********************************************************************/

func MarshalPublicIKToRaw(key ed25519.PublicKey) ([]byte, error) {
	return key, nil
}

func MarshalPublicIKToDER(key ed25519.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func MarshalPublicIKToPEM(key ed25519.PublicKey) ([]byte, error) {
	var pemBuf bytes.Buffer

	derData, err := MarshalPublicIKToDER(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  PublicIKPEMTypeString,
		Bytes: derData,
	}

	err = pem.Encode(&pemBuf, block)
	if err != nil {
		return nil, err
	}

	return pemBuf.Bytes(), nil
}

func WritePublicIKToFile(key ed25519.PublicKey, path string, encoding KeyEncoding) error {
	var err error
	var encoded []byte

	switch encoding {
	case EncodingRaw:
		encoded, err = MarshalPublicIKToRaw(key)
	case EncodingDER:
		encoded, err = MarshalPublicIKToDER(key)
	case EncodingPEM:
		encoded, err = MarshalPublicIKToPEM(key)
	default:
		err = fmt.Errorf("cannot write public IK to file: unrecognized encoding format %q", encoding)
	}

	if err != nil {
		return err //TODO: wrap error
	}

	return os.WriteFile(path, encoded, PublicKeyFileMode)
}

/********************************************************************
 * Private Identity Key (ik) - ed25519
 ********************************************************************/

func MarshalPrivateIKToRaw(key ed25519.PrivateKey) ([]byte, error) {
	return key, nil
}

func MarshalPrivateIKToDER(key ed25519.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

func MarshalPrivateIKToPEM(key ed25519.PrivateKey) ([]byte, error) {
	var pemBuf bytes.Buffer

	derData, err := MarshalPrivateIKToDER(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  PrivateIKPEMTypeString,
		Bytes: derData,
	}

	err = pem.Encode(&pemBuf, block)
	if err != nil {
		return nil, err
	}

	return pemBuf.Bytes(), nil
}

func WritePrivateIKToFile(key ed25519.PrivateKey, path string, encoding KeyEncoding) error {
	var err error
	var encoded []byte

	switch encoding {
	case EncodingRaw:
		encoded, err = MarshalPrivateIKToRaw(key)
	case EncodingDER:
		encoded, err = MarshalPrivateIKToDER(key)
	case EncodingPEM:
		encoded, err = MarshalPrivateIKToPEM(key)
	default:
		err = fmt.Errorf("cannot write private IK to file: unrecognized encoding format %q", encoding)
	}

	if err != nil {
		return err //TODO: wrap error
	}

	return os.WriteFile(path, encoded, PrivateKeyFileMode)
}

/*******************************************************************
 * Public Ephemeral Key (EK, also called a setup key) - x25519
 ********************************************************************/

func MarshalPublicEKToRaw(key *ecdh.PublicKey) ([]byte, error) {
	return key.Bytes(), nil
}

func MarshalPublicEKToDER(key *ecdh.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func MarshalPublicEKToPEM(key *ecdh.PublicKey) ([]byte, error) {
	var pemBuf bytes.Buffer

	derData, err := MarshalPublicEKToDER(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  PublicEKPEMTypeString,
		Bytes: derData,
	}

	err = pem.Encode(&pemBuf, block)
	if err != nil {
		return nil, err
	}

	return pemBuf.Bytes(), nil
}

func WritePublicEKToFile(key *ecdh.PublicKey, path string, encoding KeyEncoding) error {
	var err error
	var encoded []byte

	switch encoding {
	case EncodingRaw:
		encoded, err = MarshalPublicEKToRaw(key)
	case EncodingDER:
		encoded, err = MarshalPublicEKToDER(key)
	case EncodingPEM:
		encoded, err = MarshalPublicEKToPEM(key)
	default:
		err = fmt.Errorf("cannot write public EK to file: unrecognized encoding format %q", encoding)
	}

	if err != nil {
		return err //TODO: wrap error
	}

	return os.WriteFile(path, encoded, PublicKeyFileMode)
}

/*******************************************************************
 * Private Ephemeral Key (ek, also called a setup key) - x25519
 ********************************************************************/

func MarshalPrivateEKToRaw(key *ecdh.PrivateKey) ([]byte, error) {
	return key.Bytes(), nil
}

func MarshalPrivateEKToDER(key *ecdh.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

func MarshalPrivateEKToPEM(key *ecdh.PrivateKey) ([]byte, error) {
	var pemBuf bytes.Buffer

	derData, err := MarshalPrivateEKToDER(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  PrivateEKPEMTypeString,
		Bytes: derData,
	}

	err = pem.Encode(&pemBuf, block)
	if err != nil {
		return nil, err
	}

	return pemBuf.Bytes(), nil
}

func WritePrivateEKToFile(key *ecdh.PrivateKey, path string, encoding KeyEncoding) error {
	var err error
	var encoded []byte

	switch encoding {
	case EncodingRaw:
		encoded, err = MarshalPrivateEKToRaw(key)
	case EncodingDER:
		encoded, err = MarshalPrivateEKToDER(key)
	case EncodingPEM:
		encoded, err = MarshalPrivateEKToPEM(key)
	default:
		err = fmt.Errorf("cannot write private EK to file: unrecognized encoding format %q", encoding)
	}

	if err != nil {
		return err //TODO: wrap error
	}

	return os.WriteFile(path, encoded, PrivateKeyFileMode)
}

//////////////////////////////////////////////////////////////////////////////
// UNMARSHALING/READING
//////////////////////////////////////////////////////////////////////////////

/* N.B., ed25519.PublicKey and ed25519.PrivateKey are just aliases for []byte * */

/********************************************************************
 * Public Identity Key (IK) - ed25519
 ********************************************************************/

func UnmarshalPublicIKFromRaw(data []byte) (ed25519.PublicKey, error) {
	if len(data) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key size")
	}
	// TODO: what happens if raw is not an valid PublicKey?
	return ed25519.PublicKey(data), nil
}

func UnmarshalPublicIKFromDER(derData []byte) (ed25519.PublicKey, error) {
	tmp, err := x509.ParsePKIXPublicKey(derData)
	if err != nil {
		return nil, err // TODO: wrap the error message
	}

	key, ok := tmp.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("result of DER-decode is not an Ed25519 public key")
	}

	return key, nil
}

func UnmarshalPublicIKFromPEM(pemData []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("PEM-decode failed")
	}
	if block.Type != PublicIKPEMTypeString {
		return nil, fmt.Errorf("failed to PEM-decode public IK: expected PEM type string %q; got %q",
			PublicIKPEMTypeString, block.Type)
	}
	return UnmarshalPublicIKFromDER(block.Bytes)
}

func ReadPublicIKFromFile(path string, encoding KeyEncoding) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	switch encoding {
	case EncodingRaw:
		return UnmarshalPublicIKFromRaw(data)
	case EncodingDER:
		return UnmarshalPublicIKFromDER(data)
	case EncodingPEM:
		return UnmarshalPublicIKFromPEM(data)
	default:
		return nil, fmt.Errorf("cannot read public IK from file: unrecognized encoding format %q", encoding)
	}
}

/********************************************************************
 * Private Identity Key (ik) - ed25519
 ********************************************************************/

func UnmarshalPrivateIKFromRaw(data []byte) (ed25519.PrivateKey, error) {
	if len(data) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	// TODO: what happens if raw is not an valid privatekey?
	return ed25519.PrivateKey(data), nil
}

func UnmarshalPrivateIKFromDER(derData []byte) (ed25519.PrivateKey, error) {
	tmp, err := x509.ParsePKCS8PrivateKey(derData)
	if err != nil {
		return nil, err // TODO: wrap the error message
	}

	key, ok := tmp.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("result of DER-decode is not an Ed25519 private key")
	}

	return key, nil
}

func UnmarshalPrivateIKFromPEM(pemData []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("PEM-decode failed")
	}
	if block.Type != PrivateIKPEMTypeString {
		return nil, fmt.Errorf("failed to PEM-decode private IK: expected PEM type string %q; got %q",
			PrivateIKPEMTypeString, block.Type)
	}

	return UnmarshalPrivateIKFromDER(block.Bytes)
}

func ReadPrivateIKFromFile(path string, encoding KeyEncoding) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	switch encoding {
	case EncodingRaw:
		return UnmarshalPrivateIKFromRaw(data)
	case EncodingDER:
		return UnmarshalPrivateIKFromDER(data)
	case EncodingPEM:
		return UnmarshalPrivateIKFromPEM(data)
	default:
		return nil, fmt.Errorf("cannot read private IK from file: unrecognized encoding format %q", encoding)
	}
}

/*******************************************************************
 * Public Ephemeral Key (EK, also called a setup key) - x25519
 ********************************************************************/

func UnmarshalPublicEKFromRaw(data []byte) (*ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	return curve.NewPublicKey(data)
}

func UnmarshalPublicEKFromDER(derData []byte) (*ecdh.PublicKey, error) {
	tmp, err := x509.ParsePKIXPublicKey(derData)
	if err != nil {
		return nil, err // TODO: wrap the error message
	}

	key, ok := tmp.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("result of DER-decode is not an X25519 public key")
	}

	return key, nil
}

func UnmarshalPublicEKFromPEM(pemData []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("PEM-decode failed")
	}
	if block.Type != PublicEKPEMTypeString {
		return nil, fmt.Errorf("failed to PEM-decode public EK: expected PEM type string %q; got %q",
			PublicEKPEMTypeString, block.Type)
	}

	return UnmarshalPublicEKFromDER(block.Bytes)
}

func ReadPublicEKFromFile(path string, encoding KeyEncoding) (*ecdh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	switch encoding {
	case EncodingRaw:
		return UnmarshalPublicEKFromRaw(data)
	case EncodingDER:
		return UnmarshalPublicEKFromDER(data)
	case EncodingPEM:
		return UnmarshalPublicEKFromPEM(data)
	default:
		return nil, fmt.Errorf("cannot read public EK from file: unrecognized encoding format %q", encoding)
	}
}

/*******************************************************************
 * Private Ephemeral Key (ek, also called a setup key) - x25519
 ********************************************************************/

func UnmarshalPrivateEKFromRaw(data []byte) (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	return curve.NewPrivateKey(data)
}

func UnmarshalPrivateEKFromDER(derData []byte) (*ecdh.PrivateKey, error) {
	tmp, err := x509.ParsePKCS8PrivateKey(derData)
	if err != nil {
		return nil, err // TODO: wrap err
	}

	key, ok := tmp.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("result of DER-decode is not an X25519 private key")
	}

	return key, nil
}

func UnmarshalPrivateEKFromPEM(pemData []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("PEM-decode failed")
	}
	if block.Type != PrivateEKPEMTypeString {
		return nil, fmt.Errorf("failed to PEM-decode private EK: expected PEM type string %q; got %q",
			PrivateEKPEMTypeString, block.Type)
	}
	return UnmarshalPrivateEKFromDER(block.Bytes)
}

func ReadPrivateEKFromFile(path string, encoding KeyEncoding) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	switch encoding {
	case EncodingRaw:
		return UnmarshalPrivateEKFromRaw(data)
	case EncodingDER:
		return UnmarshalPrivateEKFromDER(data)
	case EncodingPEM:
		return UnmarshalPrivateEKFromPEM(data)
	default:
		return nil, fmt.Errorf("cannot read private EK from file: unrecognized encoding format %q", encoding)
	}
}

/*******************************************************************
 * Leaf Key and Node Keys - x25519
 *
 * N.B.: These are actually the same functions as for EK keys.
 ********************************************************************/

func UnmarshalPrivateX25519FromRaw(data []byte) (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	return curve.NewPrivateKey(data)
}
