package keyutl

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

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
	case Raw:
		encoded, err = MarshalPublicIKToRaw(key)
	case DER:
		encoded, err = MarshalPublicIKToDER(key)
	case PEM:
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
	case Raw:
		encoded, err = MarshalPrivateIKToRaw(key)
	case DER:
		encoded, err = MarshalPrivateIKToDER(key)
	case PEM:
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
	case Raw:
		encoded, err = MarshalPublicEKToRaw(key)
	case DER:
		encoded, err = MarshalPublicEKToDER(key)
	case PEM:
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
	case Raw:
		encoded, err = MarshalPrivateEKToRaw(key)
	case DER:
		encoded, err = MarshalPrivateEKToDER(key)
	case PEM:
		encoded, err = MarshalPrivateEKToPEM(key)
	default:
		err = fmt.Errorf("cannot write private EK to file: unrecognized encoding format %q", encoding)
	}

	if err != nil {
		return err //TODO: wrap error
	}

	return os.WriteFile(path, encoded, PrivateKeyFileMode)
}
