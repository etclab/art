package keyutl

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

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
	case Raw:
		return UnmarshalPublicIKFromRaw(data)
	case DER:
		return UnmarshalPublicIKFromDER(data)
	case PEM:
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
	case Raw:
		return UnmarshalPrivateIKFromRaw(data)
	case DER:
		return UnmarshalPrivateIKFromDER(data)
	case PEM:
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
	case Raw:
		return UnmarshalPublicEKFromRaw(data)
	case DER:
		return UnmarshalPublicEKFromDER(data)
	case PEM:
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
	case Raw:
		return UnmarshalPrivateEKFromRaw(data)
	case DER:
		return UnmarshalPrivateEKFromDER(data)
	case PEM:
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
