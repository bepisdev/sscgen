package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
)

// publicKey returns the public key corresponding to the given private key.
// It supports RSA, ECDSA, and Ed25519 private keys.
//
// Parameters:
// - priv: The private key for which the corresponding public key needs to be obtained.
//
// Returns:
// - The public key corresponding to the given private key.
// - nil if the provided private key type is not supported.
//
// Example:
//
//	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
//	if err != nil {
//		log.Fatal(err)
//	}
//	pubKey := publicKey(privKey)
func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
