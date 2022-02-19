// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"crypto/ed25519"
)

type ed25519SigningAlgorithm struct {
	algName AlgorithmName
	keyId   string
	privKey ed25519.PrivateKey
}

func (esa *ed25519SigningAlgorithm) KeyId() string {
	return esa.keyId
}

func (esa *ed25519SigningAlgorithm) AlgName() AlgorithmName {
	return esa.algName
}

func (esa *ed25519SigningAlgorithm) Sign(in []byte) ([]byte, error) {
	return ed25519.Sign(esa.privKey, in), nil
}

type ed25519VerifyingAlgorithm struct {
	algName AlgorithmName
	keyId   string
	pubKey  ed25519.PublicKey
}

func (v *ed25519VerifyingAlgorithm) KeyId() string {
	return v.keyId
}

func (v *ed25519VerifyingAlgorithm) AlgName() AlgorithmName {
	return v.algName
}

func (v *ed25519VerifyingAlgorithm) Verify(in, sig []byte) (bool, error) {
	return ed25519.Verify(v.pubKey, in, sig), nil
}
