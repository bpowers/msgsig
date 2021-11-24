// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"hash"
)

type asymmetricSigningAlgorithm struct {
	algName AlgorithmName
	keyId   string
	privKey crypto.Signer
	hashOpt crypto.Hash
	hash    hash.Hash
}

func (s *asymmetricSigningAlgorithm) KeyId() string {
	return s.keyId
}

func (s *asymmetricSigningAlgorithm) AlgName() AlgorithmName {
	return s.algName
}

func (s *asymmetricSigningAlgorithm) Sign(in []byte) ([]byte, error) {
	defer s.hash.Reset()
	s.hash.Write(in)
	digest := s.hash.Sum(nil)

	return s.privKey.Sign(rand.Reader, digest, s.hashOpt)
}

type asymmetricVerifyingAlgorithm struct {
	algName AlgorithmName
	keyId   string
	pubKey  crypto.PublicKey
	hashOpt crypto.Hash
	hash    hash.Hash
}

func (v *asymmetricVerifyingAlgorithm) KeyId() string {
	return v.keyId
}

func (v *asymmetricVerifyingAlgorithm) AlgName() AlgorithmName {
	return v.algName
}

func (v *asymmetricVerifyingAlgorithm) Verify(in, sig []byte) (bool, error) {
	defer v.hash.Reset()
	v.hash.Write(in)
	digest := v.hash.Sum(nil)

	return ecdsa.VerifyASN1(v.pubKey.(*ecdsa.PublicKey), digest, sig), nil
}
