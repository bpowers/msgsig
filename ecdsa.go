// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"hash"
	"math/big"
)

type rsaV15SigningAlgorithm struct {
	algName AlgorithmName
	keyId   string
	privKey crypto.Signer
	hashOpt crypto.Hash
	hash    hash.Hash
}

func (s *rsaV15SigningAlgorithm) KeyId() string {
	return s.keyId
}

func (s *rsaV15SigningAlgorithm) AlgName() AlgorithmName {
	return s.algName
}

func (s *rsaV15SigningAlgorithm) Sign(in []byte) ([]byte, error) {
	defer s.hash.Reset()
	s.hash.Write(in)
	digest := s.hash.Sum(nil)

	return s.privKey.Sign(rand.Reader, digest, s.hashOpt)
}

type ecdsaSigningAlgorithm struct {
	algName AlgorithmName
	keyId   string
	privKey *ecdsa.PrivateKey
	hashOpt crypto.Hash
	hash    hash.Hash
}

func (esa *ecdsaSigningAlgorithm) KeyId() string {
	return esa.keyId
}

func (esa *ecdsaSigningAlgorithm) AlgName() AlgorithmName {
	return esa.algName
}

func (esa *ecdsaSigningAlgorithm) Sign(in []byte) ([]byte, error) {
	defer esa.hash.Reset()
	esa.hash.Write(in)
	digest := esa.hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, esa.privKey, digest)
	if err != nil {
		return nil, err
	}

	sig := make([]byte, 64)
	r.FillBytes(sig[:ecdsaIntLen])
	s.FillBytes(sig[ecdsaIntLen:])

	return sig, nil
}

type ecdsaVerifyingAlgorithm struct {
	algName AlgorithmName
	keyId   string
	pubKey  *ecdsa.PublicKey
	hashOpt crypto.Hash
	hash    hash.Hash
}

const (
	ecdsaIntLen = 32
	ecdsaSigLen = ecdsaIntLen * 2
)

func parseSig(sig []byte) (r *big.Int, s *big.Int, err error) {
	if len(sig) != ecdsaSigLen {
		return nil, nil, ErrorInvalidSigLength
	}

	r = new(big.Int)
	r.SetBytes(sig[:ecdsaIntLen])

	s = new(big.Int)
	s.SetBytes(sig[ecdsaIntLen:])

	return r, s, nil
}

func (v *ecdsaVerifyingAlgorithm) KeyId() string {
	return v.keyId
}

func (v *ecdsaVerifyingAlgorithm) AlgName() AlgorithmName {
	return v.algName
}

func (v *ecdsaVerifyingAlgorithm) Verify(in, sig []byte) (bool, error) {
	defer v.hash.Reset()
	v.hash.Write(in)
	digest := v.hash.Sum(nil)

	r, s, err := parseSig(sig)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(v.pubKey, digest, r, s), nil
}
