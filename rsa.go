// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
)

type rsaPssSigningAlgorithm struct {
	keyId   string
	privKey *rsa.PrivateKey
	hashOpt crypto.Hash
	hash    hash.Hash
}

func (s *rsaPssSigningAlgorithm) KeyId() string {
	return s.keyId
}

func (s *rsaPssSigningAlgorithm) AlgName() AlgorithmName {
	return AlgorithmRsaPssSha512
}

func (s *rsaPssSigningAlgorithm) Sign(in []byte) ([]byte, error) {
	fmt.Printf("signing: `%s`\n", string(in))
	defer s.hash.Reset()
	s.hash.Write(in)
	digest := s.hash.Sum(nil)
	sig, err := rsa.SignPSS(rand.Reader, s.privKey, s.hashOpt, digest, &rsa.PSSOptions{
		SaltLength: 64,
		Hash:       s.hashOpt,
	})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

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
