// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"strings"
)

func NewHmacSha256SigningAlgorithm(key []byte, keyId string) (SigningAlgorithm, error) {
	if keyId = strings.TrimSpace(keyId); keyId == "" {
		return nil, ErrorEmptyKeyId
	}
	copiedKey := make([]byte, len(key))
	copy(copiedKey, key)
	return &hmacSigningAlgorithm{
		algName: AlgorithmHmacSha256,
		keyId:   keyId,
		hmac:    hmac.New(sha256.New, copiedKey),
	}, nil
}

type hmacSigningAlgorithm struct {
	algName AlgorithmName
	keyId   string
	hmac    hash.Hash
}

func (s *hmacSigningAlgorithm) KeyId() string {
	return s.keyId
}

func (s *hmacSigningAlgorithm) AlgName() AlgorithmName {
	return s.algName
}

func (s *hmacSigningAlgorithm) Sign(input []byte) ([]byte, error) {
	defer s.hmac.Reset()
	s.hmac.Write(input)
	digest := s.hmac.Sum(nil)
	return digest, nil
}
