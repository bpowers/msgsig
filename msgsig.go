// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"hash"
	"net/http"
	"strings"
	"time"
)

type AlgorithmName string

const (
	AlgorithmRsaPssSha512    AlgorithmName = "rsa-pss-sha512"
	AlgorithmRsaV15Sha256    AlgorithmName = "rsa-v1_5-sha256"
	AlgorithmEcdsaP256Sha256 AlgorithmName = "ecdsa-p256-sha256"
	AlgorithmHmacSha256      AlgorithmName = "hmac-sha256"
)

var (
	ErrorUnknownAlgorithm     = errors.New("algorithm name not in HTTP Signature Algorithms Registry")
	ErrorAlgorithmKeyMismatch = errors.New("wrong private key type for specified algorithm")
	ErrorEmptyKeyId           = errors.New("expected a non-empty key ID")
)

type SigningAlgorithm interface {
	KeyId() string
	Sign(input []byte) []byte
}

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

func (s *hmacSigningAlgorithm) Sign(input []byte) []byte {
	return nil
}

func NewAsymmetricSigningAlgorithm(algName AlgorithmName, privKey crypto.Signer, keyId string) (SigningAlgorithm, error) {
	if keyId = strings.TrimSpace(keyId); keyId == "" {
		return nil, ErrorEmptyKeyId
	}

	var hashOpt crypto.Hash
	switch algName {
	case AlgorithmRsaPssSha512:
		if _, ok := privKey.(*rsa.PrivateKey); !ok {
			return nil, ErrorAlgorithmKeyMismatch
		}
		hashOpt = crypto.SHA512
	case AlgorithmRsaV15Sha256:
		if _, ok := privKey.(*rsa.PrivateKey); !ok {
			return nil, ErrorAlgorithmKeyMismatch
		}
		hashOpt = crypto.SHA256
	case AlgorithmEcdsaP256Sha256:
		if _, ok := privKey.(*ecdsa.PrivateKey); !ok {
			return nil, ErrorAlgorithmKeyMismatch
		}
		hashOpt = crypto.SHA256
	default:
		return nil, ErrorUnknownAlgorithm
	}
	return &asymmetricSigningAlgorithm{
		algName: algName,
		keyId:   keyId,
		privKey: privKey,
		hashOpt: hashOpt,
		hash:    hashOpt.New(),
	}, nil
}

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

func (s *asymmetricSigningAlgorithm) Sign([]byte) []byte {
	return nil
}

type SignerOption func(*signer)

// WithCreated ensures that signatures created by a Signer with this option set have a created signature parameter.
func WithCreated(b bool) func(s *signer) {
	return func(s *signer) {
		s.hasCreated = b
	}
}

func WithMaxAge(duration time.Duration) func(s *signer) {
	return func(s *signer) {
		s.maxAge = &duration
	}
}

func WithCoveredComponents(components ...string) func(s *signer) {
	return func(s *signer) {
		s.coverAllComponents = false
		s.coveredComponents = components
	}
}

func WithNoCoveredComponents() func(s *signer) {
	return func(s *signer) {
		s.coverAllComponents = false
	}
}

func NewSigner(alg SigningAlgorithm, opts ...SignerOption) (Signer, error) {
	s := &signer{alg: alg, coverAllComponents: true}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

type signer struct {
	alg                SigningAlgorithm
	hasCreated         bool
	maxAge             *time.Duration
	coverAllComponents bool
	coveredComponents  []string
}

// Sign computes a signature over the covered components of the request and adds it to the request.
func (s *signer) Sign(req *http.Request) error {
	return nil
}

// Signer objects sign HTTP requests.
type Signer interface {
	Sign(req *http.Request) error
}
