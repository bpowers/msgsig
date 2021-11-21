// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bpowers/msgsig/safepool"
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
	AlgName() AlgorithmName
	Sign(input []byte) ([]byte, error)
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

func (s *hmacSigningAlgorithm) AlgName() AlgorithmName {
	return s.algName
}

func (s *hmacSigningAlgorithm) Sign(input []byte) ([]byte, error) {
	defer s.hmac.Reset()
	s.hmac.Write(input)
	digest := s.hmac.Sum(nil)
	return digest, nil
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
		if rsaKey, ok := privKey.(*rsa.PrivateKey); ok {
			return &rsaPssSigningAlgorithm{
				keyId:   keyId,
				privKey: rsaKey,
				hashOpt: hashOpt,
				hash:    hashOpt.New(),
			}, nil
		} else {
			return nil, ErrorAlgorithmKeyMismatch
		}
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

func (s *asymmetricSigningAlgorithm) AlgName() AlgorithmName {
	return s.algName
}

func (s *asymmetricSigningAlgorithm) Sign(in []byte) ([]byte, error) {
	defer s.hash.Reset()
	s.hash.Write(in)
	digest := s.hash.Sum(nil)

	return digest, nil
}

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

func WithNonce(nonce bool) func(s *signer) {
	return func(s *signer) {
		s.hasNonce = nonce
	}
}

func WithAlg(alg bool) func(s *signer) {
	return func(s *signer) {
		s.hasAlg = alg
	}
}

func WithSigNamer(sigNamer func(req *http.Request) []byte) func(s *signer) {
	return func(s *signer) {
		s.sigNamer = sigNamer
	}
}

func withTime(now func() time.Time) func(s *signer) {
	return func(s *signer) {
		s.now = now
	}
}

func now() time.Time {
	return time.Now()
}

var defaultSigName = []byte("sig1")

func NewSigner(alg SigningAlgorithm, opts ...SignerOption) (Signer, error) {
	s := &signer{
		alg:                alg,
		hasCreated:         true,
		hasNonce:           true,
		hasAlg:             true,
		coverAllComponents: true,
		sigNamer: func(r *http.Request) []byte {
			return defaultSigName
		},
		now: now,
		sigBufferPool: safepool.NewBufferPool(func() *bytes.Buffer {
			return bytes.NewBuffer(make([]byte, 0, 16*1024))
		}),
		b64BufferPool: safepool.NewPool(func() *[]byte {
			b := make([]byte, 0, 256)
			return &b
		}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

type signer struct {
	alg                SigningAlgorithm
	hasCreated         bool
	hasNonce           bool
	hasAlg             bool
	maxAge             *time.Duration
	sigNamer           func(req *http.Request) []byte
	coverAllComponents bool
	coveredComponents  []string
	now                func() time.Time

	sigBufferPool *safepool.BufferPool
	b64BufferPool *safepool.Pool[*[]byte]
}

type sigOptions struct {
	hasCreated bool
	created    time.Time
	hasNonce   bool
	hasAlg     bool
	hasMaxAge  bool
	maxAge     time.Duration
}

func (s *signer) buildInput(req *http.Request, sigInput, sigInputHeader *bytes.Buffer) error {
	sigInputHeader.WriteString("(")

	if s.coverAllComponents {
		panic("TODO")
	} else {
		for i, c := range s.coveredComponents {
			if i > 0 {
				sigInputHeader.WriteByte(' ')
			}
			sigInputHeader.WriteByte('"')
			sigInputHeader.WriteString(c)
			sigInputHeader.WriteByte('"')
			sigInput.WriteByte('"')
			sigInput.WriteString(c)
			sigInput.WriteString(`": `)
			if c == "@authority" {
				sigInput.WriteString(req.Host)
			} else {
				sigInput.WriteString(req.Header.Get(c))
			}
			sigInput.WriteByte('\n')
		}
	}

	sigInputHeader.WriteString(")")
	if s.hasCreated {
		var ibuf [32]byte
		i := strconv.AppendInt(ibuf[0:0:32], s.now().Unix(), 10)
		sigInputHeader.WriteString(";created=")
		sigInputHeader.Write(i)
	}

	sigInputHeader.WriteString(`;keyid="`)
	sigInputHeader.WriteString(s.alg.KeyId())
	sigInputHeader.WriteByte('"')

	if s.hasAlg {
		sigInputHeader.WriteString(`;alg="`)
		sigInputHeader.WriteString(string(s.alg.AlgName()))
		sigInputHeader.WriteByte('"')
	}

	sigInput.WriteString(`"@signature-params": `)
	sigInput.Write(sigInputHeader.Bytes())

	return nil
}

func zero(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = 0
	}
}

// Sign computes a signature over the covered components of the request and adds it to the request.
func (s *signer) Sign(req *http.Request) error {
	sigInput := s.sigBufferPool.Get()
	sigInputHeader := s.sigBufferPool.Get()
	headerBuf := s.sigBufferPool.Get()
	b64Buf := s.b64BufferPool.Get()
	defer func() {
		s.sigBufferPool.Put(sigInput)
		s.sigBufferPool.Put(sigInputHeader)
		s.sigBufferPool.Put(headerBuf)
		s.b64BufferPool.Put(b64Buf)
	}()

	sigName := s.sigNamer(req)

	if err := s.buildInput(req, sigInput, sigInputHeader); err != nil {
		return err
	}

	headerBuf.Write(sigName)
	headerBuf.WriteByte('=')
	headerBuf.Write(sigInputHeader.Bytes())

	req.Header.Set("Signature-Input", headerBuf.String())

	rawSig, err := s.alg.Sign(sigInput.Bytes())
	if err != nil {
		return err
	}

	headerBuf.Reset()
	headerBuf.Write(sigName)
	headerBuf.WriteString("=:")
	// encode the signature bytes in base64 for the header
	l := base64.StdEncoding.EncodedLen(len(rawSig))
	if l > cap(*b64Buf) {
		*b64Buf = make([]byte, 0, l)
	}
	b := (*b64Buf)[0:l]
	base64.StdEncoding.Encode(b, rawSig)
	headerBuf.Write(b)
	headerBuf.WriteByte(':')

	req.Header.Set("Signature", headerBuf.String())

	return nil
}

// Signer objects sign HTTP requests.
type Signer interface {
	Sign(req *http.Request) error
}

type Verifier interface {
	Verify(req *http.Request) error
}
