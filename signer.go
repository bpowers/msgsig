// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/bpowers/msgsig/safepool"
)

// defaultSigName matches sig names in the spec, there is no special meaning here.
var defaultSigName = []byte("sig1")

type SigningAlgorithm interface {
	KeyId() string
	AlgName() AlgorithmName
	Sign(input []byte) ([]byte, error)
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
		return &rsaV15SigningAlgorithm{
			algName: algName,
			keyId:   keyId,
			privKey: privKey,
			hashOpt: hashOpt,
			hash:    hashOpt.New(),
		}, nil
	case AlgorithmEcdsaP256Sha256:
		hashOpt = crypto.SHA256
		if ecdsaPrivKey, ok := privKey.(*ecdsa.PrivateKey); ok {
			return &ecdsaSigningAlgorithm{
				algName: algName,
				keyId:   keyId,
				privKey: ecdsaPrivKey,
				hashOpt: hashOpt,
				hash:    hashOpt.New(),
			}, nil
		} else {
			return nil, ErrorAlgorithmKeyMismatch
		}
	case AlgorithmEd25519:
		if ed25519PrivKey, ok := privKey.(ed25519.PrivateKey); ok {
			return &ed25519SigningAlgorithm{
				algName: algName,
				keyId:   keyId,
				privKey: ed25519PrivKey,
			}, nil
		}
	}
	return nil, ErrorUnknownAlgorithm
}

type SignerOption func(options *sigOptions)

func WithSigNamer(namer func() string) func(s *sigOptions) {
	return func(s *sigOptions) {
		s.sigNamer = func(_ reqResp) []byte {
			return []byte(namer())
		}
	}
}

// WithCreated ensures that signatures created by a Signer with this option set have a created signature parameter.
func WithCreated(b bool) func(s *sigOptions) {
	return func(s *sigOptions) {
		s.hasCreated = b
	}
}

func WithMaxAge(duration time.Duration) func(s *sigOptions) {
	return func(s *sigOptions) {
		s.hasMaxAge = true
		s.maxAge = duration
	}
}

func WithCoveredComponents(components ...string) func(s *sigOptions) {
	return func(s *sigOptions) {
		s.coverAllComponents = false
		s.coveredComponents = components
	}
}

func WithNoCoveredComponents() func(s *sigOptions) {
	return func(s *sigOptions) {
		s.coverAllComponents = false
	}
}

func WithNonce(nonce bool) func(s *sigOptions) {
	return func(s *sigOptions) {
		s.hasNonce = nonce
	}
}

func WithAlg(alg bool) func(s *sigOptions) {
	return func(s *sigOptions) {
		s.hasAlg = alg
	}
}

func withTime(now func() time.Time) func(s *sigOptions) {
	return func(s *sigOptions) {
		s.created = now
	}
}

// signer is safe for use from multiple goroutines to create HTTP message signatures.
type signer struct {
	alg  SigningAlgorithm
	opts sigOptions

	sigBufferPool *safepool.BufferPool
	b64BufferPool *safepool.ByteSlicePool
}

// NewSigner returns a Signer that can be used to create and attach HTTP
// message signatures to http.Request and http.Response structs.
func NewSigner(alg SigningAlgorithm, opts ...SignerOption) (Signer, error) {
	s := &signer{
		alg: alg,
		opts: sigOptions{
			algName:            alg.AlgName(),
			keyId:              alg.KeyId(),
			hasCreated:         true,
			created:            now,
			hasNonce:           true,
			hasAlg:             true,
			coverAllComponents: true,
			sigNamer: func(r reqResp) []byte {
				return defaultSigName
			},
		},
		sigBufferPool: safepool.NewBufferPool(func() *bytes.Buffer {
			return bytes.NewBuffer(make([]byte, 0, 16*1024))
		}),
		b64BufferPool: safepool.NewByteSlicePool(func() []byte {
			return make([]byte, 0, 256)
		}),
	}
	for _, opt := range opts {
		opt(&s.opts)
	}
	return s, nil
}

func (s *signer) sign(ctx context.Context, req reqResp) error {
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

	if err := buildInput(s.opts, func(c string) string {
		return getComponent(req, c)
	}, sigInput, sigInputHeader); err != nil {
		return err
	}

	sigName := s.opts.sigNamer(req)
	headerBuf.Write(sigName)
	headerBuf.WriteByte('=')
	headerBuf.Write(sigInputHeader.Bytes())

	req.Headers().Set("Signature-Input", headerBuf.String())

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

	req.Headers().Set("Signature", headerBuf.String())

	return nil
}

// Sign computes a signature over the covered components of the request and adds it to the request.
func (s *signer) Sign(req *http.Request) error {
	return s.sign(req.Context(), (*httpRequest)(req))
}

// SignResponse computes a signature over the covered components of the response and adds it to the request.
func (s *signer) SignResponse(ctx context.Context, resp *http.Response) error {
	return s.sign(ctx, (*httpResponse)(resp))
}

// Signer objects sign HTTP requests.
type Signer interface {
	Sign(req *http.Request) error
	SignResponse(ctx context.Context, resp *http.Response) error
}
