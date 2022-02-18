// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	ErrorUnknownAlgorithm           = errors.New("algorithm name not in HTTP Signature Algorithms Registry")
	ErrorAlgorithmKeyMismatch       = errors.New("wrong private key type for specified algorithm")
	ErrorEmptyKeyId                 = errors.New("expected a non-empty key ID")
	ErrorDigestVerificationFailed   = errors.New("digest verification failed")
	ErrorInvalidSigLength           = errors.New("the base64-decoded signature has an unexpected length")
	ErrorUnsupportedDigestAlgorithm = errors.New("a digest header was found, but it didn't contain a digest in a supported algorithm")
)

type SigningAlgorithm interface {
	KeyId() string
	AlgName() AlgorithmName
	Sign(input []byte) ([]byte, error)
}

type VerifyingAlgorithm interface {
	KeyId() string
	AlgName() AlgorithmName
	Verify(input, sig []byte) (bool, error)
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
	}
	return nil, ErrorUnknownAlgorithm
}

func NewAsymmetricVerifyingAlgorithm(algName AlgorithmName, pubKey crypto.PublicKey, keyId string) (VerifyingAlgorithm, error) {
	if keyId = strings.TrimSpace(keyId); keyId == "" {
		return nil, ErrorEmptyKeyId
	}

	var hashOpt crypto.Hash
	switch algName {
	case AlgorithmEcdsaP256Sha256:
		hashOpt = crypto.SHA256
		if ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			return &ecdsaVerifyingAlgorithm{
				algName: algName,
				keyId:   keyId,
				pubKey:  ecdsaPubKey,
				hashOpt: hashOpt,
				hash:    hashOpt.New(),
			}, nil
		} else {
			return nil, ErrorAlgorithmKeyMismatch
		}
	}

	return nil, ErrorUnknownAlgorithm
}

type SignerOption func(options *sigOptions)

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

func now() time.Time {
	return time.Now()
}

var defaultSigName = []byte("sig1")

func NewVerifier(algFinder func(ctx context.Context, keyName string) (VerifyingAlgorithm, bool), opts ...SignerOption) (Verifier, error) {
	return &verifier{
		algFinder: algFinder,
		opts: sigOptions{
			hasCreated:         true,
			created:            now,
			hasNonce:           true,
			hasAlg:             true,
			coverAllComponents: true,
		},
		sigBufferPool: safepool.NewBufferPool(func() *bytes.Buffer {
			return bytes.NewBuffer(make([]byte, 0, 16*1024))
		}),
		b64BufferPool: safepool.NewPool(func() *[]byte {
			b := make([]byte, 0, 256)
			return &b
		}),
		componentsBufferPool: safepool.NewPool(func() *[]string {
			s := make([]string, 0, 128)
			return &s
		}),
	}, nil
}

type verifier struct {
	algFinder func(ctx context.Context, keyName string) (VerifyingAlgorithm, bool)
	opts      sigOptions

	sigBufferPool        *safepool.BufferPool
	b64BufferPool        *safepool.Pool[*[]byte]
	componentsBufferPool *safepool.Pool[*[]string]
}

const (
	SignatureInputHeaderName = "Signature-Input"
	SignatureHeaderName      = "Signature"
	DigestHeaderName         = "Digest"
)

var (
	ErrorMissingSigParams   = errors.New("missing 'Signature-Params' header")
	ErrorMissingSig         = errors.New("missing 'Signature' header")
	ErrorMalformedSigParams = errors.New("malformed 'Signature-Params' header")
	ErrorMalformedSig       = errors.New("malformed 'Signature' header")
	ErrorVerifyFailed       = errors.New("failed to verify signature")
	ErrorDigestMismatch     = errors.New("failed to verify content hash in 'Digest' header")
)

func parseComponents(buf []string, in string) (components []string, ok bool) {
	components = buf[:0]

	for in = strings.TrimSpace(in); len(in) > 0; in = strings.TrimSpace(in) {
		if in[0] != '"' {
			return nil, false
		}
		// eat the leading '"'
		in = in[1:]
		if i := strings.IndexByte(in, '"'); i >= 0 {
			c := in[:i]
			components = append(components, c)
			in = in[i+1:]
		} else {
			return nil, false
		}
	}
	return components, true
}

func contains(slice []string, s string) bool {
	for _, ss := range slice {
		if ss == s {
			return true
		}
	}
	return false
}

func getKeyId(params string) (keyId string, err error) {
	const keyIdStart = `;keyid="`
	if i := strings.Index(params, keyIdStart); i >= 0 {
		i += len(keyIdStart)
		if j := strings.Index(params[i:], `"`); j >= 0 {
			keyId = params[i : i+j]
		} else {
			return "", ErrorMalformedSigParams
		}
	}
	return
}

func getCreated(params string) (created time.Time, hasCreated bool, err error) {
	const createdStart = `;created=`
	if i := strings.Index(params, createdStart); i >= 0 {
		createdStr := params[i+len(createdStart):]
		if j := strings.IndexByte(createdStr, ';'); j >= 0 {
			createdStr = createdStr[:j]
		}
		if createdUnix, err := strconv.ParseInt(createdStr, 10, 64); err == nil {
			return time.Unix(createdUnix, 0), true, nil
		} else {

			return time.Time{}, false, ErrorMalformedSigParams
		}
	}
	return time.Time{}, false, nil
}

func (v *verifier) verifyDigest(ctx context.Context, req reqResp, body io.Reader) (err error) {
	for _, hdr := range req.Headers().Values(DigestHeaderName) {
		var first, rest string
		for first = hdr; first != ""; first = rest {
			first, rest, _ = strings.Cut(hdr, ",")

			digestAlg, digestVal, found := strings.Cut(first, "=")
			if !found {
				continue
			}

			if !strings.EqualFold(digestAlg, "sha-256") {
				err = ErrorUnsupportedDigestAlgorithm
				continue
			}

			expectedDigest, err := base64.StdEncoding.DecodeString(digestVal)
			if err != nil {
				return ErrorMalformedSig
			}

			digest := sha256.New()
			bytesRead, err := io.Copy(digest, body)
			if err != nil {
				return err
			}

			// TODO: should we compare this to content length?
			_ = bytesRead

			actualDigest := digest.Sum(nil)

			if subtle.ConstantTimeCompare(actualDigest, expectedDigest) == 1 {
				return nil
			} else {
				return ErrorDigestVerificationFailed
			}
		}

	}

	if err == nil {
		err = ErrorDigestVerificationFailed
	}

	return err
}

func (v *verifier) verify(ctx context.Context, req reqResp, body io.Reader) error {
	sigInput := v.sigBufferPool.Get()
	sigInputHeader := v.sigBufferPool.Get()
	coveredComponentsPtr := v.componentsBufferPool.Get()
	defer func() {
		v.sigBufferPool.Put(sigInput)
		v.sigBufferPool.Put(sigInputHeader)
		v.componentsBufferPool.Put(coveredComponentsPtr)
	}()
	coveredComponents := (*coveredComponentsPtr)[0:0]
	for _, hdr := range req.Headers().Values(SignatureInputHeaderName) {
		var first, rest string
		for first = hdr; first != ""; first = rest {
			first, rest, _ = strings.Cut(hdr, ",")

			sigId, params, found := strings.Cut(first, "=")
			if !found {
				// TODO: should we continue here?
				return ErrorMalformedSigParams
			}

			// basic sanity check: this needs to be non-empty, and start with the
			// list of covered components
			if len(params) == 0 || params[0] != '(' {
				return ErrorMalformedSigParams
			}

			// see if this is a key we know
			keyId, err := getKeyId(params)
			if err != nil {
				return err
			}

			alg, ok := v.algFinder(ctx, keyId)
			if !ok {
				fmt.Printf("no key '%s' found\n", keyId)
				continue
			}

			var componentsStr string
			if i := strings.IndexByte(params, ')'); i >= 0 {
				componentsStr = params[1:i]
			} else {
				return ErrorMalformedSigParams
			}
			if coveredComponents, ok = parseComponents(coveredComponents, componentsStr); !ok {
				return ErrorMalformedSigParams
			}

			// digest here has to be lowercase, rather than the HTTP 1.1 SnakeCase
			if contains(coveredComponents, "digest") {
				if err := v.verifyDigest(ctx, req, body); err != nil {
					return err
				}
			}

			opts := v.opts
			opts.hasAlg = false
			opts.coverAllComponents = false
			opts.coveredComponents = coveredComponents
			opts.keyId = keyId

			var created time.Time
			created, opts.hasCreated, err = getCreated(params)
			opts.created = func() time.Time {
				return created
			}

			getComponent := func(c string) string {
				if c == "@authority" {
					return req.Authority()
				} else {
					return req.Headers().Get(c)
				}
			}
			if err := buildInput(opts, getComponent, sigInput, sigInputHeader); err != nil {
				return err
			}

			sigHeader := req.Headers().Get(SignatureHeaderName)
			if !strings.HasPrefix(sigHeader, sigId) || len(sigHeader) < len(sigId)+1 || sigHeader[len(sigId)] != '=' {
				return ErrorMalformedSig
			}
			sig := sigHeader[len(sigId)+1:]
			if len(sig) == 0 || sig[0] != ':' || sig[len(sig)-1] != ':' {
				return ErrorMalformedSig
			}
			sig = sig[1 : len(sig)-1]
			bsig, err := base64.StdEncoding.DecodeString(sig)
			if err != nil {
				return ErrorMalformedSig
			}

			ok, err = alg.Verify(sigInput.Bytes(), bsig)
			if err != nil {
				return err
			}
			if !ok {
				return ErrorVerifyFailed
			}
			// great success!
			return nil
		}
	}

	return ErrorMissingSig
}

func (v *verifier) Verify(req *http.Request) error {
	return v.verify(req.Context(), (*httpRequest)(req), req.Body)
}

func (v *verifier) VerifyResponse(ctx context.Context, resp *http.Response) error {
	return v.verify(ctx, (*httpResponse)(resp), resp.Body)
}

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
		},
		sigNamer: func(r reqResp) []byte {
			return defaultSigName
		},
		sigBufferPool: safepool.NewBufferPool(func() *bytes.Buffer {
			return bytes.NewBuffer(make([]byte, 0, 16*1024))
		}),
		b64BufferPool: safepool.NewPool(func() *[]byte {
			b := make([]byte, 0, 256)
			return &b
		}),
	}
	for _, opt := range opts {
		opt(&s.opts)
	}
	return s, nil
}

type signer struct {
	alg      SigningAlgorithm
	opts     sigOptions
	sigNamer func(r reqResp) []byte

	sigBufferPool *safepool.BufferPool
	b64BufferPool *safepool.Pool[*[]byte]
}

type sigOptions struct {
	created            func() time.Time
	maxAge             time.Duration
	coveredComponents  []string
	keyId              string
	algName            AlgorithmName
	coverAllComponents bool
	hasCreated         bool
	hasNonce           bool
	hasAlg             bool
	hasMaxAge          bool
}

func buildInput(s sigOptions, getComponent func(c string) string, sigInput, sigInputHeader *bytes.Buffer) error {
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
			sigInput.WriteString(getComponent(c))
			sigInput.WriteByte('\n')
		}
	}

	sigInputHeader.WriteString(")")
	if s.hasCreated {
		var ibuf [32]byte
		i := strconv.AppendInt(ibuf[0:0:32], s.created().Unix(), 10)
		sigInputHeader.WriteString(";created=")
		sigInputHeader.Write(i)
	}

	sigInputHeader.WriteString(`;keyid="`)
	sigInputHeader.WriteString(s.keyId)
	sigInputHeader.WriteByte('"')

	if s.hasAlg {
		sigInputHeader.WriteString(`;alg="`)
		sigInputHeader.WriteString(string(s.algName))
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

type httpRequest http.Request
type httpResponse http.Response

func (r *httpRequest) Headers() http.Header {
	return r.Header
}

func (r *httpRequest) Authority() string {
	return r.Host
}

func (r *httpResponse) Headers() http.Header {
	return r.Header
}

func (r *httpResponse) Authority() string {
	// TODO
	return ""
}

type reqResp interface {
	Authority() string
	Headers() http.Header
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
		if c == "@authority" {
			return req.Authority()
		} else {
			return req.Headers().Get(c)
		}
	}, sigInput, sigInputHeader); err != nil {
		return err
	}

	sigName := s.sigNamer(req)
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

type Verifier interface {
	Verify(req *http.Request) error
	VerifyResponse(ctx context.Context, resp *http.Response) error
}
