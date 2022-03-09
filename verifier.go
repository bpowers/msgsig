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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bpowers/msgsig/internal/stringsutil"

	"github.com/bpowers/msgsig/safepool"
)

type AlgorithmName string

const (
	AlgorithmRsaPssSha512    AlgorithmName = "rsa-pss-sha512"
	AlgorithmRsaV15Sha256    AlgorithmName = "rsa-v1_5-sha256"
	AlgorithmEcdsaP256Sha256 AlgorithmName = "ecdsa-p256-sha256"
	AlgorithmHmacSha256      AlgorithmName = "hmac-sha256"
	AlgorithmEd25519         AlgorithmName = "ed25519"
)

var (
	ErrorUnknownAlgorithm           = errors.New("algorithm name not in HTTP Signature Algorithms Registry")
	ErrorAlgorithmKeyMismatch       = errors.New("wrong private key type for specified algorithm")
	ErrorEmptyKeyId                 = errors.New("expected a non-empty key ID")
	ErrorDigestVerificationFailed   = errors.New("digest verification failed")
	ErrorInvalidSigLength           = errors.New("the base64-decoded signature has an unexpected length")
	ErrorUnsupportedDigestAlgorithm = errors.New("a digest header was found, but it didn't contain a digest in a supported algorithm")
	ErrorMissingSigParams           = errors.New("missing 'Signature-Params' header")
	ErrorMissingSig                 = errors.New("missing 'Signature' header")
	ErrorMalformedSigParams         = errors.New("malformed 'Signature-Params' header")
	ErrorMalformedSig               = errors.New("malformed 'Signature' header")
	ErrorVerifyFailed               = errors.New("failed to verify signature")
	ErrorDigestMismatch             = errors.New("failed to verify content hash in 'Digest' header")
)

type VerifyingAlgorithm interface {
	KeyId() string
	AlgName() AlgorithmName
	Verify(input, sig []byte) (bool, error)
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
	case AlgorithmEd25519:
		if ed25519PubKey, ok := pubKey.(ed25519.PublicKey); ok {
			return &ed25519VerifyingAlgorithm{
				algName: algName,
				keyId:   keyId,
				pubKey:  ed25519PubKey,
			}, nil
		}
	}

	return nil, ErrorUnknownAlgorithm
}

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
		b64BufferPool: safepool.NewByteSlicePool(func() []byte {
			return make([]byte, 0, 256)
		}),
		componentsBufferPool: safepool.NewStringSlicePool(func() []string {
			return make([]string, 0, 128)
		}),
	}, nil
}

type verifier struct {
	algFinder func(ctx context.Context, keyName string) (VerifyingAlgorithm, bool)
	opts      sigOptions

	sigBufferPool        *safepool.BufferPool
	b64BufferPool        *safepool.ByteSlicePool
	componentsBufferPool *safepool.StringSlicePool
}

const (
	SignatureInputHeaderName = "Signature-Input"
	SignatureHeaderName      = "Signature"
	DigestHeaderName         = "Digest"
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

func verifyDigest(req reqResp, body []byte) (err error) {
	for _, hdr := range req.Headers().Values(DigestHeaderName) {
		var first, rest string
		for first = hdr; first != ""; first = rest {
			first, rest, _ = stringsutil.Cut(hdr, ',')

			digestAlg, digestVal, found := stringsutil.Cut(first, '=')
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
			if _, err := digest.Write(body); err != nil {
				return err
			}

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

func (v *verifier) verify(ctx context.Context, req reqResp, body []byte) error {
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
			first, rest, _ = stringsutil.Cut(hdr, ',')

			sigId, params, found := stringsutil.Cut(first, '=')
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
				if err := verifyDigest(req, body); err != nil {
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

			if err := buildInput(opts, func(c string) string {
				return getComponent(req, c)
			}, sigInput, sigInputHeader); err != nil {
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

func (v *verifier) Verify(req *http.Request, body []byte) error {
	return v.verify(req.Context(), (*httpRequest)(req), body)
}

func (v *verifier) VerifyResponse(ctx context.Context, resp *http.Response, body []byte) error {
	return v.verify(ctx, (*httpResponse)(resp), body)
}

type Verifier interface {
	Verify(req *http.Request, body []byte) error
	VerifyResponse(ctx context.Context, resp *http.Response, body []byte) error
}
