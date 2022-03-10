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
	ErrorUnknownKeyId               = errors.New("key ID provided, but key lookup failed")
	ErrorInvalidSigLength           = errors.New("the base64-decoded signature has an unexpected length")
	ErrorUnsupportedDigestAlgorithm = errors.New("a digest header was found, but it didn't contain a digest in a supported algorithm")
	ErrorMissingSig                 = errors.New("missing 'Signature' header")
	ErrorMalformedSigInput          = errors.New("malformed 'Signature-Input' header")
	ErrorMalformedSig               = errors.New("malformed 'Signature' header")
	ErrorMissingSigParamsValue      = errors.New("missing expected params for sigid in 'Signature-Input' header")
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
			return "", ErrorMalformedSigInput
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

			return time.Time{}, false, ErrorMalformedSigInput
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
				return ErrorDigestMismatch
			}
		}

	}

	if err == nil {
		err = ErrorDigestMismatch
	}

	return err
}

func getSigParams(headers http.Header, sigId string) (string, error) {
	baseErr := ErrorMissingSigParamsValue

	for _, hdr := range headers.Values(SignatureInputHeaderName) {
		var first, rest string
		for first = hdr; first != ""; first = rest {
			first, rest, _ = stringsutil.Cut(hdr, ',')

			foundSigId, params, found := stringsutil.Cut(first, '=')
			if !found {
				// record that it looks wrong, but then attempt to look for another signature
				baseErr = ErrorMalformedSigInput
				continue
			}

			if sigId != foundSigId {
				continue
			}

			return params, nil
		}
	}

	return "", baseErr
}

func (v *verifier) verify(ctx context.Context, req reqResp, body []byte) error {
	baseErr := ErrorMissingSig

	headers := req.Headers()

	// grab various scratch buffers from our `*sync.Pool`s
	sigInput := v.sigBufferPool.Get()
	sigInputHeader := v.sigBufferPool.Get()
	coveredComponentsPtr := v.componentsBufferPool.Get()
	defer func() {
		v.sigBufferPool.Put(sigInput)
		v.sigBufferPool.Put(sigInputHeader)
		v.componentsBufferPool.Put(coveredComponentsPtr)
	}()
	coveredComponents := (*coveredComponentsPtr)[0:0]

	// we may see both multiple Signature HTTP headers and multiple signatures in a
	// single header separated by a comma.  This double for-loop iterates over the
	// set of values without requiring extra allocations.
	//
	// the pseudocode for the loop below is roughly:
	//
	//   for sig in allSignatures(req):
	//       params = getParams(sig)
	//       key = v.algFinder(params.keyId)
	//       if shouldVerifyDigest(params) and not digestVerifies(req):
	//           return false
	//       input = buildInput(req, params)
	//       if verifies(key, input):
	//           return true
	//
	for _, hdr := range headers.Values(SignatureHeaderName) {
		var first, rest string
		for first = hdr; first != ""; first = rest {
			first, rest, _ = stringsutil.Cut(hdr, ',')

			sigId, sig, found := stringsutil.Cut(first, '=')
			if !found {
				// record that it looks wrong, but then attempt to look for another signature
				baseErr = ErrorMalformedSig
				continue
			}

			// pull the signature value out from after the sigId (the spec expects
			// it to be wrapped in ':' chars) as per
			// https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#section-4.2
			if len(sig) == 0 || sig[0] != ':' || sig[len(sig)-1] != ':' {
				baseErr = ErrorMalformedSig
				continue
			}
			sig = sig[1 : len(sig)-1]

			// the signature is base64 encoded, so decode it
			bsig, err := base64.StdEncoding.DecodeString(sig)
			if err != nil {
				return ErrorMalformedSig
			}

			// ensure we have the input parameters we need to verify this sig
			params, err := getSigParams(headers, sigId)
			if err != nil {
				baseErr = err
				continue
			}

			// basic sanity check: this needs to be non-empty, and start with the
			// list of covered components
			if len(params) == 0 || params[0] != '(' {
				baseErr = ErrorMalformedSigInput
				continue
			}

			// extract the key ID from the Signature-Input params
			keyId, err := getKeyId(params)
			if err != nil {
				baseErr = err
				continue
			}

			// see if this is a key we know
			alg, ok := v.algFinder(ctx, keyId)
			if !ok {
				baseErr = ErrorUnknownKeyId
				continue
			}

			var componentsStr string
			if i := strings.IndexByte(params, ')'); i >= 0 {
				componentsStr = params[1:i]
			} else {
				baseErr = ErrorMalformedSigInput
				continue
			}
			if coveredComponents, ok = parseComponents(coveredComponents, componentsStr); !ok {
				baseErr = ErrorMalformedSigInput
				continue
			}

			// digest in the set of covered components is lowercase
			// rather than the expected HTTP SnakeCase
			if contains(coveredComponents, "digest") {
				if err := verifyDigest(req, body); err != nil {
					return err
				}
			}

			// configure the input builder
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
				// this return is for this closure, not the outer verify method
				return getComponent(req, c)
			}, sigInput, sigInputHeader); err != nil {
				return err
			}

			ok, err = alg.Verify(sigInput.Bytes(), bsig)
			if err != nil {
				return err
			}
			if !ok {
				return ErrorVerifyFailed
			}

			// great success! signature verification passed so return without an error
			return nil
		}
	}

	return baseErr
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
