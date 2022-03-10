// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed testmessages/request.http
	testRequestBytes string
	//go:embed testmessages/response.http
	testResponseBytes string

	testRequest  = getRequest()
	testResponse = getResponse()
)

func getResponse() *http.Response {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(testResponseBytes)), testRequest)
	if err != nil {
		panic(err)
	}
	return resp
}

func getRequest() *http.Request {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(testRequestBytes)))
	if err != nil {
		panic(err)
	}
	return req
}

func timeFromUnix(unixSecs int64) func() time.Time {
	return func() time.Time {
		return time.Unix(unixSecs, 0)
	}
}

func TestIterateCoveredComponents(t *testing.T) {
	in := `"@authority" "date" "content-type"`
	components, ok := parseComponents(nil, in)
	require.True(t, ok)
	require.Equal(t, []string{"@authority", "date", "content-type"}, components)
}

const (
	expectedMinimalSignatureRsaPssInput       = `sig1=();created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"`
	expectedMinimalSignatureRsaPss            = `sig1=:HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmEAAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgxTpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwNcZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkwIyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW+5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==:`
	expectedTestSignatureHmacSha256Input      = `sig1=("@authority" "date" "content-type");created=1618884475;keyid="test-shared-secret"`
	expectedTestSignatureHmacSha256           = `sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:`
	expectedTestSignatureEcdsaP256Sha256Input = `sig1=("content-type" "digest" "content-length");created=1618884475;keyid="test-key-ecc-p256"`
	expectedTestSignatureEcdsaP256Sha256      = `sig1=:n8RKXkj0iseWDmC6PNSQ1GX2R9650v+lhbb6rTGoSrSSx18zmn6fPOtBx48/WffYLO0n1RHHf9scvNGAgGq52Q==:`
	expectedTestSignatureEd25519Input         = `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	expectedTestSignatureEd25519              = `sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`
)

func TestRsaPssSig(t *testing.T) {
	t.Skip()
	alg, err := NewAsymmetricSigningAlgorithm(AlgorithmRsaPssSha512, testKeyRsaPssPrivate, testKeyRsaPssName)
	require.NoError(t, err)
	signer, err := NewSigner(alg, withTime(timeFromUnix(1618884475)), WithNonce(false), WithNoCoveredComponents())
	req := &http.Request{}
	*req = *testRequest

	err = signer.Sign(req)
	require.NoError(t, err)

	sigInput := req.Header.Get("signature-input")
	sig := req.Header.Get("signature")

	require.Equal(t, expectedMinimalSignatureRsaPssInput, sigInput)
	require.Equal(t, expectedMinimalSignatureRsaPss, sig)
}

func TestHmacSha256Sig(t *testing.T) {
	alg, err := NewHmacSha256SigningAlgorithm(testKeySharedSecret, testKeySharedSecretName)
	require.NoError(t, err)
	signer, err := NewSigner(alg, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("@authority", "date", "content-type"), WithAlg(false))
	req := http.Request{}
	req = *testRequest

	err = signer.Sign(&req)
	require.NoError(t, err)

	sigInput := req.Header.Get("signature-input")
	sig := req.Header.Get("signature")

	require.Equal(t, expectedTestSignatureHmacSha256Input, sigInput)
	require.Equal(t, expectedTestSignatureHmacSha256, sig)
}

func TestEcdsaP256Sha256SigSigning(t *testing.T) {
	alg, err := NewAsymmetricSigningAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Private, testKeyEccP256Name)
	require.NoError(t, err)
	signer, err := NewSigner(alg, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"), WithAlg(false))
	resp := *getResponse()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	err = signer.SignResponse(context.Background(), &resp)
	require.NoError(t, err)

	sigInput := resp.Header.Get("Signature-Input")
	sig := resp.Header.Get("Signature")

	require.Equal(t, expectedTestSignatureEcdsaP256Sha256Input, sigInput)
	require.NotEmpty(t, sig)
	require.Equal(t, 1, len(resp.Header["Signature"]))

	vAlg, err := NewAsymmetricVerifyingAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Public, testKeyEccP256Name)
	require.NoError(t, err)
	keyFinder := func(ctx context.Context, keyId string, _ http.Header) (VerifyingAlgorithm, bool) {
		if keyId == testKeyEccP256Name {
			return vAlg, true
		}
		return nil, false
	}

	verifier, err := NewVerifier(keyFinder, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"))
	require.NoError(t, err)

	err = verifier.VerifyResponse(context.Background(), &resp, body)
	require.NoError(t, err)
}

func TestEcdsaP256Sha256SigSpecCase(t *testing.T) {
	resp := *getResponse()
	resp.Header["Signature-Input"] = []string{expectedTestSignatureEcdsaP256Sha256Input}
	resp.Header["Signature"] = []string{expectedTestSignatureEcdsaP256Sha256}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	vAlg, err := NewAsymmetricVerifyingAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Public, testKeyEccP256Name)
	require.NoError(t, err)
	keyFinder := func(ctx context.Context, keyId string, _ http.Header) (VerifyingAlgorithm, bool) {
		if keyId == testKeyEccP256Name {
			return vAlg, true
		}
		return nil, false
	}

	verifier, err := NewVerifier(keyFinder, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"))
	require.NoError(t, err)

	err = verifier.VerifyResponse(context.Background(), &resp, body)
	require.NoError(t, err)
}

func TestEd25519SigSigning(t *testing.T) {
	req := getRequest()
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)

	alg, err := NewAsymmetricSigningAlgorithm(AlgorithmEd25519, testKeyEd25519Private, testKeyEd25519Name)
	require.NoError(t, err)
	signer, err := NewSigner(alg,
		withTime(timeFromUnix(1618884473)),
		WithNonce(false),
		WithCoveredComponents("date", "@method", "@path", "@authority", "content-type", "content-length"),
		WithAlg(false),
		WithSigNamer(func() string { return "sig-b26" }),
	)

	err = signer.Sign(req)
	require.NoError(t, err)

	sigInput := req.Header.Get("Signature-Input")
	sig := req.Header.Get("Signature")

	require.Equal(t, expectedTestSignatureEd25519Input, sigInput)
	require.NotEmpty(t, sig)
	require.Equal(t, 1, len(req.Header["Signature"]))

	vAlg, err := NewAsymmetricVerifyingAlgorithm(AlgorithmEd25519, testKeyEd25519Public, testKeyEd25519Name)
	require.NoError(t, err)
	keyFinder := func(ctx context.Context, keyId string, _ http.Header) (VerifyingAlgorithm, bool) {
		if keyId == testKeyEd25519Name {
			return vAlg, true
		}
		return nil, false
	}

	verifier, err := NewVerifier(keyFinder,
		withTime(timeFromUnix(1618884473)),
		WithNonce(false),
		WithCoveredComponents("date", "@method", "@path", "@authority", "content-type", "content-length"),
	)
	require.NoError(t, err)

	err = verifier.Verify(req, body)
	require.NoError(t, err)
}

func TestEd25519SigSpecCase(t *testing.T) {
	req := getRequest()
	req.Header["Signature-Input"] = []string{expectedTestSignatureEd25519Input}
	req.Header["Signature"] = []string{expectedTestSignatureEd25519}
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)

	vAlg, err := NewAsymmetricVerifyingAlgorithm(AlgorithmEd25519, testKeyEd25519Public, testKeyEd25519Name)
	require.NoError(t, err)
	keyFinder := func(ctx context.Context, keyId string, _ http.Header) (VerifyingAlgorithm, bool) {
		if keyId == testKeyEd25519Name {
			return vAlg, true
		}
		return nil, false
	}

	verifier, err := NewVerifier(keyFinder, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"))
	require.NoError(t, err)

	err = verifier.Verify(req, body)
	require.NoError(t, err)
}

func BenchmarkHmacSha256Sign(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		alg, err := NewHmacSha256SigningAlgorithm([]byte(testKeySharedSecret), testKeySharedSecretName)
		if err != nil {
			b.FailNow()
		}
		signer, err := NewSigner(alg, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("@authority", "date", "content-type"), WithAlg(false))
		if err != nil {
			b.FailNow()
		}
		testRequest := getRequest()
		req := http.Request{}

		b.ReportAllocs()
		b.ResetTimer()

		for pb.Next() {
			req = *testRequest

			err = signer.Sign(&req)
			if err != nil {
				b.FailNow()
			}

			sigInput := req.Header.Get("signature-input")
			sig := req.Header.Get("signature")

			if expectedTestSignatureHmacSha256Input != sigInput {
				b.FailNow()
			}
			if expectedTestSignatureHmacSha256 != sig {
				b.FailNow()
			}
		}
	})
}

func BenchmarkEcdsaP256Sha256Sign(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		alg, err := NewAsymmetricSigningAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Private, testKeyEccP256Name)
		if err != nil {
			b.FailNow()
		}
		signer, err := NewSigner(alg, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"), WithAlg(false))
		if err != nil {
			b.FailNow()
		}
		testResponse := getResponse()

		ctx := context.Background()
		resp := http.Response{}

		b.ReportAllocs()
		b.ResetTimer()

		for pb.Next() {
			resp = *testResponse

			err = signer.SignResponse(ctx, &resp)
			if err != nil {
				b.FailNow()
			}

			sigInput := resp.Header.Get(SignatureInputHeaderName)
			sig := resp.Header.Get(SignatureHeaderName)

			if expectedTestSignatureEcdsaP256Sha256Input != sigInput {
				b.FailNow()
			}
			if sig == "" {
				b.FailNow()
			}
		}
	})
}

func BenchmarkEcdsaP256Sha256Verify(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		alg, err := NewAsymmetricSigningAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Private, testKeyEccP256Name)
		if err != nil {
			b.FailNow()
		}
		signer, err := NewSigner(alg, WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"), WithAlg(false))
		if err != nil {
			b.FailNow()
		}
		testResponse := getResponse()
		testResponseBody, err := io.ReadAll(testResponse.Body)
		require.NoError(b, err)

		ctx := context.Background()
		err = signer.SignResponse(ctx, testResponse)
		if err != nil {
			b.FailNow()
		}

		resp := http.Response{}

		vAlg, err := NewAsymmetricVerifyingAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Public, testKeyEccP256Name)
		require.NoError(b, err)
		keyFinder := func(ctx context.Context, keyId string, _ http.Header) (VerifyingAlgorithm, bool) {
			if keyId == testKeyEccP256Name {
				return vAlg, true
			}
			return nil, false
		}

		verifier, err := NewVerifier(keyFinder, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"))
		require.NoError(b, err)

		b.ReportAllocs()
		b.ResetTimer()

		for pb.Next() {
			resp = *testResponse

			err = verifier.VerifyResponse(context.Background(), &resp, testResponseBody)
			if err != nil {
				b.FailNow()
			}
		}
	})
}

func BenchmarkEcdsaP256Sha256VerifyLargeBody(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		alg, err := NewAsymmetricSigningAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Private, testKeyEccP256Name)
		if err != nil {
			b.FailNow()
		}
		signer, err := NewSigner(alg, WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"), WithAlg(false))
		if err != nil {
			b.FailNow()
		}
		testResponse := getResponse()

		// 128 MB body
		testResponseBody := make([]byte, 128*1024*1024)
		_, err = rand.Read(testResponseBody)
		require.NoError(b, err)

		digest := sha256.New()
		digest.Write(testResponseBody)
		digestHeaderVal := "sha-256=" + base64.StdEncoding.EncodeToString(digest.Sum(nil))
		testResponse.Header["Digest"] = []string{digestHeaderVal}

		ctx := context.Background()
		err = signer.SignResponse(ctx, testResponse)
		if err != nil {
			require.NoError(b, err)
			b.FailNow()
		}

		resp := http.Response{}

		vAlg, err := NewAsymmetricVerifyingAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Public, testKeyEccP256Name)
		require.NoError(b, err)
		keyFinder := func(ctx context.Context, keyId string, _ http.Header) (VerifyingAlgorithm, bool) {
			if keyId == testKeyEccP256Name {
				return vAlg, true
			}
			return nil, false
		}

		verifier, err := NewVerifier(keyFinder, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"))
		require.NoError(b, err)

		b.ReportAllocs()
		b.ResetTimer()

		for pb.Next() {
			resp = *testResponse

			err = verifier.VerifyResponse(context.Background(), &resp, testResponseBody)
			if err != nil {
				require.NoError(b, err)
				b.FailNow()
			}
		}
	})
}

func BenchmarkEd25519Verify(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		alg, err := NewAsymmetricSigningAlgorithm(AlgorithmEd25519, testKeyEd25519Private, testKeyEd25519Name)
		if err != nil {
			b.FailNow()
		}
		signer, err := NewSigner(alg, WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"), WithAlg(false))
		if err != nil {
			b.FailNow()
		}
		testResponse := getResponse()
		testResponseBody, err := io.ReadAll(testResponse.Body)
		require.NoError(b, err)

		ctx := context.Background()
		err = signer.SignResponse(ctx, testResponse)
		if err != nil {
			b.FailNow()
		}

		resp := http.Response{}

		vAlg, err := NewAsymmetricVerifyingAlgorithm(AlgorithmEd25519, testKeyEd25519Public, testKeyEd25519Name)
		require.NoError(b, err)
		keyFinder := func(ctx context.Context, keyId string, _ http.Header) (VerifyingAlgorithm, bool) {
			if keyId == testKeyEd25519Name {
				return vAlg, true
			}
			return nil, false
		}

		verifier, err := NewVerifier(keyFinder, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"))
		require.NoError(b, err)

		b.ReportAllocs()
		b.ResetTimer()

		for pb.Next() {
			resp = *testResponse

			err = verifier.VerifyResponse(context.Background(), &resp, testResponseBody)
			if err != nil {
				b.FailNow()
			}
		}
	})
}
