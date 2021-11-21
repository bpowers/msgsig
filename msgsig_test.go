// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"bufio"
	_ "embed"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func must[T any](result T, err error) T {
	if err != nil {
		panic(err)
	}
	return result
}

var (
	//go:embed testmessages/request.http
	testRequestBytes string
	//go:embed testmessages/response.http
	testResponseBytes string

	testRequest  = must(http.ReadRequest(bufio.NewReader(strings.NewReader(testRequestBytes))))
	testResponse = must(http.ReadResponse(bufio.NewReader(strings.NewReader(testResponseBytes)), testRequest))
)

func timeFromUnix(unixSecs int64) func() time.Time {
	return func() time.Time {
		return time.Unix(unixSecs, 0)
	}
}

const (
	expectedMinimalSignatureRsaPssInput        = `sig1=();created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"`
	expectedMinimalSignatureRsaPss             = `sig1=:HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmEAAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgxTpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwNcZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkwIyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW+5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==:`
	expectedTestSignatureHmacSha256Input       = `sig1=("@authority" "date" "content-type");created=1618884475;keyid="test-shared-secret"`
	expectedTestSignatureHmacSha256            = `sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:`
	expectestTestSignatureEcdsaP256Sha256Input = `sig1=("content-type" "digest" "content-length");created=1618884475;keyid="test-key-ecc-p256"`
	expectestTestSignatureEcdsaP256Sha256      = `sig1=:n8RKXkj0iseWDmC6PNSQ1GX2R9650v+lhbb6rTGoSrSSx18zmn6fPOtBx48/WffYLO0n1RHHf9scvNGAgGq52Q==:`
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
	alg, err := NewHmacSha256SigningAlgorithm([]byte(testKeySharedSecret), testKeySharedSecretName)
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

func TestEcdsaP256Sha256Sig(t *testing.T) {
	alg, err := NewAsymmetricSigningAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Private, testKeyEccP256Name)
	require.NoError(t, err)
	signer, err := NewSigner(alg, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("content-type", "digest", "content-length"), WithAlg(false))
	resp := http.Response{}
	resp = *testResponse

	err = signer.SignResponse(&resp)
	require.NoError(t, err)

	sigInput := resp.Header.Get("signature-input")
	sig := resp.Header.Get("signature")

	require.Equal(t, expectestTestSignatureEcdsaP256Sha256Input, sigInput)
	require.NotEmpty(t, sig)
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
		testRequest := must(http.ReadRequest(bufio.NewReader(strings.NewReader(testRequestBytes))))
		req := http.Request{}
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
		testResponse := must(http.ReadResponse(bufio.NewReader(strings.NewReader(testResponseBytes)), testRequest))

		resp := http.Response{}

		for pb.Next() {
			resp = *testResponse

			err = signer.SignResponse(&resp)
			if err != nil {
				b.FailNow()
			}

			sigInput := resp.Header.Get("signature-input")
			sig := resp.Header.Get("signature")

			if expectestTestSignatureEcdsaP256Sha256Input != sigInput {
				b.FailNow()
			}
			if sig == "" {
				b.FailNow()
			}
		}
	})
}
