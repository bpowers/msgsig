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
	expectedMinimalSignatureRsaPssInput  = `sig1=();created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"`
	expectedMinimalSignatureRsaPss       = `sig1=:HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmEAAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgxTpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwNcZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkwIyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW+5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==:`
	expectedTestSignatureHmacSha256Input = `sig1=("@authority" "date" "content-type");created=1618884475;keyid="test-shared-secret"`
	expectedTestSignatureHmacSha256      = `sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:`
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

func BenchmarkHmacSha256Sign(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		alg, err := NewHmacSha256SigningAlgorithm([]byte(testKeySharedSecret), testKeySharedSecretName)
		require.NoError(b, err)
		signer, err := NewSigner(alg, withTime(timeFromUnix(1618884475)), WithNonce(false), WithCoveredComponents("@authority", "date", "content-type"), WithAlg(false))
		require.NoError(b, err)
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
