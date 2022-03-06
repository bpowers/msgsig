msgsig: HTTP Message Signatures for Go
======================================

This package implements v09 of the [HTTP Message Signatures](https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html) draft specification.
It will be updated for future revisions of the spec.

Usage
-----

At a high level, this package provides `Signer` and `Verifier` interfaces.  Signers and verifiers are **_not_** safe for use by multiple Goroutines.  Keep a `sync.Pool` of them (recommended), or protect them with a lock.

Signing messages consists of constructing a Signer and re-using it to sign multiple messages:

```go
	alg, _ := NewAsymmetricSigningAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Private, testKeyEccP256Name)
	signer, err := NewSigner(alg, WithCoveredComponents("content-type", "digest", "content-length"))

	_ = signer.SignResponse(context.Background(), resp)
```

Verifying messages is similar in that you construct a verifier and re-use it to verify multiple messages:

```go
	vAlg, _ := NewAsymmetricVerifyingAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Public, testKeyEccP256Name)

	keyFinder := func(ctx context.Context, keyId string) (VerifyingAlgorithm, bool) {
		if keyId == testKeyEccP256Name {
			return vAlg, true
		}
		return nil, false
	}

	verifier, _ := NewVerifier(keyFinder, WithCoveredComponents("content-type", "digest", "content-length"))

	_ = verifier.VerifyResponse(context.Background(), resp, body)
```
Unlike signers, it is expected that Verifiers may see signatures for a range of keys, so instead of being parameterized with a single key they take a function to lookup keys by id. 

Verify functions take an explicit HTTP body because, in general, Go's `http.Response.Body` field doesn't buffer the body for multiple readers.
It seems least-surprising to have to have the caller read (and buffer) the whole HTTP body that having that happen silently within a call to this library.

For the verifier, the `WithCoveredComponents` argument is the minimum set of HTTP headers that must be signed.
If the request/response's signature doesn't cover _at least_ those fields, verification will fail.

## Performance

There is more to optimize, but performance is good (10s of signs and verifies per _millisecond_) and largely gated by the cost of ECDSA operations:

```go
goos: darwin
goarch: arm64
pkg: github.com/bpowers/msgsig
BenchmarkHmacSha256Sign                 	 7315312	     814.0 ns/op	     256 B/op	       7 allocs/op
BenchmarkEcdsaP256Sha256Sign            	  301438	     19701 ns/op	    2808 B/op	      38 allocs/op
BenchmarkEcdsaP256Sha256Verify          	  105506	     56467 ns/op	    1464 B/op	      27 allocs/op
BenchmarkEcdsaP256Sha256VerifyLargeBody 	     100	  55139152 ns/op	    1818 B/op	      27 allocs/op
BenchmarkEd25519Verify                  	  115123	     51935 ns/op	     312 B/op	       6 allocs/op
```

The large body tests verification of messages with a 128 MB POST body, where all the additional time is spent generating the SHA256 digest of the body (to compare against the `Digest` header).
On an M1 mac that test takes ~60 milliseconds, but we've observed it take 400 ms on an EC2 `m5d` instance.
