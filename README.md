msgsig: HTTP Message Signatures
===============================

As specified by https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html

Signing messages consists of constructing a Signer and re-using it to sign multiple messages:

```go
	alg, _ := NewAsymmetricSigningAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Private, testKeyEccP256Name)
	signer, err := NewSigner(alg, WithCoveredComponents("content-type", "digest", "content-length"))

	_ = signer.SignResponse(context.Background(), resp)
```

Verifying messages is similar:

```go
	vAlg, _ := NewAsymmetricVerifyingAlgorithm(AlgorithmEcdsaP256Sha256, testKeyEccP256Public, testKeyEccP256Name)

	keyFinder := func(ctx context.Context, keyId string) (VerifyingAlgorithm, bool) {
		if keyId == testKeyEccP256Name {
			return vAlg, true
		}
		return nil, false
	}

	verifier, _ := NewVerifier(keyFinder, WithCoveredComponents("content-type", "digest", "content-length"))

	_ = verifier.VerifyResponse(context.Background(), resp)
```
Unlike signers, it is expected that Verifiers may see signatures for a range of keys, so instead of being parameterized with a single key they take a function to lookup keys by id. 

For the verifier, the `WithCoveredComponents` argument is the minimum set of HTTP headers that must be signed.
If the request/response's signature doesn't cover _at least_ those fields, verification will fail.

Signers and verifiers are _not_ safe for use by multiple Goroutines.  Keep a `sync.Pool` of them, or protect them with a lock.