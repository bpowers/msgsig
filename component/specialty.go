// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

// Package component contains constants defined in section 2.3: Specialty Components.
package component

const (
	// SignatureParams is REQUIRED as part of the signature base (Section 2.3)
	// but the component identifier MUST NOT be enumerated within the set of
	// covered components itself.
	SignatureParams = "@signature-params"
	Method          = "@method"
	TargetUri       = "@target-uri"
	Authority       = "@authority"
	Scheme          = "@scheme"
	RequestTarget   = "@request-target"
	Path            = "@path"
	Query           = "@query"
	QueryParams     = "@query-params"
	Status          = "@status"
	RequestResponse = "@request-response"
)
