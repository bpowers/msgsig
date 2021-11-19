// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"bufio"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"testing"
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

func TestSig(t *testing.T) {
	_ = t

	fmt.Printf("request: %v", testRequest)
	fmt.Printf("response: %v", testResponse)
}
