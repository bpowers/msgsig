// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package msgsig

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/bpowers/msgsig/component"
)

func now() time.Time {
	return time.Now()
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
	sigNamer           func(r reqResp) []byte
}

func appendValueStringQuoted(buf *bytes.Buffer, v string) {
	buf.WriteByte('"')
	buf.WriteString(v)
	buf.WriteByte('"')
}

func appendKeyValueString(buf *bytes.Buffer, k, v string) {
	buf.WriteByte(';')
	buf.WriteString(k)
	buf.WriteByte('=')
	appendValueStringQuoted(buf, v)
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
			appendValueStringQuoted(sigInputHeader, c)
			appendValueStringQuoted(sigInput, c)
			sigInput.WriteString(`: `)
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

	appendKeyValueString(sigInputHeader, "keyid", s.keyId)

	if s.hasAlg {
		appendKeyValueString(sigInputHeader, "alg", string(s.algName))
	}

	sigInput.WriteString(`"@signature-params": `)
	sigInput.Write(sigInputHeader.Bytes())

	return nil
}

type httpRequest http.Request
type httpResponse http.Response

func (r *httpRequest) Headers() http.Header {
	return r.Header
}

func (r *httpRequest) Authority() string {
	return r.Host
}

func (r *httpRequest) GetURL() *url.URL {
	return r.URL
}

func (r *httpRequest) GetMethod() string {
	return r.Method
}

func (r *httpResponse) Headers() http.Header {
	return r.Header
}

func (r *httpResponse) GetURL() *url.URL {
	return nil
}

func (r *httpResponse) Authority() string {
	// TODO
	return ""
}

func (r *httpResponse) GetMethod() string {
	// TODO
	return ""
}

// reqResp is an internal abstraction for the common pieces we
// need from an HTTP message
type reqResp interface {
	Authority() string
	Headers() http.Header
	GetURL() *url.URL
	GetMethod() string
}

func getComponent(r reqResp, c string) string {
	switch c {
	case component.Authority:
		return r.Authority()
	case component.Path:
		if url := r.GetURL(); url != nil {
			return url.Path
		}
	case component.Method:
		return r.GetMethod()
	default:
		return r.Headers().Get(c)
	}
	return ""
}

func contains(slice []string, s string) bool {
	for _, ss := range slice {
		if ss == s {
			return true
		}
	}
	return false
}
