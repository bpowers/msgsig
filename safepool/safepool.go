// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package safepool

import (
	"bytes"
	"sync"
)

func zeroByteSlice(s *[]byte) {
	// get a reference to the full backing array of the slice
	full := (*s)[:cap(*s)]
	for i := 0; i < len(full); i++ {
		full[i] = 0
	}
	*s = full[:0]
}

type ByteSlicePool struct {
	p sync.Pool
}

func NewByteSlicePool(newFn func() []byte) *ByteSlicePool {
	return &ByteSlicePool{
		p: sync.Pool{
			New: func() interface{} {
				s := newFn()
				return &s
			},
		},
	}
}

func (p *ByteSlicePool) Get() *[]byte {
	return p.p.Get().(*[]byte)
}

func (p *ByteSlicePool) Put(item *[]byte) {
	zeroByteSlice(item)
	p.p.Put(item)
}

func zeroStringSlice(s *[]string) {
	// get a reference to the full backing array of the slice
	full := (*s)[:cap(*s)]
	for i := 0; i < len(full); i++ {
		full[i] = ""
	}
}

type StringSlicePool struct {
	p sync.Pool
}

func NewStringSlicePool(newFn func() []string) *StringSlicePool {
	return &StringSlicePool{
		p: sync.Pool{
			New: func() interface{} {
				s := newFn()
				return &s
			},
		},
	}
}

func (p *StringSlicePool) Get() *[]string {
	return p.p.Get().(*[]string)
}

func (p *StringSlicePool) Put(item *[]string) {
	zeroStringSlice(item)
	p.p.Put(item)
}

type BufferPool struct {
	p sync.Pool
}

func NewBufferPool(newFn func() *bytes.Buffer) *BufferPool {
	return &BufferPool{
		p: sync.Pool{
			New: func() interface{} {
				return newFn()
			},
		},
	}
}

func (p *BufferPool) Get() *bytes.Buffer {
	return p.p.Get().(*bytes.Buffer)
}

func (p *BufferPool) Put(item *bytes.Buffer) {
	item.Reset()
	p.p.Put(item)
}
