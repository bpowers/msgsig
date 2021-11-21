// Copyright 2021 The msgsig Authors. All rights reserved.
// Use of this source code is governed by the Apache License,
// Version 2.0, that can be found in the LICENSE file.

package safepool

import (
	"bytes"
	"sync"
)

type Pool[T any] struct {
	p sync.Pool
}

func NewPool[T any](newFn func() T) *Pool[T] {
	return &Pool[T]{
		p: sync.Pool{
			New: func() interface{} {
				return newFn()
			},
		},
	}
}

func (p *Pool[T]) Get() T {
	return p.p.Get().(T)
}

func (p *Pool[T]) Put(item T) {
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
