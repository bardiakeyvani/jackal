/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package router

import (
	"sync"

	"github.com/ortuman/jackal/errors"
	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/xml"
)

type s2sRouter struct {
	mu         sync.RWMutex
	inStreams  map[string]stream.S2SIn
	outStreams map[string]stream.S2SOut
}

func newS2SRouter() *s2sRouter {
	return &s2sRouter{
		inStreams:  make(map[string]stream.S2SIn),
		outStreams: make(map[string]stream.S2SOut),
	}
}

func (r *s2sRouter) registerOut(stm stream.S2SOut) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outStreams[stm.LocalDomain()+":"+stm.RemoteDomain()] = stm
	return nil
}

func (r *s2sRouter) registerIn(stm stream.S2SIn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inStreams[stm.ID()] = stm
	return nil
}

func (r *s2sRouter) unregisterIn(stm stream.S2SIn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inStreams, stm.ID())
	return nil
}

func (r *s2sRouter) unregisterOut(stm stream.S2SOut) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.outStreams, stm.LocalDomain()+":"+stm.RemoteDomain())
	return nil
}

func (r *s2sRouter) route(elem xml.Stanza, ignoreBlocking bool) error {
	return nil
}

func (r *s2sRouter) shutdown() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, stm := range r.outStreams {
		stm.Disconnect(streamerror.ErrSystemShutdown)
	}
	for _, stm := range r.inStreams {
		stm.Disconnect(streamerror.ErrSystemShutdown)
	}
}
