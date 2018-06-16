/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package router

import (
	"fmt"
	"sync"

	"github.com/ortuman/jackal/errors"
	"github.com/ortuman/jackal/log"
	"github.com/ortuman/jackal/storage"
	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/xml"
)

type c2sRouter struct {
	mu            sync.RWMutex
	streams       map[string]stream.C2S
	bindedStreams map[string][]stream.C2S
}

func newC2SRouter() *c2sRouter {
	return &c2sRouter{
		streams:       make(map[string]stream.C2S),
		bindedStreams: make(map[string][]stream.C2S),
	}
}

func (r *c2sRouter) registerStream(stm stream.C2S) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.streams[stm.ID()]
	if ok {
		return fmt.Errorf("c2s stream already registered: %s", stm.ID())
	}
	r.streams[stm.ID()] = stm
	log.Infof("registered c2s stream... (id: %s)", stm.ID())
	return nil
}

func (r *c2sRouter) unregisterStream(stm stream.C2S) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.streams[stm.ID()]
	if !ok {
		return fmt.Errorf("c2s stream not found: %s", stm.ID())
	}
	if resources := r.bindedStreams[stm.Username()]; resources != nil {
		res := stm.Resource()
		for i := 0; i < len(resources); i++ {
			if res == resources[i].Resource() {
				resources = append(resources[:i], resources[i+1:]...)
				break
			}
		}
		if len(resources) > 0 {
			r.bindedStreams[stm.Username()] = resources
		} else {
			delete(r.bindedStreams, stm.Username())
		}
	}
	delete(r.streams, stm.ID())
	log.Infof("unregistered c2s stream... (id: %s)", stm.ID())
	return nil
}

func (r *c2sRouter) bindStream(stm stream.C2S) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if authenticated := r.bindedStreams[stm.Username()]; authenticated != nil {
		r.bindedStreams[stm.Username()] = append(authenticated, stm)
	} else {
		r.bindedStreams[stm.Username()] = []stream.C2S{stm}
	}
	log.Infof("binded c2s stream... (%s/%s)", stm.Username(), stm.Resource())
	return nil
}

func (r *c2sRouter) route(elem xml.Stanza, ignoreBlocking bool) error {
	toJID := elem.ToJID()
	rcps := r.streamsMatchingJID(toJID.ToBareJID())
	if len(rcps) == 0 {
		exists, err := storage.Instance().UserExists(toJID.Node())
		if err != nil {
			return err
		}
		if exists {
			return ErrNotAuthenticated
		}
		return ErrNotExistingAccount
	}
	if toJID.IsFullWithUser() {
		for _, stm := range rcps {
			if stm.Resource() == toJID.Resource() {
				stm.SendElement(elem)
				return nil
			}
		}
		return ErrResourceNotFound
	}
	switch elem.(type) {
	case *xml.Message:
		// send toJID highest priority stream
		stm := rcps[0]
		var highestPriority int8
		if p := stm.Presence(); p != nil {
			highestPriority = p.Priority()
		}
		for i := 1; i < len(rcps); i++ {
			rcp := rcps[i]
			if p := rcp.Presence(); p != nil && p.Priority() > highestPriority {
				stm = rcp
				highestPriority = p.Priority()
			}
		}
		stm.SendElement(elem)

	default:
		// broadcast toJID all streams
		for _, stm := range rcps {
			stm.SendElement(elem)
		}
	}
	return nil
}

func (r *c2sRouter) streamsMatchingJID(jid *xml.JID) []stream.C2S {
	var ret []stream.C2S
	opts := xml.JIDMatchesDomain
	if jid.IsFull() {
		opts |= xml.JIDMatchesResource
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(jid.Node()) > 0 {
		opts |= xml.JIDMatchesNode
		stms := r.bindedStreams[jid.Node()]
		for _, stm := range stms {
			if stm.JID().Matches(jid, opts) {
				ret = append(ret, stm)
			}
		}
	} else {
		for _, stms := range r.bindedStreams {
			for _, stm := range stms {
				if stm.JID().Matches(jid, opts) {
					ret = append(ret, stm)
				}
			}
		}
	}
	return ret
}

func (r *c2sRouter) shutdown() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, stm := range r.streams {
		stm.Disconnect(streamerror.ErrSystemShutdown)
	}
}
