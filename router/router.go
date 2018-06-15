/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package router

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ortuman/jackal/log"
	"github.com/ortuman/jackal/storage"
	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/xml"
)

var (
	// ErrNotExistingAccount will be returned by Route method
	// if destination user does not exist.
	ErrNotExistingAccount = errors.New("router: account does not exist")

	// ErrResourceNotFound will be returned by Route method
	// if destination resource does not match any of user's available resources.
	ErrResourceNotFound = errors.New("router: resource not found")

	// ErrNotAuthenticated will be returned by Route method if
	// destination user is not available at this moment.
	ErrNotAuthenticated = errors.New("router: user not authenticated")

	// ErrBlockedJID will be returned by Route method if
	// destination JID matches any of the user's blocked JID.
	ErrBlockedJID = errors.New("router: destination jid is blocked")
)

// Router manages the sessions associated with an account.
type Router struct {
	mu           sync.RWMutex
	domains      map[string]struct{}
	blockListsMu sync.RWMutex
	blockLists   map[string][]*xml.JID
	c2sRouter    *c2sRouter
}

// singleton interface
var (
	instMu      sync.RWMutex
	inst        *Router
	initialized bool
)

// Initialize initializes the router manager.
func Initialize() {
	instMu.Lock()
	defer instMu.Unlock()
	if initialized {
		return
	}
	inst = &Router{
		domains:    make(map[string]struct{}),
		blockLists: make(map[string][]*xml.JID),
		c2sRouter:  newC2SRouter(),
	}
	initialized = true
}

// Shutdown shuts down router manager system.
// This method should be used only for testing purposes.
func Shutdown() {
	instMu.Lock()
	defer instMu.Unlock()
	if !initialized {
		return
	}
	inst.shutdown()
	inst = nil
	initialized = false
}

// Instance returns the router manager instance.
func Instance() *Router {
	instMu.RLock()
	defer instMu.RUnlock()
	if inst == nil {
		log.Fatalf("router manager not initialized")
	}
	return inst
}

// RegisterDomain registers a new local domain.
func (r *Router) RegisterDomain(domain string) {
	r.mu.Lock()
	r.domains[domain] = struct{}{}
	r.mu.Unlock()
}

// IsLocalDomain returns true if domain is a local server domain.
func (r *Router) IsLocalDomain(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.domains[domain]
	return ok
}

// RegisterC2S registers the specified c2s stream.
// An error will be returned in case the stream has been previously registered.
func (r *Router) RegisterC2S(stm stream.C2S) error {
	if !r.IsLocalDomain(stm.Domain()) {
		return fmt.Errorf("invalid domain: %s", stm.Domain())
	}
	return r.c2sRouter.registerStream(stm)
}

// UnregisterC2S unregisters the specified c2s stream removing
// associated resource from the manager.
// An error will be returned in case the stream has not been previously registered.
func (r *Router) UnregisterC2S(stm stream.C2S) error {
	return r.c2sRouter.unregisterStream(stm)
}

// BindC2S marks a previously registered c2s stream as authenticated.
// An error will be returned in case no assigned resource is found.
func (r *Router) BindC2S(stm stream.C2S) error {
	if len(stm.Resource()) == 0 {
		return fmt.Errorf("resource not yet assigned: %s", stm.ID())
	}
	return r.c2sRouter.bindStream(stm)
}

func (r *Router) RegisterS2S(stm stream.S2S) error {
	return nil
}

func (r *Router) UnregisterS2S(stm stream.S2S) error {
	return nil
}

// IsBlockedJID returns whether or not the passed jid matches any
// of a user's blocking list JID.
func (r *Router) IsBlockedJID(jid *xml.JID, username string) bool {
	bl := r.getBlockList(username)
	for _, blkJID := range bl {
		if r.jidMatchesBlockedJID(jid, blkJID) {
			return true
		}
	}
	return false
}

// ReloadBlockList reloads in memory block list for a given user and starts
// applying it for future stanza routing.
func (r *Router) ReloadBlockList(username string) {
	r.blockListsMu.Lock()
	defer r.blockListsMu.Unlock()

	delete(r.blockLists, username)
	log.Infof("block list reloaded... (username: %s)", username)
}

// Route routes a stanza applying server rules for handling XML stanzas.
// (https://xmpp.org/rfcs/rfc3921.html#rules)
func (r *Router) Route(elem xml.Stanza) error {
	return r.route(elem, false)
}

// MustRoute routes a stanza applying server rules for handling XML stanzas
// ignoring blocking lists.
func (r *Router) MustRoute(elem xml.Stanza) error {
	return r.route(elem, true)
}

// StreamsMatchingJID returns all available c2s streams matching a given JID.
func (r *Router) StreamsMatchingJID(jid *xml.JID) []stream.C2S {
	if !r.IsLocalDomain(jid.Domain()) {
		return nil
	}
	return r.c2sRouter.streamsMatchingJID(jid)
}

func (r *Router) route(elem xml.Stanza, ignoreBlocking bool) error {
	toJID := elem.ToJID()
	if !ignoreBlocking && !toJID.IsServer() {
		if r.IsBlockedJID(elem.FromJID(), toJID.Node()) {
			return ErrBlockedJID
		}
	}
	if !r.IsLocalDomain(toJID.Domain()) {
		return nil
	}
	return r.c2sRouter.route(elem, ignoreBlocking)
}

func (r *Router) getBlockList(username string) []*xml.JID {
	r.blockListsMu.RLock()
	bl := r.blockLists[username]
	r.blockListsMu.RUnlock()
	if bl != nil {
		return bl
	}
	blItms, err := storage.Instance().FetchBlockListItems(username)
	if err != nil {
		log.Error(err)
		return nil
	}
	bl = []*xml.JID{}
	for _, blItm := range blItms {
		j, _ := xml.NewJIDString(blItm.JID, true)
		bl = append(bl, j)
	}
	r.blockListsMu.Lock()
	r.blockLists[username] = bl
	r.blockListsMu.Unlock()
	return bl
}

func (r *Router) jidMatchesBlockedJID(jid, blockedJID *xml.JID) bool {
	if blockedJID.IsFullWithUser() {
		return jid.Matches(blockedJID, xml.JIDMatchesNode|xml.JIDMatchesDomain|xml.JIDMatchesResource)
	} else if blockedJID.IsFullWithServer() {
		return jid.Matches(blockedJID, xml.JIDMatchesDomain|xml.JIDMatchesResource)
	} else if blockedJID.IsBare() {
		return jid.Matches(blockedJID, xml.JIDMatchesNode|xml.JIDMatchesDomain)
	}
	return jid.Matches(blockedJID, xml.JIDMatchesDomain)
}

func (r *Router) shutdown() {
	r.c2sRouter.shutdown()
}
