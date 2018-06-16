/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"sync/atomic"

	"github.com/ortuman/jackal/errors"
	"github.com/ortuman/jackal/log"
	"github.com/ortuman/jackal/router"
	"github.com/ortuman/jackal/session"
	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/xml"
)

const (
	inConnecting uint32 = iota
	inConnected
	inDisconnected
)

type inStream struct {
	id            string
	cfg           *inConfig
	state         uint32
	sess          *session.Session
	secured       bool
	authenticated bool
	actorCh       chan func()
}

func newInStream(id string, cfg *inConfig) stream.S2SIn {
	s := &inStream{
		id:      id,
		cfg:     cfg,
		actorCh: make(chan func(), streamMailboxSize),
	}
	// start s2s in session
	s.restartSession()

	go s.loop()
	go s.doRead() // start reading transport...
	return s
}

func (s *inStream) ID() string {
	return s.id
}

func (s *inStream) SendElement(elem xml.XElement) {
	s.actorCh <- func() { s.writeElement(elem) }
}

func (s *inStream) Disconnect(err error) {
	waitCh := make(chan struct{})
	s.actorCh <- func() {
		s.disconnect(err)
		close(waitCh)
	}
	<-waitCh
}

// runs on its own goroutine
func (s *inStream) loop() {
	for {
		f := <-s.actorCh
		f()
		if s.getState() == inDisconnected {
			return
		}
	}
}

// runs on its own goroutine
func (s *inStream) doRead() {
	if elem, sErr := s.sess.Receive(); sErr == nil {
		s.actorCh <- func() {
			s.readElement(elem)
		}
	} else {
		if s.getState() == inDisconnected {
			return // already disconnected...
		}
		s.handleSessionError(sErr)
	}
}

func (s *inStream) handleElement(elem xml.XElement) {
	switch s.getState() {
	}
}

func (s *inStream) writeElement(elem xml.XElement) {
	s.sess.Send(elem)
}

func (s *inStream) readElement(elem xml.XElement) {
	if elem != nil {
		s.handleElement(elem)
	}
	if s.getState() != inDisconnected {
		go s.doRead()
	}
}

func (s *inStream) handleSessionError(sErr *session.Error) {
	switch err := sErr.UnderlyingErr.(type) {
	case nil:
		s.disconnect(nil)
	case *streamerror.Error:
		s.disconnectWithStreamError(err)
	case *xml.StanzaError:
		s.writeElement(xml.NewErrorElementFromElement(sErr.Element, err, nil))
	default:
		log.Error(err)
		s.disconnectWithStreamError(streamerror.ErrUndefinedCondition)
	}
}

func (s *inStream) disconnect(err error) {
	if s.getState() == inDisconnected {
		return
	}
	switch err {
	case nil:
		s.disconnectClosingSession(false, true)
	default:
		if stmErr, ok := err.(*streamerror.Error); ok {
			s.disconnectWithStreamError(stmErr)
		} else {
			log.Error(err)
			s.disconnectClosingSession(false, true)
		}
	}
}

func (s *inStream) disconnectWithStreamError(err *streamerror.Error) {
	if s.getState() == inConnecting {
		s.sess.Open()
	}
	s.writeElement(err.Element())

	unregister := err != streamerror.ErrSystemShutdown
	s.disconnectClosingSession(true, unregister)
}

func (s *inStream) disconnectClosingSession(closeSession bool, unregister bool) {
	if closeSession {
		s.sess.Close()
	}
	if unregister {
		if err := router.Instance().UnregisterS2SIn(s); err != nil {
			log.Error(err)
		}
	}
	s.setState(inDisconnected)
	s.cfg.transport.Close()
}

func (s *inStream) restartSession() {
	j, _ := xml.NewJID("", s.cfg.localDomain, "", true)
	s.sess = session.New(&session.Config{
		JID:           j,
		Transport:     s.cfg.transport,
		MaxStanzaSize: s.cfg.maxStanzaSize,
		RemoteDomain:  s.cfg.remoteDomain,
		IsServer:      true,
	})
	s.setState(inConnecting)
}

func (s *inStream) setState(state uint32) {
	atomic.StoreUint32(&s.state, state)
}

func (s *inStream) getState() uint32 {
	return atomic.LoadUint32(&s.state)
}
