/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"sync/atomic"

	"github.com/ortuman/jackal/errors"
	"github.com/ortuman/jackal/log"
	"github.com/ortuman/jackal/session"
	"github.com/ortuman/jackal/xml"
)

const streamMailboxSize = 64

const (
	tlsNamespace      = "urn:ietf:params:xml:ns:xmpp-tls"
	saslNamespace     = "urn:ietf:params:xml:ns:xmpp-sasl"
	dialbackNamespace = "urn:xmpp:features:dialback"
)

const (
	connecting uint32 = iota
	connected
	securing
	authenticating
	started
	disconnected
)

type out struct {
	id            string
	cfg           *outConfig
	state         uint32
	sess          *session.Session
	secured       bool
	authenticated bool
	actorCh       chan func()
}

func newOut(id string, cfg *outConfig) *out {
	s := &out{
		id:      id,
		cfg:     cfg,
		actorCh: make(chan func(), streamMailboxSize),
	}
	// start s2s out session
	s.restartSession()

	go s.loop()
	go s.doRead() // start reading transport...

	return s
}

func (s *out) DomainPair() (local string, remote string) {
	local = s.cfg.localDomain
	remote = s.cfg.remoteDomain
	return
}

func (s *out) SendElement(elem xml.XElement) {
	s.actorCh <- func() { s.writeElement(elem) }
}

func (s *out) Disconnect(err error) {
	waitCh := make(chan struct{})
	s.actorCh <- func() {
		s.disconnect(err)
		close(waitCh)
	}
	<-waitCh
}

func (s *out) Start() {
	s.actorCh <- func() {
		s.sess.Open(false, s.cfg.remoteDomain)
	}
}

// runs on its own goroutine
func (s *out) loop() {
	for {
		f := <-s.actorCh
		f()
		if s.getState() == disconnected {
			return
		}
	}
}

// runs on its own goroutine
func (s *out) handleElement(elem xml.XElement) {
	switch s.getState() {
	case connecting:
		s.handleConnecting(elem)
	case connected:
		s.handleConnected(elem)
	case securing:
		s.handleSecuring(elem)
	case authenticating:
		s.handleAuthenticating(elem)
	case started:
		s.handleStarted(elem)
	}
}

func (s *out) handleConnecting(elem xml.XElement) {
	s.setState(connected)
}

func (s *out) handleConnected(elem xml.XElement) {
	if elem.Name() != "stream:features" {
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
		return
	}
	if !s.secured {
		if !s.hasStartTLSFeature(elem) {
			// unsecured channels not supported
			s.disconnectWithStreamError(streamerror.ErrPolicyViolation)
			return
		}
		s.writeElement(xml.NewElementNamespace("starttls", tlsNamespace))
		s.setState(securing)

	} else if s.hasExternalAuthFeature(elem) && !s.authenticated {
		auth := xml.NewElementNamespace("auth", saslNamespace)
		auth.SetAttribute("mechanism", "EXTERNAL")
		auth.SetText("=")
		s.writeElement(auth)
		s.setState(authenticating)

	} else if s.hasDialbackFeature(elem) {

	}
}

func (s *out) handleSecuring(elem xml.XElement) {
	if elem.Name() != "proceed" {
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
		return
	} else if elem.Namespace() != tlsNamespace {
		s.disconnectWithStreamError(streamerror.ErrInvalidNamespace)
		return
	}
	s.cfg.transport.StartTLS(s.cfg.tls, true)

	s.restartSession()
	s.sess.Open(false, s.cfg.remoteDomain)

	s.secured = true
}

func (s *out) handleAuthenticating(elem xml.XElement) {
	if elem.Namespace() != saslNamespace {
		s.disconnectWithStreamError(streamerror.ErrInvalidNamespace)
		return
	}
	switch elem.Name() {
	case "success":
		s.restartSession()
		s.sess.Open(false, s.cfg.remoteDomain)
		s.authenticated = true

	case "failure":
		s.disconnectWithStreamError(streamerror.ErrRemoteConnectionFailed)

	default:
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
	}
}

func (s *out) handleStarted(elem xml.XElement) {
}

func (s *out) disconnect(err error) {
	if s.getState() == disconnected {
		return
	}
	switch err {
	case nil:
		s.disconnectClosingStream(false)
	default:
		if stmErr, ok := err.(*streamerror.Error); ok {
			s.disconnectWithStreamError(stmErr)
		} else {
			log.Error(err)
			s.disconnectClosingStream(false)
		}
	}
}

func (s *out) writeElement(elem xml.XElement) {
	s.sess.Send(elem)
}

func (s *out) readElement(elem xml.XElement) {
	if elem != nil {
		s.handleElement(elem)
	}
	if s.getState() != disconnected {
		go s.doRead()
	}
}

func (s *out) disconnectWithStreamError(err *streamerror.Error) {
	s.writeElement(err.Element())
	s.disconnectClosingStream(true)
}

func (s *out) disconnectClosingStream(closeStream bool) {
	if closeStream {
		s.sess.Close()
	}
	// TODO(ortuman): unregister from router manager

	s.setState(disconnected)
	s.cfg.transport.Close()
}

func (s *out) doRead() {
	if elem, sErr := s.sess.Receive(); sErr == nil {
		s.actorCh <- func() {
			s.readElement(elem)
		}
	} else {
		if s.getState() == disconnected {
			return // already disconnected...
		}
		s.handleSessionError(sErr)
	}
}

func (s *out) handleSessionError(sessErr *session.Error) {
	switch err := sessErr.UnderlyingErr.(type) {
	case nil:
		s.disconnect(nil)
	case *streamerror.Error:
		s.disconnectWithStreamError(err)
	case *xml.StanzaError:
		s.writeElement(xml.NewErrorElementFromElement(sessErr.Element, err, nil))
	default:
		log.Error(err)
		s.disconnectWithStreamError(streamerror.ErrUndefinedCondition)
	}
}

func (s *out) hasStartTLSFeature(features xml.XElement) bool {
	return features.Elements().ChildrenNamespace("starttls", tlsNamespace) != nil
}

func (s *out) hasExternalAuthFeature(features xml.XElement) bool {
	ms := features.Elements().ChildNamespace("mechanisms", saslNamespace)
	if ms != nil {
		for _, m := range ms.Elements().All() {
			if m.Name() == "mechanism" && m.Text() == "EXTERNAL" {
				return true
			}
		}
	}
	return false
}

func (s *out) hasDialbackFeature(features xml.XElement) bool {
	return features.Elements().ChildrenNamespace("dialback", dialbackNamespace) != nil
}

func (s *out) restartSession() {
	j, _ := xml.NewJID("", s.cfg.localDomain, "", true)
	s.sess = session.New(&session.Config{
		JID:           j,
		Transport:     s.cfg.transport,
		MaxStanzaSize: s.cfg.maxStanzaSize,
		IsServer:      true,
	})
	s.setState(connecting)
}

func (s *out) setState(state uint32) {
	atomic.StoreUint32(&s.state, state)
}

func (s *out) getState() uint32 {
	return atomic.LoadUint32(&s.state)
}
