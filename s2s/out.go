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
	tlsNamespace  = "urn:ietf:params:xml:ns:xmpp-tls"
	saslNamespace = "urn:ietf:params:xml:ns:xmpp-sasl"
)

const (
	connecting uint32 = iota
	connected
	securing
	authenticating
	started
	disconnected
)

type Out struct {
	id      string
	cfg     *OutConfig
	state   uint32
	sess    *session.Session
	secured bool
	actorCh chan func()
}

func NewOut(id string, cfg *OutConfig) *Out {
	s := &Out{
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

func (s *Out) DomainPair() (local string, remote string) {
	local = s.cfg.LocalDomain
	remote = s.cfg.RemoteDomain
	return
}

func (s *Out) SendElement(elem xml.XElement) {
	s.actorCh <- func() { s.writeElement(elem) }
}

func (s *Out) Disconnect(err error) {
	waitCh := make(chan struct{})
	s.actorCh <- func() {
		s.disconnect(err)
		close(waitCh)
	}
	<-waitCh
}

func (s *Out) Start() {
	s.actorCh <- func() {
		s.sess.Open(false, s.cfg.RemoteDomain)
	}
}

// runs on its own goroutine
func (s *Out) loop() {
	for {
		f := <-s.actorCh
		f()
		if s.getState() == disconnected {
			return
		}
	}
}

// runs on its own goroutine
func (s *Out) handleElement(elem xml.XElement) {
	switch s.getState() {
	case connecting:
		s.handleConnecting(elem)
	case connected:
		s.handleConnected(elem)
	case securing:
		s.handleSecuring(elem)
	case started:
		s.handleStarted(elem)
	}
}

func (s *Out) handleConnecting(elem xml.XElement) {
	s.setState(connected)
}

func (s *Out) handleConnected(elem xml.XElement) {
	if elem.Name() != "stream:features" {
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
		return
	}
	if !s.secured {
		if elem.Elements().Child("starttls") == nil {
			// unsecured channels not supported
			s.disconnectWithStreamError(streamerror.ErrPolicyViolation)
			return
		}
		s.writeElement(xml.NewElementNamespace("starttls", tlsNamespace))
		s.setState(securing)

	} else {
		ms := elem.Elements().ChildNamespace("mechanisms", saslNamespace)
		if ms != nil {
			for _, m := range ms.Elements().All() {
				if m.Name() == "mechanism" && m.Text() == "EXTERNAL" {
					auth := xml.NewElementNamespace("auth", saslNamespace)
					auth.SetAttribute("mechanism", "EXTERNAL")
					auth.SetText("=")
					s.writeElement(auth)
					goto authenticating
				}
			}
		} else {

		}
		return

	authenticating:
		s.setState(authenticating)
	}
}

func (s *Out) handleSecuring(elem xml.XElement) {
	if elem.Name() != "proceed" {
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
		return
	} else if elem.Namespace() != tlsNamespace {
		s.disconnectWithStreamError(streamerror.ErrInvalidNamespace)
		return
	}
	s.cfg.Transport.StartTLS(s.cfg.TLS, true)

	s.restartSession()
	s.sess.Open(false, s.cfg.RemoteDomain)

	s.secured = true
}

func (s *Out) handleStarted(elem xml.XElement) {
}

func (s *Out) disconnect(err error) {
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

func (s *Out) writeElement(elem xml.XElement) {
	s.sess.Send(elem)
}

func (s *Out) readElement(elem xml.XElement) {
	if elem != nil {
		s.handleElement(elem)
	}
	if s.getState() != disconnected {
		go s.doRead()
	}
}

func (s *Out) disconnectWithStreamError(err *streamerror.Error) {
	s.writeElement(err.Element())
	s.disconnectClosingStream(true)
}

func (s *Out) disconnectClosingStream(closeStream bool) {
	if closeStream {
		s.sess.Close()
	}
	// TODO(ortuman): unregister from router manager

	s.setState(disconnected)
	s.cfg.Transport.Close()
}

func (s *Out) doRead() {
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

func (s *Out) handleSessionError(sessErr *session.Error) {
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

func (s *Out) restartSession() {
	j, _ := xml.NewJID("", s.cfg.LocalDomain, "", true)
	s.sess = session.New(&session.Config{
		JID:           j,
		Transport:     s.cfg.Transport,
		MaxStanzaSize: s.cfg.MaxStanzaSize,
		IsServer:      true,
	})
	s.setState(connecting)
}

func (s *Out) setState(state uint32) {
	atomic.StoreUint32(&s.state, state)
}

func (s *Out) getState() uint32 {
	return atomic.LoadUint32(&s.state)
}
