/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package c2s

import (
	"crypto/sha256"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/ortuman/jackal/auth"
	"github.com/ortuman/jackal/errors"
	"github.com/ortuman/jackal/log"
	"github.com/ortuman/jackal/module"
	"github.com/ortuman/jackal/module/offline"
	"github.com/ortuman/jackal/module/roster"
	"github.com/ortuman/jackal/module/xep0012"
	"github.com/ortuman/jackal/module/xep0030"
	"github.com/ortuman/jackal/module/xep0049"
	"github.com/ortuman/jackal/module/xep0054"
	"github.com/ortuman/jackal/module/xep0077"
	"github.com/ortuman/jackal/module/xep0092"
	"github.com/ortuman/jackal/module/xep0191"
	"github.com/ortuman/jackal/module/xep0199"
	"github.com/ortuman/jackal/router"
	"github.com/ortuman/jackal/session"
	"github.com/ortuman/jackal/storage"
	"github.com/ortuman/jackal/storage/model"
	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/transport"
	"github.com/ortuman/jackal/transport/compress"
	"github.com/ortuman/jackal/xml"
	"github.com/pborman/uuid"
)

const streamMailboxSize = 64

const (
	connecting uint32 = iota
	connected
	authenticating
	authenticated
	sessionStarted
	disconnected
)

const (
	streamNamespace           = "http://etherx.jabber.org/streams"
	tlsNamespace              = "urn:ietf:params:xml:ns:xmpp-tls"
	compressProtocolNamespace = "http://jabber.org/protocol/compress"
	bindNamespace             = "urn:ietf:params:xml:ns:xmpp-bind"
	sessionNamespace          = "urn:ietf:params:xml:ns:xmpp-session"
	saslNamespace             = "urn:ietf:params:xml:ns:xmpp-sasl"
	blockedErrorNamespace     = "urn:xmpp:blocking:errors"
)

// stream context keys
const (
	usernameCtxKey      = "stream:username"
	domainCtxKey        = "stream:domain"
	resourceCtxKey      = "stream:resource"
	jidCtxKey           = "stream:jid"
	securedCtxKey       = "stream:secured"
	authenticatedCtxKey = "stream:authenticated"
	compressedCtxKey    = "stream:compressed"
	presenceCtxKey      = "stream:presence"
)

// once context keys
const (
	rosterOnceCtxKey  = "stream:rosterOnce"
	offlineOnceCtxKey = "stream:offlineOnce"
)

type modules struct {
	roster       *roster.Roster
	offline      *offline.Offline
	lastActivity *xep0012.LastActivity
	discoInfo    *xep0030.DiscoInfo
	private      *xep0049.Private
	vCard        *xep0054.VCard
	register     *xep0077.Register
	version      *xep0092.Version
	blockingCmd  *xep0191.BlockingCommand
	ping         *xep0199.Ping
	iqHandlers   []module.IQHandler
	all          []module.Module
}

type inStream struct {
	cfg            *InConfig
	sess           *session.Session
	id             string
	connectTm      *time.Timer
	state          uint32
	ctx            stream.Context
	authenticators []auth.Authenticator
	activeAuth     auth.Authenticator
	mods           modules
	actorCh        chan func()
	doneCh         chan<- struct{}
}

// New returns a new c2s stream instance.
func New(id string, cfg *InConfig) stream.C2S {
	ctx, doneCh := stream.NewContext()
	s := &inStream{
		cfg:     cfg,
		id:      id,
		ctx:     ctx,
		actorCh: make(chan func(), streamMailboxSize),
		doneCh:  doneCh,
	}
	// initialize stream context
	secured := !(cfg.Transport.Type() == transport.Socket)
	s.ctx.SetBool(secured, securedCtxKey)
	s.ctx.SetString(s.cfg.Domain, domainCtxKey)

	j, _ := xml.NewJID("", s.cfg.Domain, "", true)
	s.ctx.SetObject(j, jidCtxKey)

	// initialize authenticators
	s.initializeAuthenticators()

	// initialize modules
	s.initializeModules()

	// start c2s session
	s.restartSession()

	if cfg.ConnectTimeout > 0 {
		s.connectTm = time.AfterFunc(time.Duration(cfg.ConnectTimeout)*time.Second, s.connectTimeout)
	}
	go s.loop()
	go s.doRead() // start reading...

	return s
}

// ID returns stream identifier.
func (s *inStream) ID() string {
	return s.id
}

// context returns stream associated context.
func (s *inStream) Context() stream.Context {
	return s.ctx
}

// Username returns current stream username.
func (s *inStream) Username() string {
	return s.ctx.String(usernameCtxKey)
}

// Domain returns current stream domain.
func (s *inStream) Domain() string {
	return s.ctx.String(domainCtxKey)
}

// Resource returns current stream resource.
func (s *inStream) Resource() string {
	return s.ctx.String(resourceCtxKey)
}

// JID returns current user JID.
func (s *inStream) JID() *xml.JID {
	return s.ctx.Object(jidCtxKey).(*xml.JID)
}

// IsAuthenticated returns whether or not the XMPP stream
// has successfully authenticated.
func (s *inStream) IsAuthenticated() bool {
	return s.ctx.Bool(authenticatedCtxKey)
}

// IsSecured returns whether or not the XMPP stream
// has been secured using SSL/TLS.
func (s *inStream) IsSecured() bool {
	return s.ctx.Bool(securedCtxKey)
}

// IsCompressed returns whether or not the XMPP stream
// has enabled a compression method.
func (s *inStream) IsCompressed() bool {
	return s.ctx.Bool(compressedCtxKey)
}

// Presence returns last sent presence element.
func (s *inStream) Presence() *xml.Presence {
	switch v := s.ctx.Object(presenceCtxKey).(type) {
	case *xml.Presence:
		return v
	}
	return nil
}

// SendElement sends the given XML element.
func (s *inStream) SendElement(elem xml.XElement) {
	s.actorCh <- func() { s.writeElement(elem) }
}

// Disconnect disconnects remote peer by closing
// the underlying TCP socket connection.
func (s *inStream) Disconnect(err error) {
	waitCh := make(chan struct{})
	s.actorCh <- func() {
		s.disconnect(err)
		close(waitCh)
	}
	<-waitCh
}

func (s *inStream) initializeAuthenticators() {
	tr := s.cfg.Transport
	var authenticators []auth.Authenticator
	for _, a := range s.cfg.SASL {
		switch a {
		case "plain":
			authenticators = append(authenticators, auth.NewPlain(s))

		case "digest_md5":
			authenticators = append(authenticators, auth.NewDigestMD5(s))

		case "scram_sha_1":
			authenticators = append(authenticators, auth.NewScram(s, tr, auth.ScramSHA1, false))
			authenticators = append(authenticators, auth.NewScram(s, tr, auth.ScramSHA1, true))

		case "scram_sha_256":
			authenticators = append(authenticators, auth.NewScram(s, tr, auth.ScramSHA256, false))
			authenticators = append(authenticators, auth.NewScram(s, tr, auth.ScramSHA256, true))
		}
	}
	s.authenticators = authenticators
}

func (s *inStream) initializeModules() {
	var mods modules

	// XEP-0030: Service Discovery (https://xmpp.org/extensions/xep-0030.html)
	mods.discoInfo = xep0030.New(s)
	mods.iqHandlers = append(mods.iqHandlers, mods.discoInfo)
	mods.all = append(mods.all, mods.discoInfo)

	// Roster (https://xmpp.org/rfcs/rfc3921.html#roster)
	mods.roster = roster.New(&s.cfg.Modules.Roster, s)
	mods.iqHandlers = append(mods.iqHandlers, mods.roster)
	mods.all = append(mods.all, mods.roster)

	// XEP-0012: Last Activity (https://xmpp.org/extensions/xep-0012.html)
	if _, ok := s.cfg.Modules.Enabled["last_activity"]; ok {
		mods.lastActivity = xep0012.New(s)
		mods.iqHandlers = append(mods.iqHandlers, mods.lastActivity)
		mods.all = append(mods.all, mods.lastActivity)
	}

	// XEP-0049: Private XML Storage (https://xmpp.org/extensions/xep-0049.html)
	if _, ok := s.cfg.Modules.Enabled["private"]; ok {
		mods.private = xep0049.New(s)
		mods.iqHandlers = append(mods.iqHandlers, mods.private)
		mods.all = append(mods.all, mods.private)
	}

	// XEP-0054: vcard-temp (https://xmpp.org/extensions/xep-0054.html)
	if _, ok := s.cfg.Modules.Enabled["vcard"]; ok {
		mods.vCard = xep0054.New(s)
		mods.iqHandlers = append(mods.iqHandlers, mods.vCard)
		mods.all = append(mods.all, mods.vCard)
	}

	// XEP-0077: In-band registration (https://xmpp.org/extensions/xep-0077.html)
	if _, ok := s.cfg.Modules.Enabled["registration"]; ok {
		mods.register = xep0077.New(&s.cfg.Modules.Registration, s)
		mods.iqHandlers = append(mods.iqHandlers, mods.register)
		mods.all = append(mods.all, mods.register)
	}

	// XEP-0092: Software Version (https://xmpp.org/extensions/xep-0092.html)
	if _, ok := s.cfg.Modules.Enabled["version"]; ok {
		mods.version = xep0092.New(&s.cfg.Modules.Version, s)
		mods.iqHandlers = append(mods.iqHandlers, mods.version)
		mods.all = append(mods.all, mods.version)
	}

	// XEP-0191: Blocking Command (https://xmpp.org/extensions/xep-0191.html)
	if _, ok := s.cfg.Modules.Enabled["blocking_command"]; ok {
		mods.blockingCmd = xep0191.New(s)
		mods.iqHandlers = append(mods.iqHandlers, mods.blockingCmd)
		mods.all = append(mods.all, mods.blockingCmd)
	}

	// XEP-0199: XMPP Ping (https://xmpp.org/extensions/xep-0199.html)
	if _, ok := s.cfg.Modules.Enabled["ping"]; ok {
		mods.ping = xep0199.New(&s.cfg.Modules.Ping, s)
		mods.iqHandlers = append(mods.iqHandlers, mods.ping)
		mods.all = append(mods.all, mods.ping)
	}

	// XEP-0160: Offline message storage (https://xmpp.org/extensions/xep-0160.html)
	if _, ok := s.cfg.Modules.Enabled["offline"]; ok {
		mods.offline = offline.New(&s.cfg.Modules.Offline, s)
		mods.all = append(mods.all, mods.offline)
	}
	s.mods = mods
}

func (s *inStream) connectTimeout() {
	s.actorCh <- func() { s.disconnect(streamerror.ErrConnectionTimeout) }
}

func (s *inStream) handleElement(elem xml.XElement) {
	switch s.getState() {
	case connecting:
		s.handleConnecting(elem)
	case connected:
		s.handleConnected(elem)
	case authenticated:
		s.handleAuthenticated(elem)
	case authenticating:
		s.handleAuthenticating(elem)
	case sessionStarted:
		s.handleSessionStarted(elem)
	}
}

func (s *inStream) handleConnecting(elem xml.XElement) {
	// cancel connection timeout timer
	if s.connectTm != nil {
		s.connectTm.Stop()
		s.connectTm = nil
	}
	// assign stream domain
	s.ctx.SetString(elem.To(), domainCtxKey)

	// open stream session
	s.sess.Open()

	features := xml.NewElementName("stream:features")
	features.SetAttribute("xmlns:stream", streamNamespace)
	features.SetAttribute("version", "1.0")

	if !s.IsAuthenticated() {
		features.AppendElements(s.unauthenticatedFeatures())
		s.setState(connected)
	} else {
		features.AppendElements(s.authenticatedFeatures())
		s.setState(authenticated)
	}
	s.writeElement(features)
}

func (s *inStream) unauthenticatedFeatures() []xml.XElement {
	var features []xml.XElement

	isSocketTr := s.cfg.Transport.Type() == transport.Socket

	if isSocketTr && !s.IsSecured() {
		startTLS := xml.NewElementName("starttls")
		startTLS.SetNamespace("urn:ietf:params:xml:ns:xmpp-tls")
		startTLS.AppendElement(xml.NewElementName("required"))
		features = append(features, startTLS)
	}

	// attach SASL mechanisms
	shouldOfferSASL := (!isSocketTr || (isSocketTr && s.IsSecured()))

	if shouldOfferSASL && len(s.authenticators) > 0 {
		mechanisms := xml.NewElementName("mechanisms")
		mechanisms.SetNamespace(saslNamespace)
		for _, athr := range s.authenticators {
			mechanism := xml.NewElementName("mechanism")
			mechanism.SetText(athr.Mechanism())
			mechanisms.AppendElement(mechanism)
		}
		features = append(features, mechanisms)
	}

	// allow In-band registration over encrypted Stream only
	allowRegistration := s.IsSecured()

	if reg := s.mods.register; reg != nil && allowRegistration {
		registerFeature := xml.NewElementNamespace("register", "http://jabber.org/features/iq-register")
		features = append(features, registerFeature)
	}
	return features
}

func (s *inStream) authenticatedFeatures() []xml.XElement {
	var features []xml.XElement

	isSocketTr := s.cfg.Transport.Type() == transport.Socket

	// attach compression feature
	compressionAvailable := isSocketTr && s.cfg.Compression.Level != compress.NoCompression

	if !s.IsCompressed() && compressionAvailable {
		compression := xml.NewElementNamespace("compression", "http://jabber.org/features/compress")
		method := xml.NewElementName("method")
		method.SetText("zlib")
		compression.AppendElement(method)
		features = append(features, compression)
	}
	bind := xml.NewElementNamespace("bind", "urn:ietf:params:xml:ns:xmpp-bind")
	bind.AppendElement(xml.NewElementName("required"))
	features = append(features, bind)

	sessElem := xml.NewElementNamespace("session", "urn:ietf:params:xml:ns:xmpp-session")
	features = append(features, sessElem)

	if s.mods.roster != nil && s.mods.roster.VersioningEnabled() {
		ver := xml.NewElementNamespace("ver", "urn:xmpp:features:rosterver")
		features = append(features, ver)
	}
	return features
}

func (s *inStream) handleConnected(elem xml.XElement) {
	switch elem.Name() {
	case "starttls":
		if len(elem.Namespace()) > 0 && elem.Namespace() != tlsNamespace {
			s.disconnectWithStreamError(streamerror.ErrInvalidNamespace)
			return
		}
		s.proceedStartTLS()

	case "auth":
		if elem.Namespace() != saslNamespace {
			s.disconnectWithStreamError(streamerror.ErrInvalidNamespace)
			return
		}
		s.startAuthentication(elem)

	case "iq":
		iq := elem.(*xml.IQ)
		if reg := s.mods.register; reg.MatchesIQ(iq) {
			reg.ProcessIQ(iq)
			return
		} else if iq.Elements().ChildNamespace("query", "jabber:iq:auth") != nil {
			// don't allow non-SASL authentication
			s.writeElement(iq.ServiceUnavailableError())
			return
		}
		fallthrough

	case "message", "presence":
		s.disconnectWithStreamError(streamerror.ErrNotAuthorized)

	default:
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
	}
}

func (s *inStream) handleAuthenticating(elem xml.XElement) {
	if elem.Namespace() != saslNamespace {
		s.disconnectWithStreamError(streamerror.ErrInvalidNamespace)
		return
	}
	authr := s.activeAuth
	s.continueAuthentication(elem, authr)
	if authr.Authenticated() {
		s.finishAuthentication(authr.Username())
	}
}

func (s *inStream) handleAuthenticated(elem xml.XElement) {
	switch elem.Name() {
	case "compress":
		if elem.Namespace() != compressProtocolNamespace {
			s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
			return
		}
		s.compress(elem)

	case "iq":
		iq := elem.(*xml.IQ)
		if len(s.Resource()) == 0 { // expecting bind
			s.bindResource(iq)
		} else { // expecting session
			s.startSession(iq)
		}

	default:
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
	}
}

func (s *inStream) handleSessionStarted(elem xml.XElement) {
	// reset ping timer deadline
	if p := s.mods.ping; p != nil {
		p.ResetDeadline()
	}
	stanza, ok := elem.(xml.Stanza)
	if !ok {
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
		return
	}
	if s.isComponentDomain(stanza.ToJID().Domain()) {
		s.processComponentStanza(stanza)
	} else {
		s.processStanza(stanza)
	}
}

func (s *inStream) proceedStartTLS() {
	if s.IsSecured() {
		s.disconnectWithStreamError(streamerror.ErrNotAuthorized)
		return
	}
	s.ctx.SetBool(true, securedCtxKey)

	s.writeElement(xml.NewElementNamespace("proceed", tlsNamespace))

	// don't do anything in case no TLS configuration has been provided (useful for testing purposes).
	if tlsConfig := s.cfg.TLS; tlsConfig != nil {
		s.cfg.Transport.StartTLS(tlsConfig, false)
	}
	log.Infof("secured stream... id: %s", s.id)

	s.restartSession()
}

func (s *inStream) compress(elem xml.XElement) {
	if s.IsCompressed() {
		s.disconnectWithStreamError(streamerror.ErrUnsupportedStanzaType)
		return
	}
	method := elem.Elements().Child("method")
	if method == nil || len(method.Text()) == 0 {
		failure := xml.NewElementNamespace("failure", compressProtocolNamespace)
		failure.AppendElement(xml.NewElementName("setup-failed"))
		s.writeElement(failure)
		return
	}
	if method.Text() != "zlib" {
		failure := xml.NewElementNamespace("failure", compressProtocolNamespace)
		failure.AppendElement(xml.NewElementName("unsupported-method"))
		s.writeElement(failure)
		return
	}
	s.ctx.SetBool(true, compressedCtxKey)

	s.writeElement(xml.NewElementNamespace("compressed", compressProtocolNamespace))

	s.cfg.Transport.EnableCompression(s.cfg.Compression.Level)

	log.Infof("compressed stream... id: %s", s.id)

	s.restartSession()
}

func (s *inStream) startAuthentication(elem xml.XElement) {
	mechanism := elem.Attributes().Get("mechanism")
	for _, authr := range s.authenticators {
		if authr.Mechanism() == mechanism {
			if err := s.continueAuthentication(elem, authr); err != nil {
				return
			}
			if authr.Authenticated() {
				s.finishAuthentication(authr.Username())
			} else {
				s.activeAuth = authr
				s.setState(authenticating)
			}
			return
		}
	}
	// ...mechanism not found...
	failure := xml.NewElementNamespace("failure", saslNamespace)
	failure.AppendElement(xml.NewElementName("invalid-mechanism"))
	s.writeElement(failure)
}

func (s *inStream) continueAuthentication(elem xml.XElement, authr auth.Authenticator) error {
	err := authr.ProcessElement(elem)
	if saslErr, ok := err.(*auth.SASLError); ok {
		s.failAuthentication(saslErr.Element())
	} else if err != nil {
		log.Error(err)
		s.failAuthentication(auth.ErrSASLTemporaryAuthFailure.(*auth.SASLError).Element())
	}
	return err
}

func (s *inStream) finishAuthentication(username string) {
	if s.activeAuth != nil {
		s.activeAuth.Reset()
		s.activeAuth = nil
	}
	j, _ := xml.NewJID(username, s.Domain(), "", true)

	s.ctx.SetString(username, usernameCtxKey)
	s.ctx.SetBool(true, authenticatedCtxKey)
	s.ctx.SetObject(j, jidCtxKey)

	s.restartSession()
}

func (s *inStream) failAuthentication(elem xml.XElement) {
	failure := xml.NewElementNamespace("failure", saslNamespace)
	failure.AppendElement(elem)
	s.writeElement(failure)

	if s.activeAuth != nil {
		s.activeAuth.Reset()
		s.activeAuth = nil
	}
	s.setState(connected)
}

func (s *inStream) bindResource(iq *xml.IQ) {
	bind := iq.Elements().ChildNamespace("bind", bindNamespace)
	if bind == nil {
		s.writeElement(iq.NotAllowedError())
		return
	}
	var resource string
	if resourceElem := bind.Elements().Child("resource"); resourceElem != nil {
		resource = resourceElem.Text()
	} else {
		resource = uuid.New()
	}
	// try binding...
	var stm stream.C2S
	stms := router.Instance().StreamsMatchingJID(s.JID().ToBareJID())
	for _, s := range stms {
		if s.Resource() == resource {
			stm = s
		}
	}
	if stm != nil {
		switch s.cfg.ResourceConflict {
		case Override:
			// override the resource with a server-generated resourcepart...
			h := sha256.New()
			h.Write([]byte(s.ID()))
			resource = hex.EncodeToString(h.Sum(nil))
		case Replace:
			// terminate the session of the currently connected client...
			stm.Disconnect(streamerror.ErrResourceConstraint)
		default:
			// disallow resource binding attempt...
			s.writeElement(iq.ConflictError())
			return
		}
	}
	userJID, err := xml.NewJID(s.Username(), s.Domain(), resource, false)
	if err != nil {
		s.writeElement(iq.BadRequestError())
		return
	}
	s.ctx.SetString(resource, resourceCtxKey)
	s.ctx.SetObject(userJID, jidCtxKey)

	s.sess.UpdateJID(userJID)

	log.Infof("binded resource... (%s/%s)", s.Username(), s.Resource())

	//...notify successful binding
	result := xml.NewIQType(iq.ID(), xml.ResultType)
	result.SetNamespace(iq.Namespace())

	binded := xml.NewElementNamespace("bind", bindNamespace)
	jid := xml.NewElementName("jid")
	jid.SetText(s.Username() + "@" + s.Domain() + "/" + s.Resource())
	binded.AppendElement(jid)
	result.AppendElement(binded)

	s.writeElement(result)

	if err := router.Instance().BindC2S(s); err != nil {
		log.Error(err)
	}
}

func (s *inStream) startSession(iq *xml.IQ) {
	if len(s.Resource()) == 0 {
		// not binded yet...
		s.Disconnect(streamerror.ErrNotAuthorized)
		return
	}
	sess := iq.Elements().ChildNamespace("session", sessionNamespace)
	if sess == nil {
		s.writeElement(iq.NotAllowedError())
		return
	}
	s.writeElement(iq.ResultIQ())

	// register disco info elements
	s.mods.discoInfo.RegisterDefaultEntities()
	for _, mod := range s.mods.all {
		mod.RegisterDisco(s.mods.discoInfo)
	}
	if p := s.mods.ping; p != nil {
		p.StartPinging()
	}
	s.setState(sessionStarted)
}

func (s *inStream) processStanza(stanza xml.Stanza) {
	toJID := stanza.ToJID()
	if s.isBlockedJID(toJID) { // blocked JID?
		blocked := xml.NewElementNamespace("blocked", blockedErrorNamespace)
		resp := xml.NewErrorElementFromElement(stanza, xml.ErrNotAcceptable.(*xml.StanzaError), []xml.XElement{blocked})
		s.writeElement(resp)
		return
	}
	if !router.Instance().IsLocalDomain(toJID.Domain()) {
		router.Instance().Route(stanza)
		return
	}
	switch stanza := stanza.(type) {
	case *xml.Presence:
		s.processPresence(stanza)
	case *xml.IQ:
		s.processIQ(stanza)
	case *xml.Message:
		s.processMessage(stanza)
	}
}

func (s *inStream) processComponentStanza(stanza xml.Stanza) {
}

func (s *inStream) processIQ(iq *xml.IQ) {
	toJID := iq.ToJID()
	if node := toJID.Node(); len(node) > 0 && router.Instance().IsBlockedJID(s.JID(), node) {
		// destination user blocked stream JID
		if iq.IsGet() || iq.IsSet() {
			s.writeElement(iq.ServiceUnavailableError())
		}
		return
	}
	if toJID.IsFullWithUser() {
		switch router.Instance().Route(iq) {
		case router.ErrResourceNotFound:
			s.writeElement(iq.ServiceUnavailableError())
		}
		return
	}
	for _, handler := range s.mods.iqHandlers {
		if !handler.MatchesIQ(iq) {
			continue
		}
		handler.ProcessIQ(iq)
		return
	}

	// ...IQ not handled...
	if iq.IsGet() || iq.IsSet() {
		s.writeElement(iq.ServiceUnavailableError())
	}
}

func (s *inStream) processPresence(presence *xml.Presence) {
	toJID := presence.ToJID()
	if toJID.IsBare() && (toJID.Node() != s.Username() || toJID.Domain() != s.Domain()) {
		if rst := s.mods.roster; rst != nil {
			rst.ProcessPresence(presence)
		}
		return
	}
	if toJID.IsFullWithUser() {
		router.Instance().Route(presence)
		return
	}
	// set context presence
	s.ctx.SetObject(presence, presenceCtxKey)

	// deliver pending approval notifications
	if rst := s.mods.roster; rst != nil {
		if !s.ctx.Bool(rosterOnceCtxKey) {
			rst.DeliverPendingApprovalNotifications()
			rst.ReceivePresences()
			s.ctx.SetBool(true, rosterOnceCtxKey)
		}
		rst.BroadcastPresence(presence)
	}

	// deliver offline messages
	if p := s.Presence(); s.mods.offline != nil && p != nil && p.Priority() >= 0 {
		if !s.ctx.Bool(offlineOnceCtxKey) {
			s.mods.offline.DeliverOfflineMessages()
			s.ctx.SetBool(true, offlineOnceCtxKey)
		}
	}
}

func (s *inStream) processMessage(message *xml.Message) {
	toJID := message.ToJID()

sendMessage:
	err := router.Instance().Route(message)
	switch err {
	case nil:
		break
	case router.ErrNotAuthenticated:
		if off := s.mods.offline; off != nil {
			if (message.IsChat() || message.IsGroupChat()) && message.IsMessageWithBody() {
				return
			}
			off.ArchiveMessage(message)
		}
	case router.ErrResourceNotFound:
		// treat the stanza as if it were addressed to <node@domain>
		toJID = toJID.ToBareJID()
		goto sendMessage
	case router.ErrNotExistingAccount, router.ErrBlockedJID:
		s.writeElement(message.ServiceUnavailableError())
	default:
		log.Error(err)
	}
}

// runs on it's own goroutine
func (s *inStream) loop() {
	for {
		f := <-s.actorCh
		f()
		if s.getState() == disconnected {
			return
		}
	}
}

// runs on it's own goroutine
func (s *inStream) doRead() {
	elem, sErr := s.sess.Receive()
	if sErr == nil {
		s.actorCh <- func() {
			s.readElement(elem)
		}
	} else {
		s.actorCh <- func() {
			if s.getState() == disconnected {
				return
			}
			s.handleSessionError(sErr)
		}
	}
}

func (s *inStream) handleSessionError(sessErr *session.Error) {
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

func (s *inStream) writeElement(elem xml.XElement) {
	s.sess.Send(elem)
}

func (s *inStream) readElement(elem xml.XElement) {
	if elem != nil {
		s.handleElement(elem)
	}
	if s.getState() != disconnected {
		go s.doRead() // keep reading...
	}
}

func (s *inStream) disconnect(err error) {
	if s.getState() == disconnected {
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

func (s *inStream) isComponentDomain(domain string) bool {
	return false
}

func (s *inStream) disconnectWithStreamError(err *streamerror.Error) {
	if s.getState() == connecting {
		s.sess.Open()
	}
	s.writeElement(err.Element())

	unregistering := err != streamerror.ErrSystemShutdown
	s.disconnectClosingSession(true, unregistering)
}

func (s *inStream) disconnectClosingSession(closeSession, unregistering bool) {
	if presence := s.Presence(); presence != nil && presence.IsAvailable() && s.mods.roster != nil {
		s.mods.roster.BroadcastPresenceAndWait(xml.NewPresence(s.JID(), s.JID(), xml.UnavailableType))
	}
	if closeSession {
		s.sess.Close()
	}
	// signal termination...
	close(s.doneCh)

	// unregister stream
	if unregistering {
		if err := router.Instance().UnregisterC2S(s); err != nil {
			log.Error(err)
		}
	}
	if err := s.updateLogoutInfo(); err != nil {
		log.Error(err)
	}
	s.setState(disconnected)
	s.cfg.Transport.Close()
}

func (s *inStream) updateLogoutInfo() error {
	var usr *model.User
	var err error
	if presence := s.Presence(); presence != nil {
		if usr, err = storage.Instance().FetchUser(s.Username()); usr != nil && err == nil {
			usr.LoggedOutAt = time.Now()
			if presence.IsUnavailable() {
				usr.LoggedOutStatus = presence.Status()
			}
			return storage.Instance().InsertOrUpdateUser(usr)
		}
	}
	return err
}

func (s *inStream) isBlockedJID(jid *xml.JID) bool {
	if jid.IsServer() && router.Instance().IsLocalDomain(jid.Domain()) {
		return false
	}
	return router.Instance().IsBlockedJID(jid, s.Username())
}

func (s *inStream) restartSession() {
	s.sess = session.New(&session.Config{
		JID:           s.JID(),
		Transport:     s.cfg.Transport,
		MaxStanzaSize: s.cfg.MaxStanzaSize,
	})
	s.setState(connecting)
}

func (s *inStream) setState(state uint32) {
	atomic.StoreUint32(&s.state, state)
}

func (s *inStream) getState() uint32 {
	return atomic.LoadUint32(&s.state)
}
