/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/ortuman/jackal/log"
	"github.com/pkg/errors"
)

const streamMailboxSize = 64

const (
	tlsNamespace      = "urn:ietf:params:xml:ns:xmpp-tls"
	saslNamespace     = "urn:ietf:params:xml:ns:xmpp-sasl"
	dialbackNamespace = "urn:xmpp:features:dialback"
)

var (
	instMu      sync.RWMutex
	config      *Config
	srv         *server
	initialized bool
)

func Initialize(cfg *Config) {
	if cfg.Disabled {
		return
	}
	instMu.Lock()
	defer instMu.Unlock()
	if initialized {
		return
	}
	config = cfg
	srv = &server{cfg: cfg}
	go srv.start()
	initialized = true
}

func Shutdown() {
	instMu.Lock()
	defer instMu.Unlock()
	if initialized {
		srv.shutdown()
		srv = nil
		initialized = false
	}
}

func NewDialer() (*Dialer, error) {
	instMu.RLock()
	defer instMu.RUnlock()
	if !initialized {
		log.Fatalf("s2s subsystem not initialized")
	} else if config.Disabled {
		return nil, errors.New("s2s not enabled")
	}
	return &Dialer{
		dbSecret:  config.DialbackSecret,
		timeout:   config.DialTimeout,
		keepAlive: config.Transport.KeepAlive,
	}, nil
}

func dialbackKey(from, to, streamID, secret string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	hm := hmac.New(sha256.New, []byte(hex.EncodeToString(h.Sum(nil))))
	hm.Write([]byte(fmt.Sprintf("%s %s %s", to, from, streamID)))
	return hex.EncodeToString(hm.Sum(nil))
}
