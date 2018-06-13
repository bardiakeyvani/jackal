/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"sync"

	"github.com/ortuman/jackal/log"
	"github.com/pkg/errors"
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
}

func Shutdown() {
	instMu.Lock()
	defer instMu.Unlock()
	if initialized {
		srv.shutdown()
		srv = nil
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
		localDomain: config.LocalDomain,
		timeout:     config.DialTimeout,
		keepAlive:   config.Transport.KeepAlive,
		tlsConfig:   config.TLS,
	}, nil
}
