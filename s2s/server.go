/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"fmt"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/ortuman/jackal/log"
	"github.com/ortuman/jackal/router"
	"github.com/ortuman/jackal/transport"
)

var listenerProvider = net.Listen

type server struct {
	cfg       *Config
	ln        net.Listener
	stmCnt    int32
	listening uint32
}

func (s *server) start() {
	bindAddr := s.cfg.Transport.BindAddress
	port := s.cfg.Transport.Port
	address := bindAddr + ":" + strconv.Itoa(port)

	log.Infof("s2s_in: listening at %s", address)

	if err := s.listenConn(address); err != nil {
		log.Fatalf("%v", err)
	}
}

func (s *server) shutdown() {
	s.ln.Close()
}

func (s *server) listenConn(address string) error {
	ln, err := listenerProvider("tcp", address)
	if err != nil {
		return err
	}
	s.ln = ln

	atomic.StoreUint32(&s.listening, 1)
	for atomic.LoadUint32(&s.listening) == 1 {
		conn, err := ln.Accept()
		if err == nil {
			go s.startStream(transport.NewSocketTransport(conn, s.cfg.Transport.KeepAlive))
			continue
		}
	}
	return nil
}

func (s *server) startStream(tr transport.Transport) {
	cfg := &inConfig{
		dbSecret:       s.cfg.DialbackSecret,
		transport:      tr,
		connectTimeout: s.cfg.ConnectTimeout,
		maxStanzaSize:  s.cfg.MaxStanzaSize,
	}
	stm := newInStream(s.nextID(), cfg)
	if err := router.Instance().RegisterS2SIn(stm); err != nil {
		log.Error(err)
	}
}

func (s *server) nextID() string {
	return fmt.Sprintf("s2s_in:%d", atomic.AddInt32(&s.stmCnt, 1))
}
