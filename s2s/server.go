/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"fmt"
	"net"
	"sync/atomic"
)

var (
	initialized uint32
)

type server struct {
	cfg       *Config
	ln        net.Listener
	stmCnt    int32
	listening uint32
}

func Initialize(cfg *Config) {
	if cfg.Disabled {
		return
	}
	if !atomic.CompareAndSwapUint32(&initialized, 0, 1) {
		return
	}
}

func (s *server) nextID() string {
	return fmt.Sprintf("s2s_in:%d", atomic.AddInt32(&s.stmCnt, 1))
}
