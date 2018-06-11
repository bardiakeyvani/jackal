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

type server struct {
	cfg        *Config
	ln         net.Listener
	strCounter int32
	listening  uint32
}

func (s *server) nextID() string {
	return fmt.Sprintf("s2s_in:%d", atomic.AddInt32(&s.strCounter, 1))
}
