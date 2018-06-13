/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/transport"
)

type Dialer struct {
	localDomain   string
	cert          tls.Certificate
	timeout       time.Duration
	keepAlive     time.Duration
	maxStanzaSize int
	dialCnt       uint32
}

func (d *Dialer) Dial(domain string) (stream.S2SOut, error) {
	_, addrs, err := net.LookupSRV("xmpp-server", "tcp", domain)

	var target string
	if err != nil || len(addrs) == 0 || (len(addrs) == 1 && addrs[0].Target == ".") {
		target = domain + ":5269"
	} else {
		target = strings.TrimSuffix(addrs[0].Target, ".")
	}
	conn, err := net.DialTimeout("tcp", target+":"+strconv.Itoa(int(addrs[0].Port)), d.timeout)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:   domain,
		Certificates: []tls.Certificate{d.cert},
	}
	tr := transport.NewSocketTransport(conn, d.keepAlive)
	cfg := &OutConfig{
		Transport:     tr,
		RemoteDomain:  domain,
		LocalDomain:   d.localDomain,
		TLS:           tlsConfig,
		MaxStanzaSize: d.maxStanzaSize,
	}
	return NewOut(fmt.Sprintf("s2s_out:%d", atomic.AddUint32(&d.dialCnt, 1)), cfg), nil
}
