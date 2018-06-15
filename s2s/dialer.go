/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"net"
	"strconv"
	"strings"
	"time"

	"crypto/tls"

	"github.com/ortuman/jackal/router"
	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/transport"
)

type Dialer struct {
	dbSecret      string
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
		Certificates: router.Instance().GetCertificates(),
	}
	tr := transport.NewSocketTransport(conn, d.keepAlive)
	cfg := &streamConfig{
		dbSecret:      d.dbSecret,
		tls:           tlsConfig,
		transport:     tr,
		remoteDomain:  domain,
		maxStanzaSize: d.maxStanzaSize,
	}
	return newOutStream(cfg), nil
}
