/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"crypto/tls"
	"time"

	"github.com/ortuman/jackal/transport"
	"github.com/pkg/errors"
)

const (
	defaultTransportPort      = 5269
	defaultTransportKeepAlive = time.Duration(120) * time.Second
	defaultOutConnectTimeout  = time.Duration(15) * time.Second
	defaultInConnectTimeout   = time.Duration(5) * time.Second
	defaultMaxStanzaSize      = 131072
)

type TransportConfig struct {
	BindAddress string
	Port        int
	KeepAlive   time.Duration
}

type transportConfigProxy struct {
	BindAddress string `yaml:"bind_addr"`
	Port        int    `yaml:"port"`
	KeepAlive   int    `yaml:"keep_alive"`
}

// UnmarshalYAML satisfies Unmarshaler interface.
func (c *TransportConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	p := transportConfigProxy{}
	if err := unmarshal(&p); err != nil {
		return err
	}
	c.BindAddress = p.BindAddress
	c.Port = p.Port
	if c.Port == 0 {
		c.Port = defaultTransportPort
	}
	if p.KeepAlive > 0 {
		c.KeepAlive = time.Duration(p.KeepAlive) * time.Second
	} else {
		c.KeepAlive = defaultTransportKeepAlive
	}
	return nil
}

// TLSConfig represents a server TLS configuration.
type TLSConfig struct {
	CertFile    string `yaml:"cert_path"`
	PrivKeyFile string `yaml:"privkey_path"`
}

type Config struct {
	Disabled          bool
	OutConnectTimeout time.Duration
	InConnectTimeout  time.Duration
	DialbackSecret    string
	MaxStanzaSize     int
	Transport         TransportConfig
}

type configProxy struct {
	Disabled          bool            `yaml:"disabled"`
	OutConnectTimeout int             `yaml:"out_connect_timeout"`
	InConnectTimeout  int             `yaml:"in_connect_timeout"`
	DialbackSecret    string          `yaml:"dialback_secret"`
	MaxStanzaSize     int             `yaml:"max_stanza_size"`
	Transport         TransportConfig `yaml:"transport"`
}

// UnmarshalYAML satisfies Unmarshaler interface.
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	p := configProxy{}
	if err := unmarshal(&p); err != nil {
		return err
	}
	c.Disabled = p.Disabled
	if c.Disabled {
		return nil
	}
	c.DialbackSecret = p.DialbackSecret
	if len(c.DialbackSecret) == 0 {
		return errors.New("s2s.Config: must specify a dialback secret")
	}
	c.OutConnectTimeout = time.Duration(p.OutConnectTimeout) * time.Second
	if c.OutConnectTimeout == 0 {
		c.OutConnectTimeout = defaultOutConnectTimeout
	}
	c.InConnectTimeout = time.Duration(p.InConnectTimeout) * time.Second
	if c.InConnectTimeout == 0 {
		c.InConnectTimeout = defaultInConnectTimeout
	}
	c.Transport = p.Transport
	c.MaxStanzaSize = p.MaxStanzaSize
	if c.MaxStanzaSize == 0 {
		c.MaxStanzaSize = defaultMaxStanzaSize
	}
	return nil
}

type outConfig struct {
	dbSecret      string
	localDomain   string
	remoteDomain  string
	tls           *tls.Config
	transport     transport.Transport
	maxStanzaSize int
}

type inConfig struct {
	dbSecret       string
	localDomain    string
	remoteDomain   string
	connectTimeout time.Duration
	tls            *tls.Config
	transport      transport.Transport
	maxStanzaSize  int
}
