/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package c2s

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/ortuman/jackal/module/offline"
	"github.com/ortuman/jackal/module/roster"
	"github.com/ortuman/jackal/module/xep0077"
	"github.com/ortuman/jackal/module/xep0092"
	"github.com/ortuman/jackal/module/xep0199"
	"github.com/ortuman/jackal/transport"
	"github.com/ortuman/jackal/transport/compress"
	"github.com/ortuman/jackal/util"
)

const (
	defaultDomain                  = "localhost"
	defaultTransportConnectTimeout = 5
	defaultTransportMaxStanzaSize  = 32768
	defaultTransportPort           = 5222
	defaultTransportKeepAlive      = 120
)

// ResourceConflictPolicy represents a resource conflict policy.
type ResourceConflictPolicy int

const (
	// Override represents 'override' resource conflict policy.
	Override ResourceConflictPolicy = iota

	// Reject represents 'reject' resource conflict policy.
	Reject

	// Replace represents 'replace' resource conflict policy.
	Replace
)

// CompressConfig represents a server Stream compression configuration.
type CompressConfig struct {
	Level compress.Level
}

type compressionProxyType struct {
	Level string `yaml:"level"`
}

// UnmarshalYAML satisfies Unmarshaler interface.
func (c *CompressConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	p := compressionProxyType{}
	if err := unmarshal(&p); err != nil {
		return err
	}
	switch p.Level {
	case "":
		c.Level = compress.NoCompression
	case "best":
		c.Level = compress.BestCompression
	case "speed":
		c.Level = compress.SpeedCompression
	case "default":
		c.Level = compress.DefaultCompression
	default:
		return fmt.Errorf("c2s.CompressConfig: unrecognized compression level: %s", p.Level)
	}
	return nil
}

// ModulesConfig represents C2S modules configuration.
type ModulesConfig struct {
	Enabled      map[string]struct{}
	Roster       roster.Config
	Offline      offline.Config
	Registration xep0077.Config
	Version      xep0092.Config
	Ping         xep0199.Config
}

type modulesConfigProxy struct {
	Enabled      []string       `yaml:"enabled"`
	Roster       roster.Config  `yaml:"mod_roster"`
	Offline      offline.Config `yaml:"mod_offline"`
	Registration xep0077.Config `yaml:"mod_registration"`
	Version      xep0092.Config `yaml:"mod_version"`
	Ping         xep0199.Config `yaml:"mod_ping"`
}

// UnmarshalYAML satisfies Unmarshaler interface.
func (cfg *ModulesConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	p := modulesConfigProxy{}
	if err := unmarshal(&p); err != nil {
		return err
	}
	// validate modules
	enabled := make(map[string]struct{}, len(p.Enabled))
	for _, mod := range p.Enabled {
		switch mod {
		case "roster", "last_activity", "private", "vcard", "registration", "version", "blocking_command",
			"ping", "offline":
			break
		default:
			return fmt.Errorf("c2s.ModulesConfig: unrecognized module: %s", mod)
		}
		enabled[mod] = struct{}{}
	}
	cfg.Enabled = enabled
	cfg.Roster = p.Roster
	cfg.Offline = p.Offline
	cfg.Registration = p.Registration
	cfg.Version = p.Version
	cfg.Ping = p.Ping
	return nil
}

// TransportConfig represents an XMPP stream transport configuration.
type TransportConfig struct {
	Type        transport.TransportType
	BindAddress string
	Port        int
	KeepAlive   int
	URLPath     string
}

type transportProxyType struct {
	Type        string `yaml:"type"`
	BindAddress string `yaml:"bind_addr"`
	Port        int    `yaml:"port"`
	KeepAlive   int    `yaml:"keep_alive"`
	URLPath     string `yaml:"url_path"`
}

// UnmarshalYAML satisfies Unmarshaler interface.
func (t *TransportConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	p := transportProxyType{}
	if err := unmarshal(&p); err != nil {
		return err
	}
	// validate transport type
	switch p.Type {
	case "", "socket":
		t.Type = transport.Socket

	case "websocket":
		t.Type = transport.WebSocket

	default:
		return fmt.Errorf("c2s.TransportConfig: unrecognized transport type: %s", p.Type)
	}
	t.BindAddress = p.BindAddress
	t.Port = p.Port
	t.KeepAlive = p.KeepAlive
	t.URLPath = p.URLPath

	// assign transport's defaults
	if t.Port == 0 {
		t.Port = defaultTransportPort
	}
	if t.KeepAlive == 0 {
		t.KeepAlive = defaultTransportKeepAlive
	}
	return nil
}

// TLSConfig represents a server TLS configuration.
type TLSConfig struct {
	CertFile    string `yaml:"cert_path"`
	PrivKeyFile string `yaml:"privkey_path"`
}

// ServerConfig represents C2S server configuration.
type ServerConfig struct {
	ID               string
	Domain           string
	TLS              *tls.Config
	ConnectTimeout   int
	MaxStanzaSize    int
	ResourceConflict ResourceConflictPolicy
	Transport        TransportConfig
	SASL             []string
	Compression      CompressConfig
	Modules          ModulesConfig
}

type serverConfigProxy struct {
	ID               string          `yaml:"id"`
	Domain           string          `yaml:"domain"`
	TLS              TLSConfig       `yaml:"tls"`
	ConnectTimeout   int             `yaml:"connect_timeout"`
	MaxStanzaSize    int             `yaml:"max_stanza_size"`
	ResourceConflict string          `yaml:"resource_conflict"`
	Transport        TransportConfig `yaml:"transport"`
	SASL             []string        `yaml:"sasl"`
	Compression      CompressConfig  `yaml:"compression"`
	Modules          ModulesConfig   `yaml:"modules"`
}

// UnmarshalYAML satisfies Unmarshaler interface.
func (cfg *ServerConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	p := serverConfigProxy{}
	if err := unmarshal(&p); err != nil {
		return err
	}
	cfg.ID = p.ID
	cfg.Domain = p.Domain
	if len(cfg.Domain) == 0 {
		cfg.Domain = defaultDomain
	}
	cer, err := util.LoadCertificate(p.TLS.PrivKeyFile, p.TLS.CertFile, cfg.Domain)
	if err != nil {
		return err
	}
	cfg.TLS = &tls.Config{ServerName: cfg.Domain, Certificates: []tls.Certificate{cer}}

	cfg.ConnectTimeout = p.ConnectTimeout
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = defaultTransportConnectTimeout
	}
	cfg.MaxStanzaSize = p.MaxStanzaSize
	if cfg.MaxStanzaSize == 0 {
		cfg.MaxStanzaSize = defaultTransportMaxStanzaSize
	}

	// validate resource conflict policy type
	rc := strings.ToLower(p.ResourceConflict)
	switch rc {
	case "override":
		cfg.ResourceConflict = Override
	case "reject":
		cfg.ResourceConflict = Reject
	case "", "replace":
		cfg.ResourceConflict = Replace
	default:
		return fmt.Errorf("c2s.Config: invalid resource_conflict option: %s", rc)
	}
	// validate SASL mechanisms
	for _, sasl := range p.SASL {
		switch sasl {
		case "plain", "digest_md5", "scram_sha_1", "scram_sha_256":
			continue
		default:
			return fmt.Errorf("c2s.Config: unrecognized SASL mechanism: %s", sasl)
		}
	}
	cfg.Transport = p.Transport
	cfg.SASL = p.SASL
	cfg.Compression = p.Compression
	cfg.Modules = p.Modules
	return nil
}

type InConfig struct {
	Domain           string
	TLS              *tls.Config
	Transport        transport.Transport
	ConnectTimeout   time.Duration
	MaxStanzaSize    int
	ResourceConflict ResourceConflictPolicy
	SASL             []string
	Compression      CompressConfig
	Modules          ModulesConfig
}
