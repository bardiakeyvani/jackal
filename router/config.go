/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package router

import (
	"crypto/tls"

	"github.com/ortuman/jackal/util"
)

// TLSConfig represents a host TLS configuration.
type TLSConfig struct {
	CertFile    string `yaml:"cert_path"`
	PrivKeyFile string `yaml:"privkey_path"`
}

type HostConfig struct {
	Name        string
	Certificate tls.Certificate
}

type hostConfigProxy struct {
	Name string    `yaml:"name"`
	TLS  TLSConfig `yaml:"tls"`
}

// UnmarshalYAML satisfies Unmarshaler interface.
func (c *HostConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	p := hostConfigProxy{}
	if err := unmarshal(&p); err != nil {
		return err
	}
	c.Name = p.Name
	cer, err := util.LoadCertificate(p.TLS.PrivKeyFile, p.TLS.CertFile, c.Name)
	if err != nil {
		return err
	}
	c.Certificate = cer
	return nil
}
