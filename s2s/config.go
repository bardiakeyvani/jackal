/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

type TransportConfig struct {
	BindAddress string `yaml:"bind_addr"`
	Port        int    `yaml:"port"`
	KeepAlive   int    `yaml:"keep_alive"`
}

type Config struct {
	Disabled  bool            `yaml:"disabled"`
	Transport TransportConfig `yaml:"transport"`
}
