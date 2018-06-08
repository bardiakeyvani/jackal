/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"time"

	"github.com/ortuman/jackal/log"
	"github.com/ortuman/jackal/router"
	"github.com/ortuman/jackal/s2s"
	"github.com/ortuman/jackal/server"
	"github.com/ortuman/jackal/storage"
	"github.com/ortuman/jackal/stream"
	"github.com/ortuman/jackal/version"
)

var logoStr = []string{
	`        __               __            __   `,
	`       |__|____    ____ |  | _______  |  |  `,
	`       |  \__  \ _/ ___\|  |/ /\__  \ |  |  `,
	`       |  |/ __ \\  \___|    <  / __ \|  |__`,
	`   /\__|  (____  /\___  >__|_ \(____  /____/`,
	`   \______|    \/     \/     \/     \/      `,
}

const usageStr = `
Usage: jackal [options]

Server Options:
    -c, --config <file>    Configuration file path
Common Options:
    -h, --help             Show this message
    -v, --version          Show version
`

func main() {
	var configFile string
	var showVersion bool
	var showUsage bool

	flag.BoolVar(&showUsage, "help", false, "Show this message")
	flag.BoolVar(&showUsage, "h", false, "Show this message")
	flag.BoolVar(&showVersion, "version", false, "Print version information.")
	flag.BoolVar(&showVersion, "v", false, "Print version information.")
	flag.StringVar(&configFile, "config", "/etc/jackal/jackal.yml", "Configuration file path.")
	flag.StringVar(&configFile, "c", "/etc/jackal/jackal.yml", "Configuration file path.")
	flag.Usage = func() {
		for i := range logoStr {
			fmt.Fprintf(os.Stdout, "%s\n", logoStr[i])
		}
		fmt.Fprintf(os.Stdout, "%s\n", usageStr)
	}
	flag.Parse()

	// print usage
	if showUsage {
		flag.Usage()
		return
	}

	// print version
	if showVersion {
		fmt.Fprintf(os.Stdout, "jackal version: %v\n", version.ApplicationVersion)
		return
	}

	// load configuration
	var cfg Config
	if err := cfg.FromFile(configFile); err != nil {
		fmt.Fprintf(os.Stderr, "jackal: %v\n", err)
		return
	}
	if len(cfg.Servers) == 0 {
		fmt.Fprint(os.Stderr, "jackal: couldn't find a server configuration\n")
		return
	}

	// initialize subsystems
	log.Initialize(&cfg.Logger)

	router.Initialize(&cfg.Router, nil)

	storage.Initialize(&cfg.Storage)

	testS2S()

	// create PID file
	if err := createPIDFile(cfg.PIDFile); err != nil {
		log.Warnf("%v", err)
	}
	// start serving...
	for i := range logoStr {
		log.Infof("%s", logoStr[i])
	}
	log.Infof("")
	log.Infof("jackal %v\n", version.ApplicationVersion)

	server.Initialize(cfg.Servers, cfg.Debug.Port)
}

var s2sOut stream.S2SOut

func testS2S() {
	opts := stream.S2SDialerOptions{KeepAlive: time.Duration(120) * time.Second}
	out, err := s2s.Dial("", "jabber.org", &opts)
	if err != nil {
		log.Error(err)
		return
	}
	s2sOut = out
	s2sOut.Start()
}

func createPIDFile(pidFile string) error {
	if len(pidFile) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(pidFile), os.ModePerm); err != nil {
		return err
	}
	file, err := os.Create(pidFile)
	if err != nil {
		return err
	}
	currentPid := os.Getpid()
	if _, err := file.WriteString(strconv.FormatInt(int64(currentPid), 10)); err != nil {
		return err
	}
	return nil
}
