/*
 * Copyright 2019 Travis Ralston <travis@t2bot.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"os"
	"strings"
	"time"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"
	"github.com/t2bot/matrix-key-server/api"
	"github.com/t2bot/matrix-key-server/db"
	"github.com/t2bot/matrix-key-server/keys"
	"github.com/t2bot/matrix-key-server/logging"
	"github.com/t2bot/matrix-key-server/metrics"
)

func main() {
	logging.Setup()
	logrus.Info("Starting up...")

	domainName := flag.String("domain", "localhost", "The domain name for the key server")
	pgUrl := flag.String("postgres", "postgres://username:password@localhost/dbname?sslmode=disable", "PostgreSQL database URI")
	listenHost := flag.String("address", "0.0.0.0", "Address to listen for requests on")
	listenPort := flag.Int("port", 8080, "Port to listen for requests on")
	notaries := flag.String("notaries", "matrix.org,tchncs.de,unredacted.org", "Comma-separated list of trusted notary servers to consult when an origin server is unreachable")
	flag.Parse()

	logrus.Info("Preparing database...")
	var err error
	if strings.HasPrefix(*pgUrl, "/run/secrets") {
		var b []byte
		b, err = os.ReadFile(*pgUrl)
		if err != nil {
			logrus.Fatal(err)
		}
		err = db.Setup(strings.TrimSpace(string(b)))
	} else {
		err = db.Setup(*pgUrl)
	}
	if err != nil {
		logrus.Fatal(err)
	}

	keys.SelfDomainName = *domainName
	logrus.Infof("This server's domain is %s", keys.SelfDomainName)

	keys.TrustedNotaries = parseNotaries(*notaries, keys.SelfDomainName)
	logrus.Infof("Trusted notaries: %v", keys.TrustedNotaries)

	logrus.Info("Preparing own signing key...")
	err = prepareOwnKey()
	if err != nil {
		logrus.Fatal(err)
	}

	startKnownServerGauges()
	keys.StartOriginSweeper()

	logrus.Info("Starting app...")
	api.Run(*listenHost, *listenPort)
}

// knownServerRefreshInterval is how often the cached-server gauges are recomputed
// from the database. These counts move only as fast as keys are fetched, so a
// coarse interval keeps the aggregate query off the scrape path.
const knownServerRefreshInterval = 60 * time.Second

// startKnownServerGauges publishes the direct/notary server counts once, then
// keeps them refreshed in the background so a scrape never has to wait on a
// database aggregate.
func startKnownServerGauges() {
	refresh := func() {
		direct, viaNotary, unreachable, err := db.CountKnownServers()
		if err != nil {
			logrus.Warnf("Could not refresh known-server gauges: %v", err)
			return
		}
		metrics.SetKnownServers(direct, viaNotary, unreachable)
	}

	refresh()
	go func() {
		for range time.Tick(knownServerRefreshInterval) {
			refresh()
		}
	}()
}

// parseNotaries splits a comma-separated notary list, trimming whitespace and
// dropping empties, duplicates, and this server's own domain.
func parseNotaries(raw string, self string) []string {
	seen := make(map[string]bool)
	notaries := make([]string, 0)
	for _, n := range strings.Split(raw, ",") {
		n = strings.TrimSpace(n)
		if n == "" || n == self || seen[n] {
			continue
		}
		seen[n] = true
		notaries = append(notaries, n)
	}
	return notaries
}

func prepareOwnKey() error {
	key, err := keys.GetSelfKey()
	if err != nil {
		return err
	}

	logrus.Infof("Using key %s as the preferred key for this server", key.ID)
	return nil
}
