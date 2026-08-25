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

package keys

import (
	"time"

	"github.com/sirupsen/logrus"
	"github.com/t2bot/matrix-key-server/db"
	"github.com/t2bot/matrix-key-server/db/models"
	"github.com/t2bot/matrix-key-server/util"
)

// originSweepInterval is how often we look for origins due another probe. It
// only bounds how promptly a due probe is noticed - how often any given origin
// is actually contacted is decided by its own backoff ladder, not by this.
const originSweepInterval = 1 * time.Minute

// originSweepBatch caps how many origins one tick may probe. Each probe is a
// federated round-trip, so this bounds the outbound burst when a large number of
// servers come due together - after a restart, or when a shared host recovers.
// Anything left over is simply picked up by the next tick, oldest due first.
const originSweepBatch = 25

// StartOriginSweeper heals notary-sourced and unresolved records in the
// background, so a server we fell back on recovers without waiting for someone
// to ask about it again.
//
// The request path already re-probes a due origin, but only when a request
// happens to arrive for that server. For a key server that is the wrong way
// round: the request that triggers the repair is the one that pays for it, and
// meanwhile every request in between is answered from a notary copy. Sweeping
// ahead of demand means the repair lands before anyone asks.
//
// It is naturally self-limiting. Candidates are drawn from the origin backoff
// schedule, so a healthy server never appears here, a healed one drops out the
// moment its standoff is cleared, and a long-dead one is offered at most once a
// day once its ladder tops out.
func StartOriginSweeper() {
	go func() {
		for range time.Tick(originSweepInterval) {
			sweepOriginsOnce()
		}
	}()
}

// sweepOriginsOnce probes every origin currently due, up to the batch cap, and
// reports how many recovered. Split out from the ticker so it can be driven
// directly in a test or from a one-shot at startup.
func sweepOriginsOnce() (attempted int, recovered int) {
	candidates, err := db.GetOriginProbeCandidates(models.Timestamp(util.NowMillis()), originSweepBatch)
	if err != nil {
		logrus.Warnf("Could not list origins due for a probe: %v", err)
		return 0, 0
	}
	if len(candidates) == 0 {
		return 0, 0
	}

	logrus.Infof("Sweeping %d origin(s) due for a re-probe", len(candidates))
	for _, serverName := range candidates {
		// Re-read each record immediately before probing rather than trusting the
		// listing: a request may have probed this same server in the meantime, and
		// the failure count we pass decides the next standoff.
		s, err := db.GetRemoteServerMetadata(serverName)
		if err != nil {
			logrus.Warnf("Could not load %s for an origin sweep: %v", serverName, err)
			continue
		}
		now := util.NowMillis()
		if !shouldProbeOrigin(s, now) {
			continue
		}

		attempted++
		if _, err := probeOrigin(serverName, s, now); err == nil {
			recovered++
			logrus.Infof("Origin %s is reachable again; serving its keys directly", serverName)
		}
	}

	if recovered > 0 {
		logrus.Infof("Origin sweep recovered %d of %d server(s)", recovered, attempted)
	}
	return attempted, recovered
}
