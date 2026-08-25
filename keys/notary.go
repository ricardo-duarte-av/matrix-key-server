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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/t2bot/matrix-key-server/api/api_models"
	"github.com/t2bot/matrix-key-server/db"
	"github.com/t2bot/matrix-key-server/db/models"
	"github.com/t2bot/matrix-key-server/federation"
	"github.com/t2bot/matrix-key-server/metrics"
	"github.com/t2bot/matrix-key-server/signing"
	"github.com/t2bot/matrix-key-server/util"
	"golang.org/x/crypto/ed25519"
)

func QueryRemoteKeys(serverName models.ServerName, minValidUntilTs models.Timestamp) (*models.CachedRemoteKeys, error) {
	return queryRemoteKeys(serverName, minValidUntilTs, true)
}

// remoteKeyLifespanMs is the maximum age of a cached record we will answer from
// without probing the origin, regardless of its valid_until_ts.
const remoteKeyLifespanMs = int64(604800000) // 7 days

// originBackoffLadder is how long we stand off from an origin after each
// consecutive failed probe. It replaces a pair of flat constants - a 1h refetch
// cooldown and a 24h archive re-check - both of which were reached after a
// single failure, so one transient 502 from a live server froze it out of origin
// probes for up to a day. The standoff is earned here rather than assumed: a
// blip costs minutes, while a genuinely gone server climbs to the same
// once-a-day probe the archive re-check used to give us, which is what keeps
// notary churn bounded.
var originBackoffLadder = []time.Duration{
	5 * time.Minute,
	15 * time.Minute,
	1 * time.Hour,
	6 * time.Hour,
	24 * time.Hour,
}

// transientOriginBackoff applies to the first few failures that prove the host
// is actually up - a 5xx from its reverse proxy. Those clear on their own far
// more often than not, so we re-probe within a minute instead of standing down.
const (
	transientOriginBackoff      = 1 * time.Minute
	transientOriginFailureLimit = 2
)

// originBackoff returns how long to wait before probing an origin again, given
// how many consecutive times it has now failed and whether the latest failure
// proved the host is still reachable.
func originBackoff(failures int, transient bool) time.Duration {
	if transient && failures <= transientOriginFailureLimit {
		return transientOriginBackoff
	}
	if failures < 1 {
		failures = 1
	}
	if failures > len(originBackoffLadder) {
		return originBackoffLadder[len(originBackoffLadder)-1]
	}
	return originBackoffLadder[failures-1]
}

// originStatusError reports that an origin answered us, but not with keys. It is
// kept distinct from a transport failure because it proves the host is up, which
// is what earns it the much shorter transient backoff.
type originStatusError struct {
	serverName models.ServerName
	statusCode int
}

func (e *originStatusError) Error() string {
	return fmt.Sprintf("origin %s returned status %d", e.serverName, e.statusCode)
}

// isTransientOriginFailure reports whether a failed probe left the host looking
// reachable - a 5xx from its reverse proxy - as opposed to a DNS, connection,
// TLS, or verification failure, which say nothing so reassuring.
func isTransientOriginFailure(err error) bool {
	var se *originStatusError
	if errors.As(err, &se) {
		return se.statusCode >= 500
	}
	return false
}

// isArchived reports whether a stored record is an archived snapshot of a gone
// server: obtained via a notary, and already expired even by that notary's
// reckoning. This is now purely descriptive - a metrics and logging label. It
// deliberately no longer gates any scheduling: "we last heard this from a
// notary" says nothing about whether the origin is worth asking again, and
// treating it as if it did is what froze live servers out for a day at a time.
func isArchived(s *models.RemoteServer, now int64) bool {
	return s != nil && s.ObtainedViaNotary != "" && int64(s.ValidUntilTs) < now
}

// isFresh reports whether a cached record answers a request outright, with no
// origin probe at all.
func isFresh(updatedTs, validUntilTs, minValidUntilTs, now int64) bool {
	isBeyondLifespan := now > updatedTs+remoteKeyLifespanMs
	isHalfwayDead := (updatedTs+validUntilTs)/2 < now
	isMinimallyAccepted := validUntilTs >= minValidUntilTs

	return isMinimallyAccepted && !isHalfwayDead && !isBeyondLifespan
}

// shouldProbeOrigin reports whether the origin may be contacted right now. It
// reads only the reachability columns: what we hold, and how stale it is, has no
// bearing on whether the origin is worth a request. An unknown server is always
// probed - that is the only way it becomes known.
func shouldProbeOrigin(s *models.RemoteServer, now int64) bool {
	return s == nil || now >= int64(s.NextOriginAttemptTs)
}

// heldSatisfies reports whether what we already hold answers the caller's
// request on its own terms, which is what decides whether a notary walk could
// still tell us anything we do not know.
func heldSatisfies(held *models.CachedRemoteKeys, minValidUntilTs models.Timestamp) bool {
	return held != nil && len(held.Keys) > 0 && held.ValidUntilTs >= minValidUntilTs
}

// queryRemoteKeys resolves a server's keys, optionally falling back to trusted
// notaries when the origin cannot answer. allowNotaryFallback must be false when
// resolving a notary's own keys, since trusting a notary's signature requires
// fetching that notary's keys directly (never through another notary).
//
// Two questions are answered independently here, and keeping them apart is the
// whole design: "what is the best thing we hold?" and "may we probe the origin
// right now?". The first is about key data and may legitimately be an expired
// archived bundle - serving those is the point of a reservoir. The second is
// about reachability alone, and lives in the origin backoff columns.
func queryRemoteKeys(serverName models.ServerName, minValidUntilTs models.Timestamp, allowNotaryFallback bool) (*models.CachedRemoteKeys, error) {
	s, err := db.GetRemoteServerMetadata(serverName)
	if err != nil {
		return nil, err
	}
	now := util.NowMillis()

	var held *models.CachedRemoteKeys
	if s != nil {
		if held, err = packageCachedKeysFor(s); err != nil {
			return nil, err
		}
	}

	// Fast path: what we hold already answers the request outright.
	if held != nil && isFresh(int64(s.UpdatedTs), int64(s.ValidUntilTs), int64(minValidUntilTs), now) {
		metrics.RecordKeyQuery(metrics.OutcomeCacheFresh)
		return held, nil
	}

	// Stale or expired, but the origin is inside its backoff. Serve what we hold
	// rather than re-probing a host that just told us it cannot help.
	if !shouldProbeOrigin(s, now) {
		if isArchived(s, now) {
			metrics.RecordKeyQuery(metrics.OutcomeArchiveServed)
		} else {
			metrics.RecordKeyQuery(metrics.OutcomeCacheCooldown)
		}
		return held, nil
	}

	// TODO: Rate limit: https://github.com/turt2live/matrix-key-server/issues/2
	result, err := probeOrigin(serverName, s, now)
	if err == nil {
		metrics.RecordKeyQuery(metrics.OutcomeOriginSuccess)
		return result, nil
	}

	// Ask the notaries only when what we hold cannot answer this request anyway.
	// A notary walk costs several federated round-trips per notary, and when our
	// stored bundle already satisfies the caller it buys nothing. Reaching here
	// at all is gated by the origin backoff, so a long-dead server costs one walk
	// per probe tick rather than one per request.
	if allowNotaryFallback && !heldSatisfies(held, minValidUntilTs) {
		cached, nErr := queryViaTrustedNotaries(serverName, minValidUntilTs)
		if nErr != nil {
			logrus.Warnf("Notary fallback for %s failed: %v", serverName, nErr)
		} else if cached != nil {
			metrics.RecordKeyQuery(metrics.OutcomeNotarySuccess)
			return cached, nil
		}
	}

	// Neither the origin nor a notary could improve on what we have. Serve the
	// reservoir copy, expired or not.
	if held != nil && len(held.Keys) > 0 {
		metrics.RecordKeyQuery(metrics.OutcomeAllFailedStale)
		return held, nil
	}

	// The server is dead and we hold no keys anywhere. NoteOriginFailure above has
	// already persisted the row, so the backoff covers this case too.
	metrics.RecordKeyQuery(metrics.OutcomeAllFailedEmpty)
	return &models.CachedRemoteKeys{
		Keys:       make([]*models.RemoteKey, 0),
		Signatures: make([]*models.RemoteSignature, 0),
		RemoteServer: &models.RemoteServer{
			ServerName:   serverName,
			ValidUntilTs: models.Timestamp(now),
			UpdatedTs:    models.Timestamp(now),
		},
	}, nil
}

// probeOrigin fetches a server's keys straight from the origin and records the
// outcome against that origin's backoff schedule. Both the request path and the
// background sweeper go through here, so there is exactly one place that decides
// how long to stand off from a failing host and the two cannot drift apart.
//
// On success, storeRemoteKeys clears the standoff; on failure the next probe is
// scheduled here, before the caller does anything else with the error, so the
// standoff holds however the caller's fallbacks turn out.
func probeOrigin(serverName models.ServerName, s *models.RemoteServer, now int64) (*models.CachedRemoteKeys, error) {
	originStart := time.Now()
	result, err := fetchDirectFromOrigin(serverName)
	if err == nil {
		metrics.ObserveOriginFetch(metrics.ResultSuccess, time.Since(originStart))
		return result, nil
	}
	metrics.ObserveOriginFetch(metrics.ResultFailure, time.Since(originStart))
	logrus.Warnf("Could not fetch keys for %s directly from the origin: %v", serverName, err)

	// A never-seen server has no failure history, so this is its first.
	failures := 1
	if s != nil {
		failures = s.OriginFailures + 1
	}
	backoff := originBackoff(failures, isTransientOriginFailure(err))
	if fErr := db.NoteOriginFailure(serverName, models.Timestamp(now), failures, models.Timestamp(now+backoff.Milliseconds())); fErr != nil {
		logrus.Warnf("Could not record origin failure for %s: %v", serverName, fErr)
	}
	logrus.Infof("Origin %s has failed %d consecutive probe(s); next probe in %s", serverName, failures, backoff)

	return nil, err
}

// fetchDirectFromOrigin resolves and fetches a server's keys straight from the
// origin, verifies the self-signature, and caches them. It returns an error if
// the server cannot be reached or the response fails verification.
func fetchDirectFromOrigin(serverName models.ServerName) (*models.CachedRemoteKeys, error) {
	url, hostname, err := federation.GetServerApiUrl(string(serverName))
	if err != nil {
		return nil, err
	}

	keysUrl := url + "/_matrix/key/v2/server"
	keysResponse, err := federation.FederatedGet(keysUrl, hostname)
	if err != nil {
		return nil, err
	}
	defer keysResponse.Body.Close()

	// Plenty of hosts answer this endpoint with an error document (or an HTML
	// error page from a reverse proxy) rather than keys. Reject on status before
	// parsing so those never reach the decode path.
	if keysResponse.StatusCode != http.StatusOK {
		return nil, &originStatusError{serverName: serverName, statusCode: keysResponse.StatusCode}
	}

	c, err := federation.ReadResponseBody(keysResponse.Body)
	if err != nil {
		return nil, err
	}

	keyInfo := api_models.ServerKeyResult{}
	err = json.Unmarshal(c, &keyInfo)
	if err != nil {
		return nil, err
	}
	if err = keyInfo.Validate(); err != nil {
		return nil, fmt.Errorf("origin %s returned an unusable key response: %w", serverName, err)
	}

	publicKeys, err := grabPublicKeys(keyInfo)
	if err != nil {
		return nil, err
	}

	additionalFields := models.AdditionalJSON{}
	fullyUnmarshalled := make(map[string]interface{})
	err = json.Unmarshal(c, &fullyUnmarshalled)
	if err != nil {
		return nil, err
	}
	m, err := util.InterfaceToMap(keyInfo)
	if err != nil {
		return nil, err
	}
	for k, v := range fullyUnmarshalled {
		if _, ok := m[k]; !ok {
			additionalFields[k] = v
			m[k] = v
		}
	}

	err = signing.VerifySignatures(m, publicKeys)
	if err != nil {
		return nil, err
	}

	return storeRemoteKeys(keyInfo, additionalFields, "")
}

func packageCachedKeysFor(server *models.RemoteServer) (*models.CachedRemoteKeys, error) {
	keys, err := db.GetAllRemoteServerKeys(server.ServerName)
	if err != nil {
		return nil, err
	}

	sigs, err := db.GetAllRemoteServerSignatures(server.ServerName)
	if err != nil {
		return nil, err
	}

	return &models.CachedRemoteKeys{
		RemoteServer: server,
		Keys:         keys,
		Signatures:   sigs,
	}, nil
}

func storeRemoteKeys(keyInfo api_models.ServerKeyResult, additionalJson models.AdditionalJSON, obtainedViaNotary string) (*models.CachedRemoteKeys, error) {
	now := util.NowMillis()
	serverName := models.ServerName(keyInfo.ServerName)

	// Upgrade rule. The reservoir must never lose keys, and the write path below
	// deletes-then-reinserts, so a thinner or older reply must not land on top of
	// a richer one. The origin is authoritative about its own keys and always
	// wins; a notary must prove it is offering something strictly fresher than
	// what we already hold, whatever the provenance of that is.
	//
	// This replaces a narrower freeze that only protected records classed as
	// archived, which inherited that classification's false "server is gone"
	// reading and left ordinary stale records unprotected.
	if existing, err := db.GetRemoteServerMetadata(serverName); err == nil && existing != nil {
		if obtainedViaNotary != "" && models.Timestamp(keyInfo.ValidUntilTs) <= existing.ValidUntilTs {
			logrus.Infof("Keeping stored keys for %s: notary %s offered nothing newer than what we hold", serverName, obtainedViaNotary)
			return packageCachedKeysFor(existing)
		}
	}

	res := &models.CachedRemoteKeys{
		RemoteServer: &models.RemoteServer{
			ServerName:        serverName,
			UpdatedTs:         models.Timestamp(now),
			ValidUntilTs:      models.Timestamp(keyInfo.ValidUntilTs),
			NonStandardJSON:   additionalJson,
			ObtainedViaNotary: obtainedViaNotary,
		},
		Keys:       make([]*models.RemoteKey, 0),
		Signatures: make([]*models.RemoteSignature, 0),
	}

	err := db.UpsertRemoteServer(res.ServerName, res.UpdatedTs, res.ValidUntilTs, additionalJson, obtainedViaNotary)
	if err != nil {
		return nil, err
	}

	err = db.DeleteRemoteServerKeys(res.ServerName)
	if err != nil {
		return nil, err
	}

	err = db.DeleteRemoteServerSignatures(res.ServerName)
	if err != nil {
		return nil, err
	}

	// The origin answered us directly, so it is healthy: clear any standoff a
	// previous failure left behind.
	if obtainedViaNotary == "" {
		if rErr := db.ResetOriginProbe(res.ServerName); rErr != nil {
			logrus.Warnf("Could not reset origin probe schedule for %s: %v", res.ServerName, rErr)
		}
	}

	for keyId, key := range keyInfo.VerifyKeys {
		cachedKey := &models.RemoteKey{
			ServerName: res.ServerName,
			ID:         models.KeyID(keyId),
			PublicKey:  models.UnpaddedBase64EncodedData(key.Key),
			ExpiresTs:  models.Timestamp(0),
		}
		err = db.AddRemoteServerKey(cachedKey.ServerName, cachedKey.ID, cachedKey.PublicKey, cachedKey.ExpiresTs)
		if err != nil {
			return nil, err
		}
		res.Keys = append(res.Keys, cachedKey)
	}

	for keyId, key := range keyInfo.OldVerifyKeys {
		cachedKey := &models.RemoteKey{
			ServerName: res.ServerName,
			ID:         models.KeyID(keyId),
			PublicKey:  models.UnpaddedBase64EncodedData(key.Key),
			ExpiresTs:  models.Timestamp(key.ExpiredTs),
		}
		err = db.AddRemoteServerKey(cachedKey.ServerName, cachedKey.ID, cachedKey.PublicKey, cachedKey.ExpiresTs)
		if err != nil {
			return nil, err
		}
		res.Keys = append(res.Keys, cachedKey)
	}

	for _, sig := range keyInfo.Signatures {
		for keyId, signature := range sig {
			cachedSignature := &models.RemoteSignature{
				ServerName: res.ServerName,
				KeyID:      models.KeyID(keyId),
				Signature:  models.UnpaddedBase64EncodedData(signature),
			}
			err = db.AddRemoteServerSignature(cachedSignature.ServerName, cachedSignature.KeyID, cachedSignature.Signature)
			if err != nil {
				return nil, err
			}
			res.Signatures = append(res.Signatures, cachedSignature)
		}
	}

	return res, nil
}

func grabPublicKeys(keyInfo api_models.ServerKeyResult) (map[string]map[string]ed25519.PublicKey, error) {
	keys := make(map[string]map[string]ed25519.PublicKey)
	keys[keyInfo.ServerName] = make(map[string]ed25519.PublicKey)
	for keyId, encodedKey := range keyInfo.VerifyKeys {
		b, err := signing.DecodeUnpaddedBase64String(string(encodedKey.Key))
		if err != nil {
			return nil, err
		}

		keys[keyInfo.ServerName][string(keyId)] = ed25519.PublicKey(b)
	}

	return keys, nil
}
