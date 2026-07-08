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
	"io"
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

// remoteRefetchCooldownMs bounds how often we re-attempt a live fetch (origin
// then trusted notaries) for a server whose cached keys are stale or expired.
// Without it, a long-dead server whose keys have lapsed fails the freshness gate
// on every request and triggers a full origin timeout plus a notary round-trip
// each time. Within the cooldown we serve the last thing we stored - expired or
// not - instead of pinging the notaries again.
const remoteRefetchCooldownMs = int64(3600000) // 1 hour

// remoteKeyLifespanMs is the maximum age of a cached record we will ever serve
// from, regardless of its valid_until_ts.
const remoteKeyLifespanMs = int64(604800000) // 7 days

// remoteArchiveRecheckMs is the (long) backoff for archived servers - ones a
// notary could only serve from a frozen, already-expired copy, meaning the
// origin is gone and the data is static. We keep serving our stored snapshot and
// re-attempt a refresh at most this often, purely as cheap insurance in case the
// server revives.
const remoteArchiveRecheckMs = int64(86400000) // 24 hours

// isArchived reports whether a stored record is an archived snapshot of a gone
// server: it was obtained via a notary (the origin was unreachable) and the
// notary itself could only vouch with an already-expired valid_until_ts. Such a
// record is treated as an immutable historical artifact - see storeRemoteKeys,
// which refuses to overwrite it with anything but a genuinely fresher snapshot.
func isArchived(s *models.RemoteServer, now int64) bool {
	return s != nil && s.ObtainedViaNotary != "" && int64(s.ValidUntilTs) < now
}

// serveDecision describes whether, and on what basis, a cached remote-server
// record can satisfy a request without a live refetch.
type serveDecision int

const (
	// serveNone means the cache cannot be served and a live refetch is required.
	serveNone serveDecision = iota
	// serveFresh means the cache passed the freshness gate.
	serveFresh
	// serveCooldown means the cache is stale/expired but we attempted a refresh
	// within the cooldown window, so we serve it rather than refetch.
	serveCooldown
)

// canServeCachedKeys decides whether a cached remote-server record can satisfy a
// request without a live refetch. It returns serveFresh when the cache is fresh
// enough per the freshness gate, serveCooldown when the cache is stale/expired
// but we attempted a refresh within remoteRefetchCooldownMs (which stops a
// long-dead server from triggering a full origin timeout plus notary round-trip
// on every request), or serveNone when a refetch is required.
func canServeCachedKeys(updatedTs, validUntilTs, minValidUntilTs, now int64) serveDecision {
	isBeyondLifespan := now > updatedTs+remoteKeyLifespanMs
	isHalfwayDead := (updatedTs+validUntilTs)/2 < now
	isMinimallyAccepted := validUntilTs >= minValidUntilTs

	if isMinimallyAccepted && !isHalfwayDead && !isBeyondLifespan {
		return serveFresh
	}

	// Stale or expired, but we tried to refresh recently: serve what we last
	// stored rather than hammering a likely-dead origin and the notaries again.
	if now < updatedTs+remoteRefetchCooldownMs {
		return serveCooldown
	}

	return serveNone
}

// queryRemoteKeys resolves a server's keys, optionally falling back to trusted
// notaries when the origin is unreachable. allowNotaryFallback must be false
// when resolving a notary's own keys, since trusting a notary's signature
// requires fetching that notary's keys directly (never through another notary).
func queryRemoteKeys(serverName models.ServerName, minValidUntilTs models.Timestamp, allowNotaryFallback bool) (*models.CachedRemoteKeys, error) {
	s, err := db.GetRemoteServerMetadata(serverName)
	if err != nil {
		return nil, err
	}
	now := util.NowMillis()
	if s != nil {
		switch canServeCachedKeys(int64(s.UpdatedTs), int64(s.ValidUntilTs), int64(minValidUntilTs), now) {
		case serveFresh:
			metrics.RecordKeyQuery(metrics.OutcomeCacheFresh)
			return packageCachedKeysFor(s)
		case serveCooldown:
			metrics.RecordKeyQuery(metrics.OutcomeCacheCooldown)
			return packageCachedKeysFor(s)
		}

		// The record is an archived snapshot of a gone server. Its keys are
		// static, so serve them straight from the store and only re-attempt a
		// refresh on the long archive backoff - no per-request notary churn.
		if isArchived(s, now) && now < int64(s.UpdatedTs)+remoteArchiveRecheckMs {
			metrics.RecordKeyQuery(metrics.OutcomeArchiveServed)
			return packageCachedKeysFor(s)
		}
	}

	// Cache miss, stale, and past the refetch cooldown: try the origin directly.
	// TODO: Rate limit: https://github.com/turt2live/matrix-key-server/issues/2
	originStart := time.Now()
	result, err := fetchDirectFromOrigin(serverName)
	if err == nil {
		metrics.ObserveOriginFetch(metrics.ResultSuccess, time.Since(originStart))
		metrics.RecordKeyQuery(metrics.OutcomeOriginSuccess)
		return result, nil
	}
	metrics.ObserveOriginFetch(metrics.ResultFailure, time.Since(originStart))
	logrus.Warnf("Could not fetch keys for %s directly from the origin: %v", serverName, err)

	// The origin is unreachable or gave us an unusable response. Before giving up
	// (or serving a stale copy), ask the configured trusted notaries whether they
	// still hold these keys. Skipped when resolving a notary's own keys.
	if allowNotaryFallback {
		cached, nErr := queryViaTrustedNotaries(serverName, minValidUntilTs)
		if nErr != nil {
			logrus.Warnf("Notary fallback for %s failed: %v", serverName, nErr)
		} else if cached != nil {
			metrics.RecordKeyQuery(metrics.OutcomeNotarySuccess)
			return cached, nil
		}
	}

	if s != nil {
		// Neither the origin nor a notary could help. Serve the last known
		// response and record the failed attempt so the cooldown suppresses
		// repeated origin/notary round-trips until it elapses.
		if err := db.TouchRemoteServer(serverName, models.Timestamp(now)); err != nil {
			logrus.Warnf("Could not update refresh timestamp for %s: %v", serverName, err)
		}
		metrics.RecordKeyQuery(metrics.OutcomeAllFailedStale)
		return packageCachedKeysFor(s)
	}

	// The server is dead and we have no keys anywhere. Persist a negative-cache
	// entry so the cooldown applies here too and we stop re-querying the notaries
	// for a server nobody can resolve.
	if err := db.UpsertRemoteServer(serverName, models.Timestamp(now), models.Timestamp(now), models.AdditionalJSON{}, ""); err != nil {
		logrus.Warnf("Could not persist negative cache entry for %s: %v", serverName, err)
	}
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

	c, err := io.ReadAll(keysResponse.Body)
	if err != nil {
		return nil, err
	}

	keyInfo := api_models.ServerKeyResult{}
	err = json.Unmarshal(c, &keyInfo)
	if err != nil {
		return nil, err
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

	// Freeze protection: never overwrite an archived (gone-server) snapshot with a
	// non-upgrade. Its keys are an immutable historical artifact, and the write
	// path below deletes-then-reinserts, so a thinner notary reply would silently
	// drop keys we may be the last to hold. Only a genuinely fresher snapshot
	// (later valid_until_ts, e.g. a revived server) is allowed to replace it. We
	// still bump updated_ts so the archive re-check backoff is honoured.
	if existing, err := db.GetRemoteServerMetadata(serverName); err == nil &&
		isArchived(existing, now) && models.Timestamp(keyInfo.ValidUntilTs) <= existing.ValidUntilTs {
		if tErr := db.TouchRemoteServer(serverName, models.Timestamp(now)); tErr != nil {
			logrus.Warnf("Could not update refresh timestamp for archived server %s: %v", serverName, tErr)
		}
		logrus.Infof("Keeping frozen archived snapshot for %s (incoming valid_until_ts is not newer)", serverName)
		return packageCachedKeysFor(existing)
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
