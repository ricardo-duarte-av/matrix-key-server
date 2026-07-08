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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/t2bot/matrix-key-server/api/api_models"
	"github.com/t2bot/matrix-key-server/db/models"
	"github.com/t2bot/matrix-key-server/federation"
	"github.com/t2bot/matrix-key-server/metrics"
	"github.com/t2bot/matrix-key-server/signing"
	"github.com/t2bot/matrix-key-server/util"
	"golang.org/x/crypto/ed25519"
)

// TrustedNotaries is the ordered list of notary server_names to consult when an
// origin server is unreachable. Set from configuration at startup.
var TrustedNotaries []string

// queryViaTrustedNotaries asks each configured trusted notary, in order, for the
// keys of an unreachable server. It returns the first cryptographically verified
// result (quorum of 1). A nil result with a nil error means no notary could help.
func queryViaTrustedNotaries(serverName models.ServerName, minValidUntilTs models.Timestamp) (*models.CachedRemoteKeys, error) {
	target := string(serverName)
	var lastErr error

	for _, notary := range TrustedNotaries {
		// Never ask a notary about itself, and never ask ourselves.
		if notary == "" || notary == SelfDomainName || notary == target {
			continue
		}

		notaryStart := time.Now()
		cached, err := queryOneNotary(notary, serverName, minValidUntilTs)
		if err != nil {
			metrics.ObserveNotaryFetch(notary, metrics.ResultFailure, time.Since(notaryStart))
			logrus.Warnf("Trusted notary %s could not provide keys for %s: %v", notary, target, err)
			lastErr = err
			continue
		}
		if cached == nil {
			metrics.ObserveNotaryFetch(notary, metrics.ResultFailure, time.Since(notaryStart))
			continue
		}
		metrics.ObserveNotaryFetch(notary, metrics.ResultSuccess, time.Since(notaryStart))

		logrus.Warnf("Obtained keys for %s via trusted notary %s (origin unreachable)", target, notary)
		return cached, nil
	}

	return nil, lastErr
}

// queryOneNotary fetches the target server's keys from a single notary and
// verifies both the origin's self-signature and the notary's counter-signature
// before storing them.
func queryOneNotary(notary string, serverName models.ServerName, minValidUntilTs models.Timestamp) (*models.CachedRemoteKeys, error) {
	target := string(serverName)

	// Fetch the notary's OWN keys directly - never through another notary - since
	// the notary's signature is the entire basis for trusting this response.
	notaryKeys, err := queryRemoteKeys(models.ServerName(notary), models.Timestamp(util.NowMillis()), false)
	if err != nil {
		return nil, fmt.Errorf("could not fetch notary %s own keys: %w", notary, err)
	}
	notaryPubKeys, err := notaryVerifyKeys(notaryKeys)
	if err != nil {
		return nil, err
	}
	if len(notaryPubKeys) == 0 {
		return nil, fmt.Errorf("notary %s has no usable verify keys", notary)
	}

	// Ask the notary for the target server's keys.
	baseUrl, hostname, err := federation.GetServerApiUrl(notary)
	if err != nil {
		return nil, err
	}
	queryUrl := fmt.Sprintf("%s/_matrix/key/v2/query/%s?minimum_valid_until_ts=%d",
		baseUrl, url.PathEscape(target), int64(minValidUntilTs))

	resp, err := federation.FederatedGet(queryUrl, hostname)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("notary %s returned status %d", notary, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		ServerKeys []json.RawMessage `json:"server_keys"`
	}
	if err = json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}

	for _, raw := range envelope.ServerKeys {
		keyInfo := api_models.ServerKeyResult{}
		if err = json.Unmarshal(raw, &keyInfo); err != nil {
			continue
		}
		if keyInfo.ServerName != target {
			continue
		}
		return verifyAndStoreNotaryResult(notary, keyInfo, raw, notaryPubKeys)
	}

	return nil, fmt.Errorf("notary %s did not return keys for %s", notary, target)
}

// verifyAndStoreNotaryResult verifies a single server-key object returned by a
// notary and persists it under the re-sign-only model (origin self-signature is
// kept, the notary's signature is discarded).
func verifyAndStoreNotaryResult(notary string, keyInfo api_models.ServerKeyResult, raw json.RawMessage, notaryPubKeys map[string]ed25519.PublicKey) (*models.CachedRemoteKeys, error) {
	verified, additionalFields, err := verifyNotaryResult(notary, keyInfo, raw, notaryPubKeys)
	if err != nil {
		return nil, err
	}
	return storeRemoteKeys(verified, additionalFields, notary)
}

// verifyNotaryResult checks that a notary's response for a server carries both
// the origin's self-signature and the notary's counter-signature, verifying both
// against the given notary keys. On success it returns the key object with its
// signatures reduced to just the origin's (re-sign-only model) along with any
// non-standard top-level fields. It performs no storage, so it is pure.
func verifyNotaryResult(notary string, keyInfo api_models.ServerKeyResult, raw json.RawMessage, notaryPubKeys map[string]ed25519.PublicKey) (api_models.ServerKeyResult, models.AdditionalJSON, error) {
	target := keyInfo.ServerName

	// The origin must have self-signed, and the notary must have counter-signed.
	if len(keyInfo.Signatures[target]) == 0 {
		return keyInfo, nil, fmt.Errorf("notary response for %s is missing the origin's self-signature", target)
	}
	if len(keyInfo.Signatures[notary]) == 0 {
		return keyInfo, nil, fmt.Errorf("notary %s did not sign its response for %s", notary, target)
	}

	// Reconstruct the full object (including any non-standard top-level fields)
	// for canonical-JSON verification, mirroring the direct-fetch path.
	additionalFields := models.AdditionalJSON{}
	fullyUnmarshalled := make(map[string]interface{})
	if err := json.Unmarshal(raw, &fullyUnmarshalled); err != nil {
		return keyInfo, nil, err
	}
	m, err := util.InterfaceToMap(keyInfo)
	if err != nil {
		return keyInfo, nil, err
	}
	for k, v := range fullyUnmarshalled {
		if _, ok := m[k]; !ok {
			additionalFields[k] = v
			m[k] = v
		}
	}

	// Verify against the origin's own keys (self-consistency) plus the notary's
	// keys (the trust anchor).
	publicKeys, err := grabPublicKeys(keyInfo)
	if err != nil {
		return keyInfo, nil, err
	}
	publicKeys[notary] = notaryPubKeys

	// VerifySignatures requires a key for every signing domain present, so drop
	// any third-party notary signatures we neither need nor can verify.
	if sigs, ok := m["signatures"].(map[string]interface{}); ok {
		for domain := range sigs {
			if domain != target && domain != notary {
				delete(sigs, domain)
			}
		}
	}

	if err = signing.VerifySignatures(m, publicKeys); err != nil {
		return keyInfo, nil, fmt.Errorf("signature verification failed for %s via notary %s: %w", target, notary, err)
	}

	// Re-sign-only: keep just the origin's self-signature. We do not persist or
	// re-serve the notary's signature; downstream trusts us, and we sign the
	// served response with our own key in findAndPrepareKeys.
	keyInfo.Signatures = api_models.Signatures{target: keyInfo.Signatures[target]}

	return keyInfo, additionalFields, nil
}

// notaryVerifyKeys extracts a notary's verify keys - both current and expired -
// from a cached key set, decoded for signature verification.
//
// Expired (old_verify_key) entries are included on purpose: a notary that cached
// a now-dead server long ago will have counter-signed that cached bundle with
// whatever key was current at the time, which may since have rotated into its
// old_verify_keys. Matrix already treats old_verify_keys as valid for verifying
// anything signed before their expiry, and we explicitly trust these notaries,
// so accepting their old keys is what makes the long-dead-server case work.
func notaryVerifyKeys(cached *models.CachedRemoteKeys) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey)
	for _, k := range cached.Keys {
		b, err := signing.DecodeUnpaddedBase64String(string(k.PublicKey))
		if err != nil {
			return nil, err
		}
		out[string(k.ID)] = ed25519.PublicKey(b)
	}
	return out, nil
}
