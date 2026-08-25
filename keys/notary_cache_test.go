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
	"fmt"
	"testing"
	"time"

	"github.com/t2bot/matrix-key-server/db/models"
)

const testNow = int64(1_000_000_000_000)
const testDay = int64(86_400_000)

func TestIsFresh(t *testing.T) {
	tests := []struct {
		name         string
		updatedTs    int64
		validUntilTs int64
		minValidTs   int64
		want         bool
	}{
		{
			name:         "fetched recently and valid well into the future",
			updatedTs:    testNow - testDay,
			validUntilTs: testNow + 10*testDay,
			minValidTs:   testNow,
			want:         true,
		},
		{
			name:         "expired keys are never fresh",
			updatedTs:    testNow - 60_000,
			validUntilTs: testNow - testDay,
			minValidTs:   testNow,
			want:         false,
		},
		{
			name:         "valid, but below the caller's minimum",
			updatedTs:    testNow - 60_000,
			validUntilTs: testNow + testDay,
			minValidTs:   testNow + 5*testDay,
			want:         false,
		},
		{
			name:         "past the halfway point of its own validity",
			updatedTs:    testNow - 10*testDay,
			validUntilTs: testNow + testDay,
			minValidTs:   testNow,
			want:         false,
		},
		{
			name:         "beyond the 7-day lifespan even though still valid",
			updatedTs:    testNow - 8*testDay,
			validUntilTs: testNow + 10*testDay,
			minValidTs:   testNow,
			want:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isFresh(tc.updatedTs, tc.validUntilTs, tc.minValidTs, testNow)
			if got != tc.want {
				t.Errorf("isFresh(updated=%d, valid=%d, min=%d, now=%d) = %v, want %v",
					tc.updatedTs, tc.validUntilTs, tc.minValidTs, testNow, got, tc.want)
			}
		})
	}
}

// TestShouldProbeOriginIgnoresKeyData is the crux of the split: whether an
// origin may be probed must depend on the origin's own failure history and
// nothing else. Expired keys, or keys last heard from a notary, previously
// suppressed probing and froze live servers out for up to a day.
func TestShouldProbeOriginIgnoresKeyData(t *testing.T) {
	tests := []struct {
		name string
		s    *models.RemoteServer
		want bool
	}{
		{
			name: "unknown server is always probed",
			s:    nil,
			want: true,
		},
		{
			name: "standoff has elapsed",
			s:    &models.RemoteServer{NextOriginAttemptTs: models.Timestamp(testNow - 1)},
			want: true,
		},
		{
			name: "standoff is still in force",
			s:    &models.RemoteServer{NextOriginAttemptTs: models.Timestamp(testNow + 60_000)},
			want: false,
		},
		{
			name: "expired notary-sourced keys do not block a due probe",
			s: &models.RemoteServer{
				ObtainedViaNotary:   "matrix.org",
				ValidUntilTs:        models.Timestamp(testNow - 200*testDay),
				NextOriginAttemptTs: models.Timestamp(testNow),
			},
			want: true,
		},
		{
			name: "perfectly good keys do not earn an early probe",
			s: &models.RemoteServer{
				ValidUntilTs:        models.Timestamp(testNow + 10*testDay),
				NextOriginAttemptTs: models.Timestamp(testNow + 60_000),
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldProbeOrigin(tc.s, testNow); got != tc.want {
				t.Errorf("shouldProbeOrigin(%+v, %d) = %v, want %v", tc.s, testNow, got, tc.want)
			}
		})
	}
}

func TestOriginBackoff(t *testing.T) {
	tests := []struct {
		failures  int
		transient bool
		want      time.Duration
	}{
		// A 502 from a live host: re-probe within the minute. This is the
		// ryuu.eu case, which used to cost a 24h freeze.
		{failures: 1, transient: true, want: time.Minute},
		{failures: 2, transient: true, want: time.Minute},
		// Still failing after the transient allowance: join the ladder.
		{failures: 3, transient: true, want: time.Hour},
		// Unreachable host: the ordinary ladder from the first failure.
		{failures: 1, transient: false, want: 5 * time.Minute},
		{failures: 2, transient: false, want: 15 * time.Minute},
		{failures: 3, transient: false, want: time.Hour},
		{failures: 4, transient: false, want: 6 * time.Hour},
		{failures: 5, transient: false, want: 24 * time.Hour},
		// A long-gone server settles at one probe a day, which is the
		// protection the old flat archive re-check provided.
		{failures: 50, transient: false, want: 24 * time.Hour},
		{failures: 50, transient: true, want: 24 * time.Hour},
		// Defensive: a nonsensical count must not index out of range.
		{failures: 0, transient: false, want: 5 * time.Minute},
		{failures: -1, transient: false, want: 5 * time.Minute},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("failures=%d/transient=%v", tc.failures, tc.transient), func(t *testing.T) {
			if got := originBackoff(tc.failures, tc.transient); got != tc.want {
				t.Errorf("originBackoff(%d, %v) = %s, want %s", tc.failures, tc.transient, got, tc.want)
			}
		})
	}
}

func TestIsTransientOriginFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "502 from a reverse proxy proves the host is up",
			err:  &originStatusError{serverName: "ryuu.eu", statusCode: 502},
			want: true,
		},
		{
			name: "503 likewise",
			err:  &originStatusError{serverName: "ryuu.eu", statusCode: 503},
			want: true,
		},
		{
			name: "404 is the host answering definitively",
			err:  &originStatusError{serverName: "ryuu.eu", statusCode: 404},
			want: false,
		},
		{
			name: "a transport failure says nothing reassuring",
			err:  fmt.Errorf("dial tcp: connection refused"),
			want: false,
		},
		{
			name: "wrapped status errors are still recognised",
			err:  fmt.Errorf("probing: %w", &originStatusError{serverName: "ryuu.eu", statusCode: 500}),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientOriginFailure(tc.err); got != tc.want {
				t.Errorf("isTransientOriginFailure(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestHeldSatisfies covers the gate on the notary walk. An empty record must
// never count as satisfying: that is what let a zero-key negative-cache entry
// suppress every retry.
func TestHeldSatisfies(t *testing.T) {
	oneKey := []*models.RemoteKey{{ID: "ed25519:a_EMUw"}}

	tests := []struct {
		name string
		held *models.CachedRemoteKeys
		min  models.Timestamp
		want bool
	}{
		{
			name: "nothing held",
			held: nil,
			min:  models.Timestamp(testNow),
			want: false,
		},
		{
			name: "record exists but holds no keys",
			held: &models.CachedRemoteKeys{
				RemoteServer: &models.RemoteServer{ValidUntilTs: models.Timestamp(testNow + 10*testDay)},
				Keys:         []*models.RemoteKey{},
			},
			min:  models.Timestamp(testNow),
			want: false,
		},
		{
			name: "keys valid past the caller's minimum",
			held: &models.CachedRemoteKeys{
				RemoteServer: &models.RemoteServer{ValidUntilTs: models.Timestamp(testNow + 10*testDay)},
				Keys:         oneKey,
			},
			min:  models.Timestamp(testNow),
			want: true,
		},
		{
			name: "expired archive cannot answer a request for current keys",
			held: &models.CachedRemoteKeys{
				RemoteServer: &models.RemoteServer{ValidUntilTs: models.Timestamp(testNow - 200*testDay)},
				Keys:         oneKey,
			},
			min:  models.Timestamp(testNow),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := heldSatisfies(tc.held, tc.min); got != tc.want {
				t.Errorf("heldSatisfies(%+v, %d) = %v, want %v", tc.held, tc.min, got, tc.want)
			}
		})
	}
}

func TestIsArchived(t *testing.T) {
	tests := []struct {
		name string
		s    *models.RemoteServer
		want bool
	}{
		{
			name: "nil record is not archived",
			s:    nil,
			want: false,
		},
		{
			name: "notary-served with expired validity is archived",
			s:    &models.RemoteServer{ObtainedViaNotary: "matrix.org", ValidUntilTs: models.Timestamp(testNow - testDay)},
			want: true,
		},
		{
			name: "notary-served but still valid is not archived",
			s:    &models.RemoteServer{ObtainedViaNotary: "matrix.org", ValidUntilTs: models.Timestamp(testNow + testDay)},
			want: false,
		},
		{
			name: "directly-fetched with expired validity is not archived",
			s:    &models.RemoteServer{ObtainedViaNotary: "", ValidUntilTs: models.Timestamp(testNow - testDay)},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isArchived(tc.s, testNow); got != tc.want {
				t.Errorf("isArchived(%+v, %d) = %v, want %v", tc.s, testNow, got, tc.want)
			}
		})
	}
}

// TestRyuuRegression walks the exact sequence that froze ryuu.eu: a live server
// whose reverse proxy returned a single 502, whose keys were then filled in from
// a notary with an already-expired bundle. Under the old rules that combination
// was classed as an archived gone-server snapshot and pinned for 24 hours, so
// the origin was never re-probed even though it was answering in 350ms.
func TestRyuuRegression(t *testing.T) {
	const minute = int64(60_000)

	// The origin answered, but with a 502 from its proxy.
	err := &originStatusError{serverName: "ryuu.eu", statusCode: 502}
	if !isTransientOriginFailure(err) {
		t.Fatal("a 502 must be recognised as transient: the host answered us")
	}

	backoff := originBackoff(1, isTransientOriginFailure(err))
	if backoff != time.Minute {
		t.Errorf("first transient failure backoff = %s, want 1m", backoff)
	}
	if backoff >= 24*time.Hour {
		t.Errorf("regression: one 502 stood us down for %s", backoff)
	}

	// The notary fills in an 8-month-expired bundle. The record is archived by
	// the descriptive definition, which must no longer suppress probing.
	record := &models.RemoteServer{
		ObtainedViaNotary:   "codestorm.net",
		ValidUntilTs:        models.Timestamp(testNow - 245*testDay),
		UpdatedTs:           models.Timestamp(testNow),
		OriginFailures:      1,
		NextOriginAttemptTs: models.Timestamp(testNow + backoff.Milliseconds()),
	}
	if !isArchived(record, testNow) {
		t.Fatal("expected the record to still be classed as archived")
	}

	// Within the standoff we serve the archive and stay off the network.
	if shouldProbeOrigin(record, testNow+30*1000) {
		t.Error("probed the origin inside its 1m standoff")
	}

	// A minute later the origin is probed again - the whole point of the fix.
	if !shouldProbeOrigin(record, testNow+minute+1) {
		t.Error("did not re-probe ryuu.eu's origin after the standoff elapsed")
	}

	// The caller wants current keys, so the expired archive must not suppress
	// the notary walk either.
	held := &models.CachedRemoteKeys{
		RemoteServer: record,
		Keys:         []*models.RemoteKey{{ID: "ed25519:a_EMUw"}},
	}
	if heldSatisfies(held, models.Timestamp(testNow)) {
		t.Error("an 8-month-expired bundle must not count as satisfying a request for current keys")
	}

	// A genuinely gone server still settles at one probe a day, so nothing about
	// the reservoir's notary-churn protection is given up.
	if got := originBackoff(9, false); got != 24*time.Hour {
		t.Errorf("settled backoff for a gone server = %s, want 24h", got)
	}
}
