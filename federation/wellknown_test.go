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

package federation

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWellKnownTtlFrom checks that a host can steer its own delegation lifetime
// through Cache-Control, but only within the clamp.
func TestWellKnownTtlFrom(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		want         time.Duration
	}{
		{"no header falls back to the default", "", discoveryValidTtl},
		{"honours a sane max-age", "max-age=7200", 2 * time.Hour},
		{"honours max-age among other directives", "public, max-age=7200, s-maxage=99", 2 * time.Hour},
		{"clamps an absurdly long max-age", "max-age=2592000", discoveryMaxTtl},
		{"clamps a too-short max-age", "max-age=5", discoveryMinTtl},
		{"treats no-store as the minimum, not as zero", "no-store", discoveryMinTtl},
		{"ignores an unparseable max-age", "max-age=banana", discoveryValidTtl},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.cacheControl != "" {
				h.Set("Cache-Control", tc.cacheControl)
			}
			if got := wellKnownTtlFrom(h); got != tc.want {
				t.Fatalf("wellKnownTtlFrom(%q) = %v, want %v", tc.cacheControl, got, tc.want)
			}
		})
	}
}

// TestDiscoveryTtlOrdering pins the invariant the whole split exists to enforce:
// a guess must never outlive an answer.
func TestDiscoveryTtlOrdering(t *testing.T) {
	if !(discoveryFailedTtl < discoveryAbsentTtl && discoveryAbsentTtl < discoveryValidTtl) {
		t.Fatalf("TTLs must increase with how much the probe actually established: failed=%v absent=%v valid=%v",
			discoveryFailedTtl, discoveryAbsentTtl, discoveryValidTtl)
	}
	if discoveryMinTtl > discoveryValidTtl || discoveryMaxTtl < discoveryValidTtl {
		t.Fatalf("the default TTL must sit inside the Cache-Control clamp")
	}
}

// TestClassifyWellKnown is the heart of the split: a host that answers "I have no
// delegation" is believed for an hour, while a host that fails to answer at all
// buys only minutes, because the URL we fall back to may be flat wrong for it.
func TestClassifyWellKnown(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		transportEr error
		wantAddr    string
		wantOutcome wellKnownOutcome
		wantTtl     time.Duration
	}{
		{
			name:        "usable delegation",
			status:      http.StatusOK,
			body:        `{"m.server":"matrix.example.org:8448"}`,
			wantAddr:    "matrix.example.org:8448",
			wantOutcome: wellKnownFound,
			wantTtl:     discoveryValidTtl,
		},
		{
			name:        "404 is an authoritative no-delegation",
			status:      http.StatusNotFound,
			body:        "not found",
			wantOutcome: wellKnownAbsent,
			wantTtl:     discoveryAbsentTtl,
		},
		{
			// The case that motivated all of this: a reverse proxy throwing 502
			// mid-deploy must not pin a guessed URL for a day.
			name:        "502 teaches us nothing",
			status:      http.StatusBadGateway,
			body:        "<html>Bad Gateway</html>",
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
		{
			name:        "503 teaches us nothing",
			status:      http.StatusServiceUnavailable,
			body:        "down for maintenance",
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
		{
			name:        "200 serving an HTML error page is not an answer",
			status:      http.StatusOK,
			body:        "<html><body>hello</body></html>",
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
		{
			name:        "200 with an empty m.server is not an answer",
			status:      http.StatusOK,
			body:        `{"m.server":""}`,
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
		{
			name:        "200 with a whitespace m.server is not an answer",
			status:      http.StatusOK,
			body:        `{"m.server":"   "}`,
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
		{
			name:        "200 with an out-of-range port is not an answer",
			status:      http.StatusOK,
			body:        `{"m.server":"host:999999"}`,
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
		{
			name:        "200 with valid JSON but the wrong shape is not an answer",
			status:      http.StatusOK,
			body:        `{"foo":"bar"}`,
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
		{
			name:        "an IPv6 literal delegation is usable",
			status:      http.StatusOK,
			body:        `{"m.server":"[::1]:8448"}`,
			wantAddr:    "[::1]:8448",
			wantOutcome: wellKnownFound,
			wantTtl:     discoveryValidTtl,
		},
		{
			name:        "surrounding whitespace is trimmed, not rejected",
			status:      http.StatusOK,
			body:        `{"m.server":"  matrix.example.org:8448  "}`,
			wantAddr:    "matrix.example.org:8448",
			wantOutcome: wellKnownFound,
			wantTtl:     discoveryValidTtl,
		},
		{
			name:        "connection failure teaches us nothing",
			transportEr: errors.New("dial tcp: connection refused"),
			wantOutcome: wellKnownFailed,
			wantTtl:     discoveryFailedTtl,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			if tc.transportEr == nil {
				rec := httptest.NewRecorder()
				// WriteHeader must precede the body: ResponseRecorder.Write
				// implicitly stamps 200 if no status has been written yet.
				rec.WriteHeader(tc.status)
				_, _ = io.WriteString(rec, tc.body)
				resp = rec.Result()
				defer resp.Body.Close()
			}

			addr, outcome, ttl := classifyWellKnown(resp, tc.transportEr)
			if addr != tc.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tc.wantAddr)
			}
			if outcome != tc.wantOutcome {
				t.Errorf("outcome = %v, want %v", outcome, tc.wantOutcome)
			}
			if ttl != tc.wantTtl {
				t.Errorf("ttl = %v, want %v", ttl, tc.wantTtl)
			}
		})
	}
}

// TestIsUsableDelegation guards the trap that net.SplitHostPort is a splitter,
// not a validator: it will hand back a blank host for "   :8448" and never
// range-checks the port. Without this gate a 200 carrying junk counts as a real
// delegation and earns the full 24h lifetime - the exact "cache a bad answer for
// a day" failure the TTL split exists to prevent.
func TestIsUsableDelegation(t *testing.T) {
	usable := []string{
		"matrix.example.org:8448",
		"matrix.example.org",
		"1.2.3.4:8448",
		"[::1]:8448",
		"example.org:443",
	}
	for _, addr := range usable {
		t.Run("usable/"+addr, func(t *testing.T) {
			if !isUsableDelegation(addr) {
				t.Fatalf("isUsableDelegation(%q) = false, want true", addr)
			}
		})
	}

	junk := map[string]string{
		"empty":             "",
		"whitespace only":   "   ",
		"a URL not a host":  "http://x:99/path",
		"port out of range": "host:999999",
		"port zero":         "host:0",
		"non-numeric port":  "host:abc",
		"space in host":     "exa mple.org:8448",
		"path in host":      "example.org/matrix:8448",
	}
	for name, addr := range junk {
		t.Run("junk/"+name, func(t *testing.T) {
			if isUsableDelegation(addr) {
				t.Fatalf("isUsableDelegation(%q) = true, want false", addr)
			}
		})
	}
}

// TestClassifyWellKnownHonoursCacheControl checks the header path survives a real
// response round-trip, not just the header helper in isolation.
func TestClassifyWellKnownHonoursCacheControl(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Cache-Control", "max-age=7200")
	_, _ = io.WriteString(rec, `{"m.server":"matrix.example.org:8448"}`)
	resp := rec.Result()
	defer resp.Body.Close()

	_, outcome, ttl := classifyWellKnown(resp, nil)
	if outcome != wellKnownFound {
		t.Fatalf("outcome = %v, want wellKnownFound", outcome)
	}
	if ttl != 2*time.Hour {
		t.Fatalf("ttl = %v, want 2h from Cache-Control", ttl)
	}
}

// TestReadResponseBody checks the cap distinguishes a body that lands exactly on
// the limit from one that runs past it, so an over-long response is rejected
// rather than silently truncated into something that might still parse.
func TestReadResponseBody(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"small body", 128, false},
		{"one byte under the cap", maxResponseBytes - 1, false},
		{"exactly at the cap", maxResponseBytes, false},
		{"one byte over the cap", maxResponseBytes + 1, true},
		{"far over the cap", maxResponseBytes * 4, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := ReadResponseBody(bytes.NewReader(bytes.Repeat([]byte("x"), tc.size)))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ReadResponseBody(%d bytes) succeeded, want an error", tc.size)
				}
				if b != nil {
					t.Fatalf("an over-long body must not be returned truncated")
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadResponseBody(%d bytes) failed: %v", tc.size, err)
			}
			if len(b) != tc.size {
				t.Fatalf("read %d bytes, want %d", len(b), tc.size)
			}
		})
	}
}

// TestReadResponseBodyStopsReadingEndlessStream is the case the cap exists for: a
// host that never stops sending. Without the limit this never returns.
func TestReadResponseBodyStopsReadingEndlessStream(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := ReadResponseBody(endlessReader{}); err == nil {
			t.Error("an endless body should be rejected, not buffered")
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ReadResponseBody did not stop reading an endless stream")
	}
}

// endlessReader never reaches EOF, standing in for a remote host streaming
// without end.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
