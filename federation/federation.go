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

// Borrowed with permission from matrix-media-repo:
// https://github.com/turt2live/matrix-media-repo/blob/75f43f98373b2ac41946d9b0b37934cae6a86e62/matrix/federation.go
// TODO: Use existing models

package federation

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alioygur/is"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"github.com/t2bot/matrix-key-server/metrics"
)

var apiUrlCacheInstance *cache.Cache
var apiUrlSingletonLock = &sync.Once{}

const (
	// federationRequestTimeout bounds a single outbound federated key fetch.
	// Homeservers retry, so a shorter timeout lets us fall back to a notary (and
	// answer the caller) faster when an origin is slow or unreachable.
	federationRequestTimeout = 8 * time.Second
	// wellKnownTimeout bounds the .well-known discovery lookup. It previously used
	// http.Get with no timeout, so a blackholed host could hang discovery for ~30s
	// and dominate request latency.
	wellKnownTimeout = 5 * time.Second
)

// wellKnownClient is a shared, timeout-bounded client for .well-known discovery.
var wellKnownClient = &http.Client{Timeout: wellKnownTimeout}

// maxResponseBytes bounds how much of a remote response we will buffer. Key
// responses and .well-known documents are a few KB at most, so a megabyte is
// generous. The timeouts above bound how *long* a remote host can hold us, but
// nothing bounded how much it could hand us: a host streaming an endless body at
// speed could balloon our heap inside the timeout window.
const maxResponseBytes = 1 << 20 // 1 MiB

// ReadResponseBody reads a remote HTTP response body, refusing to buffer more
// than maxResponseBytes. It reads one byte past the limit to tell "exactly at the
// cap" apart from "still going", so an over-long body is reported as an error
// rather than silently truncated into something that might still parse.
func ReadResponseBody(body io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponseBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxResponseBytes)
	}
	return b, nil
}

// Discovery cache lifetimes. The governing distinction is not success vs failure
// but whether the remote host actually told us something: only an answer we got
// from it may be trusted for long. A lookup that timed out or blew up taught us
// nothing, and the URL we guess in its place may well be wrong - pinning that for
// a day turns a momentary blip into a day-long outage for that server.
const (
	// discoveryValidTtl applies when .well-known answered 200 with a usable
	// delegation, and to results that involve no network at all (an IP literal or
	// an explicit port), which cannot be transiently wrong.
	discoveryValidTtl = 24 * time.Hour
	// discoveryAbsentTtl applies when the remote host authoritatively told us it
	// has no delegation (a clean 404), or when we derived the URL from SRV records.
	// Both are real answers, but cheaper to re-check than a full well-known probe.
	discoveryAbsentTtl = 1 * time.Hour
	// discoveryFailedTtl applies when discovery learned nothing: a timeout, a 5xx,
	// a refused connection, unparseable JSON. Just long enough to stop a stampede
	// while still letting the server come back quickly.
	discoveryFailedTtl = 5 * time.Minute

	// discoveryMinTtl and discoveryMaxTtl clamp a Cache-Control max-age offered by
	// a .well-known response, so a remote host can shorten or extend its delegation
	// lifetime within reason but cannot pin us for a month or force us to re-probe
	// on every request.
	discoveryMinTtl = 1 * time.Hour
	discoveryMaxTtl = 48 * time.Hour
)

type cachedServer struct {
	url      string
	hostname string
}

type wellknownServerResponse struct {
	ServerAddr string `json:"m.server"`
}

// wellKnownOutcome records what a .well-known probe actually established, which
// is what decides the cache lifetime of whatever URL we end up with.
type wellKnownOutcome int

const (
	// wellKnownFound means the host served a usable delegation.
	wellKnownFound wellKnownOutcome = iota
	// wellKnownAbsent means the host answered cleanly that it has no delegation
	// (404). The fallback URL we derive is then genuinely correct.
	wellKnownAbsent
	// wellKnownFailed means the probe told us nothing: timeout, 5xx, connection
	// refused, or a malformed body. Anything we derive is a guess.
	wellKnownFailed
)

// probeWellKnown performs the .well-known/matrix/server lookup and reports both
// the delegated address (when there is one) and, crucially, whether a failure was
// the host telling us "no delegation" or the host telling us nothing at all. The
// returned ttl is honoured from Cache-Control max-age when the host offers one.
func probeWellKnown(h string) (addr string, outcome wellKnownOutcome, ttl time.Duration) {
	r, err := wellKnownClient.Get(fmt.Sprintf("https://%s/.well-known/matrix/server", h))
	if r != nil {
		defer r.Body.Close()
	}
	return classifyWellKnown(r, err)
}

// classifyWellKnown turns a .well-known response into the delegated address and,
// more importantly, into a verdict about how much we actually learned. It is split
// from the transport so the classification can be exercised directly.
func classifyWellKnown(r *http.Response, err error) (addr string, outcome wellKnownOutcome, ttl time.Duration) {
	if err != nil || r == nil {
		return "", wellKnownFailed, discoveryFailedTtl
	}

	// A clean 404 is a real answer: this host has no delegation, so falling through
	// to SRV and then the default port is the correct result, not a guess.
	if r.StatusCode == http.StatusNotFound || r.StatusCode == http.StatusGone {
		return "", wellKnownAbsent, discoveryAbsentTtl
	}
	if r.StatusCode != http.StatusOK {
		return "", wellKnownFailed, discoveryFailedTtl
	}

	c, err := ReadResponseBody(r.Body)
	if err != nil {
		return "", wellKnownFailed, discoveryFailedTtl
	}
	wk := &wellknownServerResponse{}
	if err = json.Unmarshal(c, wk); err != nil {
		// Reachable but serving something unusable. Treat as no answer rather than
		// as an absent delegation - a broken deploy should not be cached for an hour.
		return "", wellKnownFailed, discoveryFailedTtl
	}
	addr = strings.TrimSpace(wk.ServerAddr)
	if !isUsableDelegation(addr) {
		return "", wellKnownFailed, discoveryFailedTtl
	}

	return addr, wellKnownFound, wellKnownTtlFrom(r.Header)
}

// isUsableDelegation reports whether an m.server value can actually be turned
// into a federation URL. net.SplitHostPort is not a validator - it will happily
// split "   :8448" into a blank host, and it never range-checks the port - so a
// 200 carrying junk would otherwise be treated as a real delegation and earn the
// full 24h lifetime. Anything that fails here is a host telling us nothing usable,
// which means the URL we fall back to is a guess and must expire quickly.
func isUsableDelegation(addr string) bool {
	if addr == "" {
		return false
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if !strings.HasSuffix(err.Error(), "missing port in address") {
			return false
		}
		host, port = addr, "8448"
	}

	if strings.TrimSpace(host) == "" {
		return false
	}
	// An IPv6 literal is a legitimate delegation and is the one host form that
	// legally contains colons, so it has to clear before the URL-shape checks.
	if !is.IP(host) {
		// A delegation is a host, not a URL: reject anything carrying a scheme,
		// a path, whitespace, or a stray colon.
		if strings.ContainsAny(host, "/\\ \t:") {
			return false
		}
		if !is.RequestURI("https://" + host) {
			return false
		}
	}

	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p <= 65535
}

// wellKnownTtlFrom derives the cache lifetime for a successful .well-known from
// the response's Cache-Control max-age, clamped to a sane range. Hosts that offer
// no usable directive get the default.
func wellKnownTtlFrom(header http.Header) time.Duration {
	for _, directive := range strings.Split(header.Get("Cache-Control"), ",") {
		directive = strings.TrimSpace(directive)
		if directive == "no-store" || directive == "no-cache" {
			return discoveryMinTtl
		}
		if !strings.HasPrefix(directive, "max-age=") {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimPrefix(directive, "max-age="))
		if err != nil || seconds <= 0 {
			continue
		}
		age := time.Duration(seconds) * time.Second
		if age < discoveryMinTtl {
			return discoveryMinTtl
		}
		if age > discoveryMaxTtl {
			return discoveryMaxTtl
		}
		return age
	}
	return discoveryValidTtl
}

func setupCache() {
	if apiUrlCacheInstance == nil {
		apiUrlSingletonLock.Do(func() {
			// The per-entry TTL is chosen at Set() time by the discovery outcome,
			// so the cache's own default expiration is never relied upon.
			apiUrlCacheInstance = cache.New(discoveryValidTtl, 2*discoveryValidTtl)
		})
	}
}

// rememberServerUrl caches a resolved federation URL for ttl and records the
// discovery outcome that produced it.
func rememberServerUrl(hostname, url, realHost, how string, ttl time.Duration, outcome string) (string, string, error) {
	apiUrlCacheInstance.Set(hostname, cachedServer{url, realHost}, ttl)
	metrics.RecordDiscovery(outcome)
	logrus.Info("Server API URL for " + hostname + " is " + url + " (" + how + "; ttl " + ttl.String() + ")")
	return url, realHost, nil
}

func GetServerApiUrl(hostname string) (string, string, error) {
	logrus.Info("Getting server API URL for " + hostname)

	// Check to see if we've cached this hostname at all
	setupCache()
	record, found := apiUrlCacheInstance.Get(hostname)
	if found {
		server := record.(cachedServer)
		metrics.RecordDiscovery(metrics.DiscoveryCached)
		logrus.Info("Server API URL for " + hostname + " is " + server.url + " (cache)")
		return server.url, server.hostname, nil
	}

	h, p, err := net.SplitHostPort(hostname)
	defPort := false
	if err != nil && strings.HasSuffix(err.Error(), "missing port in address") {
		h, p, err = net.SplitHostPort(hostname + ":8448")
		defPort = true
	}
	if err != nil {
		return "", "", err
	}

	// Step 1 of the discovery process: if the hostname is an IP, use that with explicit or default port
	logrus.Debug("Testing if " + h + " is an IP address")
	if is.IP(h) {
		url := fmt.Sprintf("https://%s:%s", h, p)
		return rememberServerUrl(hostname, url, hostname, "IP address", discoveryValidTtl, metrics.DiscoveryLiteral)
	}

	// Step 2: if the hostname is not an IP address, and an explicit port is given, use that
	logrus.Debug("Testing if a default port was used. Using default = ", defPort)
	if !defPort {
		url := fmt.Sprintf("https://%s:%s", h, p)
		return rememberServerUrl(hostname, url, h, "explicit port", discoveryValidTtl, metrics.DiscoveryLiteral)
	}

	// Step 3: if the hostname is not an IP address and no explicit port is given, do .well-known
	logrus.Debug("Doing .well-known lookup on " + h)
	wkAddr, wkOutcome, wkTtl := probeWellKnown(h)

	// Everything derived below inherits the lifetime the probe earned. A delegation
	// we were actually served is good for wkTtl; a host that said it has no
	// delegation gets the shorter absent lifetime; a probe that failed gets minutes,
	// because the URL we settle on is then only a guess.
	fallbackTtl, fallbackOutcome := discoveryAbsentTtl, metrics.DiscoveryWellKnownAbsent
	if wkOutcome == wellKnownFailed {
		fallbackTtl, fallbackOutcome = discoveryFailedTtl, metrics.DiscoveryWellKnownFailed
	}

	if wkOutcome == wellKnownFound {
		wkHost, wkPort, err4 := net.SplitHostPort(wkAddr)
		wkDefPort := false
		if err4 != nil && strings.HasSuffix(err4.Error(), "missing port in address") {
			wkHost, wkPort, err4 = net.SplitHostPort(wkAddr + ":8448")
			wkDefPort = true
		}
		if err4 == nil {
			// Step 3a: if the delegated host is an IP address, use that (regardless of port)
			logrus.Debug("Checking if WK host is an IP: " + wkHost)
			if is.IP(wkHost) {
				url := fmt.Sprintf("https://%s:%s", wkHost, wkPort)
				return rememberServerUrl(hostname, url, wkAddr, "WK; IP address", wkTtl, metrics.DiscoveryWellKnown)
			}

			// Step 3b: if the delegated host is not an IP and an explicit port is given, use that
			logrus.Debug("Checking if WK is using default port? ", wkDefPort)
			if !wkDefPort {
				url := fmt.Sprintf("https://%s:%s", wkHost, wkPort)
				return rememberServerUrl(hostname, url, wkHost, "WK; explicit port", wkTtl, metrics.DiscoveryWellKnown)
			}

			// Step 3c/3d: no port on the delegated host, so look for SRV records.
			if url, ok := lookupSrv(wkHost); ok {
				return rememberServerUrl(hostname, url, wkHost, "WK; SRV", wkTtl, metrics.DiscoveryWellKnown)
			}

			// Step 3e: use the delegated host as-is
			logrus.Debug("Using .well-known as-is for ", wkHost)
			url := fmt.Sprintf("https://%s:%s", wkHost, wkPort)
			return rememberServerUrl(hostname, url, wkHost, "WK; fallback", wkTtl, metrics.DiscoveryWellKnown)
		}
		// The delegation was served but unusable, so we learned nothing after all.
		fallbackTtl, fallbackOutcome = discoveryFailedTtl, metrics.DiscoveryWellKnownFailed
	}

	// Steps 4 and 5: try resolving the hostname itself using SRV records.
	// An SRV answer is a real answer, but it carries its own DNS lifetime, so it
	// never earns more than the absent TTL - and never more than a failed probe
	// allows, since we cannot trust a guess just because DNS agreed with it.
	if url, ok := lookupSrv(hostname); ok {
		srvTtl := discoveryAbsentTtl
		if fallbackTtl < srvTtl {
			srvTtl = fallbackTtl
		}
		return rememberServerUrl(hostname, url, h, "SRV", srvTtl, metrics.DiscoverySRV)
	}

	// Step 6: use the target host as-is. This is the pure guess - correct for a
	// server that genuinely has no delegation, wrong for one whose .well-known was
	// merely unreachable, which is exactly why fallbackTtl distinguishes the two.
	logrus.Debug("Using host as-is: ", hostname)
	url := fmt.Sprintf("https://%s:%s", h, p)
	if fallbackOutcome == metrics.DiscoveryWellKnownAbsent {
		fallbackOutcome = metrics.DiscoveryFallback
	}
	return rememberServerUrl(hostname, url, h, "fallback", fallbackTtl, fallbackOutcome)
}

// lookupSrv resolves the Matrix federation SRV records for a host, preferring the
// current _matrix-fed service over the deprecated _matrix one, and returns the
// resulting base URL. Errors are ignored deliberately: a missing SRV record is an
// ordinary outcome, and the host will fail later if it is genuinely unreachable.
func lookupSrv(host string) (string, bool) {
	for _, service := range []string{"matrix-fed", "matrix"} {
		logrus.Debug("Doing SRV ("+service+") on host ", host)
		_, addrs, _ := net.LookupSRV(service, "tcp", host)
		if len(addrs) == 0 {
			continue
		}
		// Trim off the trailing period if there is one (golang doesn't like this)
		realAddr := strings.TrimSuffix(addrs[0].Target, ".")
		return fmt.Sprintf("https://%s:%d", realAddr, addrs[0].Port), true
	}
	return "", false
}

var (
	federatedClientsLock sync.Mutex
	federatedClients     = map[string]*http.Client{}
)

// federatedClientFor returns a shared, connection-pooling HTTP client for the
// given TLS host. Clients are cached per host because each needs its own
// tls.Config.ServerName, but must be reused across requests: building a fresh
// http.Transport per call (as this code used to) defeats connection pooling, so
// every federation fetch paid a full DNS + TCP + TLS handshake, and the discarded
// transports leaked their keep-alive connections' readLoop/writeLoop goroutines
// indefinitely (no IdleConnTimeout). Reuse fixes both the CPU churn and the leak.
func federatedClientFor(realHost string) *http.Client {
	federatedClientsLock.Lock()
	defer federatedClientsLock.Unlock()

	if c, ok := federatedClients[realHost]; ok {
		return c
	}

	c := &http.Client{
		Transport: &http.Transport{
			// This is how we verify the certificate is valid for the host we
			// expect. Previously using `req.URL.Host` we'd end up changing which
			// server we were connecting to (ie: matrix.org instead of
			// matrix.org.cdn.cloudflare.net), which obviously doesn't help us. We
			// needed to do that though because the HTTP client doesn't verify
			// against the req.Host certificate, but it does handle it off the
			// req.URL.Host. So, we need to tell it which certificate to verify.
			TLSClientConfig:     &tls.Config{ServerName: realHost},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		Timeout: federationRequestTimeout,
	}
	federatedClients[realHost] = c
	return c
}

func FederatedGet(url string, realHost string) (*http.Response, error) {
	logrus.Info("Doing federated GET to " + url + " with host " + realHost)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Override the host to be compliant with the spec
	req.Header.Set("Host", realHost)
	req.Header.Set("User-Agent", "matrix-media-repo")
	req.Host = realHost

	resp, err := federatedClientFor(realHost).Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
