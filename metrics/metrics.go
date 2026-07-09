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

// Package metrics holds all Prometheus instrumentation for the key server. It
// keeps the prometheus client dependency contained to a single package and
// exposes small helpers so call sites stay free of collector wiring.
//
// Every label used here is deliberately bounded: request routes come from the
// fixed set of registered handler actions, key-query outcomes are a closed enum,
// and notary names come from the configured trusted-notary allowlist. Unbounded
// values (remote server_names, client IPs) are intentionally never used as
// labels - they belong in the logs, not the time series database.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Key-query outcome label values, one per return path of queryRemoteKeys.
const (
	OutcomeCacheFresh     = "cache_fresh"
	OutcomeCacheCooldown  = "cache_cooldown"
	OutcomeOriginSuccess  = "origin_success"
	OutcomeNotarySuccess  = "notary_success"
	OutcomeAllFailedStale = "all_failed_stale"
	OutcomeAllFailedEmpty = "all_failed_empty"
	OutcomeArchiveServed  = "archive_served"
)

// Result label values for outbound fetches.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Reachability label values for the known-servers gauge. They partition the
// cached servers, so summing across the label gives the total we know of.
const (
	ReachabilityDirect      = "direct"
	ReachabilityNotary      = "notary"
	ReachabilityUnreachable = "unreachable"
)

// fetchBuckets extends the default histogram buckets with a couple of larger
// ones, since outbound federated fetches can run up to the 15s client timeout.
var fetchBuckets = append(append([]float64{}, prometheus.DefBuckets...), 15, 30)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyserver_http_requests_total",
		Help: "Total HTTP requests handled, labelled by route action, method and status code.",
	}, []string{"route", "method", "status"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyserver_http_request_duration_seconds",
		Help:    "HTTP request handling latency in seconds, labelled by route action and method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route", "method"})

	keyQueries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyserver_key_query_total",
		Help: "Remote key resolutions, labelled by outcome (cache_fresh, cache_cooldown, origin_success, notary_success, all_failed_stale, all_failed_empty).",
	}, []string{"outcome"})

	originFetch = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyserver_origin_fetch_seconds",
		Help:    "Latency of direct key fetches from an origin server, labelled by result.",
		Buckets: fetchBuckets,
	}, []string{"result"})

	notaryFetch = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyserver_notary_fetch_seconds",
		Help:    "Latency of key fetches from a trusted notary (\"notary lag\"), labelled by notary and result.",
		Buckets: fetchBuckets,
	}, []string{"notary", "result"})

	knownServers = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "keyserver_known_servers",
		Help: "Cached remote servers, labelled by how their keys were last obtained: direct from the origin, through a trusted notary, or unreachable (neither could resolve them). The labels partition the set, so summing gives the total number of servers known.",
	}, []string{"reachability"})
)

// Handler returns the HTTP handler that serves the Prometheus exposition format,
// including the Go runtime and process collectors registered by default.
func Handler() http.Handler {
	return promhttp.Handler()
}

// ObserveHTTPRequest records a completed HTTP request against both the request
// counter and the latency histogram.
func ObserveHTTPRequest(route, method string, status int, d time.Duration) {
	statusStr := strconv.Itoa(status)
	httpRequests.WithLabelValues(route, method, statusStr).Inc()
	httpDuration.WithLabelValues(route, method).Observe(d.Seconds())
}

// RecordKeyQuery increments the key-resolution counter for the given outcome.
func RecordKeyQuery(outcome string) {
	keyQueries.WithLabelValues(outcome).Inc()
}

// ObserveOriginFetch records the latency and result of a direct origin fetch.
func ObserveOriginFetch(result string, d time.Duration) {
	originFetch.WithLabelValues(result).Observe(d.Seconds())
}

// ObserveNotaryFetch records the latency and result of a fetch from a single
// trusted notary.
func ObserveNotaryFetch(notary, result string, d time.Duration) {
	notaryFetch.WithLabelValues(notary, result).Observe(d.Seconds())
}

// SetKnownServers publishes the current counts of directly-reachable,
// notary-reachable, and unreachable cached servers.
func SetKnownServers(direct, viaNotary, unreachable int64) {
	knownServers.WithLabelValues(ReachabilityDirect).Set(float64(direct))
	knownServers.WithLabelValues(ReachabilityNotary).Set(float64(viaNotary))
	knownServers.WithLabelValues(ReachabilityUnreachable).Set(float64(unreachable))
}
