# Grafana dashboard

`matrix-keyserver.json` is a Grafana dashboard for the metrics exposed by this
key server's `/metrics` endpoint (see the `metrics` package).

## Importing

1. In Grafana: **Dashboards → New → Import**.
2. Upload `matrix-keyserver.json` (or paste its contents).
3. When prompted, pick your **Prometheus** data source. The dashboard uses a
   `datasource` template variable, so it is not tied to any specific instance.

## Prometheus scrape config

Point Prometheus at the key server's `/metrics` endpoint, e.g.:

```yaml
scrape_configs:
  - job_name: matrix-key-server
    static_configs:
      - targets: ["matrix-key-server:8080"]
```

The dashboard has a `job` variable; select the job name you used above.

## Notes

- This is a portable export. The live copy provisioned into a running Grafana
  instance is kept separately and is not committed here.
- The panels cover HTTP request rates/latency, the Go runtime and process
  metrics, key resolution and notary behaviour (`keyserver_key_query_total`,
  `keyserver_origin_fetch_seconds`, `keyserver_notary_fetch_seconds`), and the
  known-server counts (`keyserver_known_servers`).
- `keyserver_known_servers` is a gauge whose `reachability` label partitions
  every server we hold a record for, so `sum()` over it is the total known:
  `direct` (keys fetched from the origin), `notary` (origin unreachable, keys
  came from a trusted notary), and `unreachable` (neither could resolve it -
  a negative-cache entry). It is refreshed from the database once a minute
  rather than on each scrape, so it will lag a change by up to that long.
