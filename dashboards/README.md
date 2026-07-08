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
- The panels currently cover HTTP request rates/latency and the Go runtime and
  process metrics. The domain-specific families - `keyserver_key_query_total`
  (resolution outcomes), `keyserver_origin_fetch_seconds`,
  `keyserver_notary_fetch_seconds` (notary lag), and the `archive_served`
  outcome - are exported by the server and can be added as panels.
