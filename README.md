# Botdeny Log Analyzer

A Go-based tool that parses Nginx `access.log` files and highlights source IPs that exhibit suspicious behaviour such as high request rates, bursts, excessive errors, or wide path spraying.

## Usage

```bash
GOCACHE=$(pwd)/.gocache go run ./src --file access.log --top 10
```

Key flags:

- `--min-requests`: minimum requests required before an IP is considered (default `50`).
- `--max-rpm`: average requests per minute threshold that triggers a score (default `90`).
- `--burst` / `--burst-window`: trigger if more than N requests occur within the window (defaults `80` in `1m`).
- `--min-errors` and `--error-ratio`: error volume and percentage thresholds.
- `--unique-paths`: treat wide path coverage as suspicious.
- `--score-threshold`: minimum score before reporting an IP.
- `--config`: load defaults from a YAML config file (see below).
- `--allow-agent`: add additional trusted crawler substrings (repeats allowed) beyond the baked-in list for Google, Bing, Pinterest, etc.
- `--allow-ip`: add an individual source IP to the allowlist (repeatable).
- `--allow-ip-file`: parse trusted IPs/CIDRs from files containing directives like `set_real_ip_from` (repeatable).
- `--color`: enable ANSI colors in the report when your terminal supports them.
- `--geoip-db`: supply a MaxMind GeoIP2/GeoLite2 Country database to enrich reports with country metadata.
- `--php404`: flag IPs issuing at least this many `.php` requests that returned 404 (default `10`).
- `--bot-country`: penalise IPs originating from specific ISO country codes (repeatable).
- `--deny-output`: write an Nginx include file containing `deny` directives for the reported IPs.
- `--deny-expiry`: duration used to compute the expiration comment in the generated deny file (default `168h`).
- `--nginx-reload`: after writing the deny file, run `nginx -t` followed by `nginx -s reload`.
- `--nginx-bin`: override the nginx binary path when using `--nginx-reload` (default `nginx`).
- `--block-log`: append a timestamped summary of blocked IPs and reasons to the given log file.

### YAML configuration

Pass `--config path/to/config.yaml` to load defaults from a file, for example:

```yaml
file: /var/log/nginx/access.log
top: 20
color: true
geoip_db: /usr/share/GeoIP/GeoLite2-Country.mmdb
deny_output: /etc/nginx/includes/blockdeny.conf
deny_expiry: 168h
nginx_reload: true
nginx_bin: /usr/sbin/nginx
block_log: /var/log/botdeny/blocked.log
allow_agents:
  - FriendlyCrawler
bot_countries:
  - BR
  - VN
allow_ips:
  - 34.91.94.224
allow_ip_files:
  - /etc/nginx/cloudflare_realip.conf
min_requests: 40
max_average_rpm: 60
max_burst_window: 30s
max_burst_requests: 120
min_404_errors: 15
min_error_ratio: 0.4
min_unique_paths: 120
score_threshold: 2
min_php_404s: 5
```

Values from the config file populate the tool's defaults; any CLI flag you pass explicitly still wins at runtime.

`allow_ips` can list trusted source addresses that should never be scored or included in deny files, useful for known preloaders or internal monitors. `allow_ip_files` accepts paths to files containing `set_real_ip_from` directives (such as Cloudflare ranges) and automatically allowlists every IP or CIDR declared inside.

The CLI prints the highest-scoring IPs, their request counts, and the heuristics that fired so you can review or feed the results into automated deny lists.
Each suspect also includes its top user agents and frequent paths to help explain what was fetched.

## Limitations & Next Steps

- The parser expects the Nginx combined log format with an optional `$http_x_forwarded_for` field at the end; customise `logparser.go` if your format differs.
- GeoIP enrichment relies on a local MaxMind-compatible `.mmdb`; keep it updated to avoid stale location data.
- Default bot-country penalties cover `CN`, `RU`, `KP`, and `IR`; extend or trim via `--bot-country` to match your threat model.
- Thresholds are intentionally conservative; tune them with historical log backfills before enabling auto-blocking.
- Consider writing the suspicious IPs to a file or Redis list for Nginx to consume automatically.
- `--nginx-reload` expects local permission to execute the nginx binary; run without it if your analyzer host cannot manage Nginx directly.
