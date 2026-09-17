# CrowdStrike to Chronicle Intel Bridge

[![Go Lint & Test](https://github.com/CrowdStrike/chronicle-intel-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/CrowdStrike/chronicle-intel-bridge/actions/workflows/ci.yml)
[![Container Build on Quay](https://quay.io/repository/crowdstrike/chronicle-intel-bridge/status "Docker Repository on Quay")](https://quay.io/repository/crowdstrike/chronicle-intel-bridge)

CrowdStrike to Chronicle Intel Bridge (CCIB) forwards CrowdStrike Falcon Intelligence Indicators to Google Chronicle.

It is a small Go daemon: a reader goroutine polls the Falcon Intel API on a fixed interval, deduplicates and reshapes each page of indicators, and hands batches to a writer goroutine that delivers them to Chronicle. The two are coordinated by a bounded channel that provides back-pressure, and the process shuts down gracefully on `SIGINT`/`SIGTERM` — the in-flight batch is flushed and the resume marker persisted before exit.

## Migration from the Python service (breaking changes)

The Go rewrite renames two environment variables (and their config-file keys). The old names are **no longer read** — there are no backward-compatible aliases, so a deployment that still sets the old name will silently fall back to the default.

| Old (Python) | New (Go) | Config key |
|---|---|---|
| `FALCON_CLOUD_REGION` | `FALCON_CLOUD` | `falcon.cloud` (was `cloud_region`) |
| `ICACHE_MAX_SIZE` | `CACHE_MAX_SIZE` | `cache.max_size` (was `icache.max_size`) |

The default config file also moved from `config/config.ini` to `config/config.yaml`. A Python-era deployment that mounts its `config.ini` at the old default path will have it **silently ignored** unless you point CCIB at it explicitly.

| Old (Python) | New (Go) | Keep the old file |
|---|---|---|
| `config/config.ini` (default) | `config/config.yaml` (default) | Pass `--config config/config.ini` — INI is still a supported format. |

Forwarded indicators now include the per-label `created_on` field. This is intentional — indicators are sent to Chronicle verbatim apart from a few volatile fields stripped for deduplication — and Chronicle tolerates the extra field.

`LOG_FORMAT` (text/json) and `STATE_FILE` are new options with no Python equivalent; existing deployments need no change to keep the previous behavior.

### Chronicle API migration (new required `CHRONICLE_PROJECT`)

CCIB now delivers indicators through the Google SecOps / Chronicle v1 API
(`{region}-chronicle.googleapis.com`, `logs:import`) instead of the legacy
Chronicle Ingestion API (`malachiteingestion-pa.googleapis.com`,
`unstructuredlogentries:batchCreate`). This changes the deployment contract:

- **`CHRONICLE_PROJECT` is now required.** The new API is addressed by the
  Google Cloud project linked to your Chronicle instance; startup fails fast if
  it is unset.
- **The service account uses the single `cloud-platform` OAuth scope** and must
  be authorized for the Chronicle API on that project (see Prerequisites).
- **An unknown `CHRONICLE_REGION` is now rejected at startup** rather than
  silently falling back to the US endpoint.

## Prerequisites

- Create a new API key pair at [CrowdStrike Falcon](https://falcon.crowdstrike.com/support/api-clients-and-keys). This key pair is used to read Falcon Intelligence indicators.

   Make sure only the following permission is assigned to the key pair:
  - **Indicators (Falcon Intelligence)**: READ

- Obtain your Chronicle Customer ID, the Google Cloud project ID linked to your
  Chronicle instance, and credentials that can call the Chronicle API.
  > Your Chronicle Support representative should be able to provide you with your
  > Chronicle Customer ID and project ID.

  Credentials can be supplied three ways, in order of Google's recommendation:

  - **Workload Identity Federation (recommended).** Point
    `GOOGLE_SERVICE_ACCOUNT_FILE` at an `external_account` credential
    configuration file. WIF avoids long-lived service account keys.
  - **Application Default Credentials.** Leave `GOOGLE_SERVICE_ACCOUNT_FILE`
    unset and CCIB uses ADC, honoring `GOOGLE_APPLICATION_CREDENTIALS` and the
    ambient Google Cloud environment (e.g. an attached service account on GKE or
    Compute Engine).
  - **Service account key file.** Point `GOOGLE_SERVICE_ACCOUNT_FILE` at a
    `service_account` JSON key.

  > **Create a _new_ service account.** A legacy Chronicle service account —
  > typically one whose email contains `bk` or `malachite-cx` — is rejected by
  > the modern Chronicle API with HTTP 403.

  Whichever method you use, the identity authenticates with the single
  `https://www.googleapis.com/auth/cloud-platform` OAuth scope and must be
  granted the **Chronicle API Editor** role (or equivalent permissions on
  `logs:import`).

- The `CROWDSTRIKE_IOC` log type must be enabled for the target Chronicle instance. CCIB delivers every batch to `logTypes/CROWDSTRIKE_IOC/logs:import`; if that log type is not registered under the new Chronicle API, the instance rejects the import. This log type is standard in Google SecOps but may need to be enabled by your Chronicle Support representative on older instances.

## Configuration

Configuration is resolved from a layered set of sources, highest precedence first:

1. Command-line flags — run `ccib --help` for the full list
2. Environment variables
3. `config/config.yaml` — your settings (optional; override the path with `--config`)
4. Built-in defaults

Every option is available as a flag, an environment variable, and a config-file
key. An unset flag or empty environment variable falls through to the next source.

### Environment Variables

| Variable | Purpose |
|---|---|
| `FALCON_CLOUD` | Falcon cloud region: e.g. `us-1`, `us-2`, `eu-1`, or `us-gov-1` |
| `FALCON_CLIENT_ID` | Falcon API client ID |
| `FALCON_CLIENT_SECRET` | Falcon API client secret |
| `CHRONICLE_CUSTOMER_ID` | Chronicle Customer ID |
| `CHRONICLE_PROJECT` | Google Cloud project linked to the Chronicle instance (**required**) |
| `CHRONICLE_REGION` | Chronicle regional endpoint (optional; defaults to US multi-region) |
| `GOOGLE_SERVICE_ACCOUNT_FILE` | Path to a Chronicle credential file — a service account key or an `external_account` (WIF) config (optional; unset uses Application Default Credentials) |
| `CACHE_MAX_SIZE` | Max entries in the in-memory dedup cache (`<= 0` = unbounded) |
| `STATE_FILE` | Path to the resume-marker state file |
| `LOG_LEVEL` | `ERROR`, `WARN`, `INFO`, or `DEBUG` |
| `LOG_FORMAT` | Log output format: `text` (default) or `json` |

```bash
export FALCON_CLOUD=YOUR_CLOUD_REGION   # e.g. us-1, us-2, eu-1, us-gov-1
export FALCON_CLIENT_ID=YOUR_CLIENT_ID
export FALCON_CLIENT_SECRET=YOUR_CLIENT_SECRET
export CHRONICLE_CUSTOMER_ID=YOUR_CUSTOMER_ID
export CHRONICLE_PROJECT=YOUR_GCP_PROJECT
export CHRONICLE_REGION=YOUR_CHRONICLE_REGION   # optional, defaults to US multi-region
export GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json   # optional; unset uses Application Default Credentials
```

### Chronicle Region Configuration

The `CHRONICLE_REGION` environment variable specifies which Chronicle regional endpoint to use. The following values are supported:

- **Legacy region codes**: EU, UK, IL, AU, SG
- **Google Cloud region codes**: US, EU, EUROPE, EUROPE-WEST2, EUROPE-WEST3, EUROPE-WEST6, EUROPE-WEST9, EUROPE-WEST12, EUROPE-CENTRAL2, ME-WEST1, ME-CENTRAL1, ME-CENTRAL2, AFRICA-SOUTH1, ASIA-SOUTH1, ASIA-EAST1, ASIA-SOUTHEAST1, ASIA-SOUTHEAST2, ASIA-NORTHEAST1, ASIA-NORTHEAST3, AUSTRALIA-SOUTHEAST1, SOUTHAMERICA-EAST1, NORTHAMERICA-NORTHEAST2
- If not specified, it defaults to the US multi-region endpoint
- An unrecognized value is rejected at startup so a misconfigured region fails fast rather than silently routing to the wrong endpoint

> [!NOTE]
> Region codes are case-insensitive, with one exception. Google documents `eu` as a
> multi-region endpoint distinct from `europe`, while the legacy Chronicle code `EU`
> denotes the European instance. CCIB therefore treats lowercase `eu` as the `eu`
> endpoint and the uppercase legacy `EU` as `europe`; every other code (including
> `US`/`us` and `EUROPE`/`europe`) is matched case-insensitively.

### State Persistence

The bridge tracks its position in the Falcon indicator feed using the API's opaque `_marker` cursor, saved to `data/state.json` (writes are atomic — temp file plus rename — so a crash mid-write never corrupts the cursor). This lets the bridge resume exactly where it left off after a restart without gaps. The marker is advanced **only after a batch is fully delivered** to Chronicle, so a permanent send failure never skips undelivered indicators.

To keep state across restarts, mount a Docker volume at `/ccib/data`:

```bash
-v ccib-state:/ccib/data
```

Without the volume mount the bridge still runs, but re-fetches from the `initial_sync_lookback` window on every restart. The in-memory deduplication cache ensures any overlap during re-fetch does not produce duplicate indicators in Chronicle. Override the state file path with the `STATE_FILE` environment variable.

### Advanced Configuration

See [config/config.yaml](./config/config.yaml) for the full set of options and inline documentation.

1. Copy `config/config.yaml` from this repository to use as a template.
2. Make any changes needed.
3. Mount it over the image's copy:

    ```bash
    -v /path/to/your/config.yaml:/ccib/config/config.yaml:ro
    ```

The format is detected from the file extension, so any of the formats below
work in place of the default YAML — just point `--config` at the file.

### Supported Config File Formats

| Format | Extensions |
|---|---|
| YAML (default) | `.yaml`, `.yml` |
| JSON | `.json` |
| TOML | `.toml` |
| INI | `.ini` |

An extensionless config path is read as INI. Whichever format you choose, the
options are the same — use the section/key structure shown in
[config/config.yaml](./config/config.yaml), written in that format's own syntax
(nested keys in YAML/JSON/TOML, `[section]` headers in INI).

## Deployment Instructions

### Interactive mode (foreground)

```bash
docker run -it --rm \
      --name chronicle-intel-bridge \
      -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
      -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
      -e FALCON_CLOUD="$FALCON_CLOUD" \
      -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
      -e CHRONICLE_PROJECT="$CHRONICLE_PROJECT" \
      -e CHRONICLE_REGION="$CHRONICLE_REGION" \
      -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
      -v /path/to/your/service-account.json:/gcloud/sa.json:ro \
      -v ccib-state:/ccib/data \
      quay.io/crowdstrike/chronicle-intel-bridge:latest
```

### Detached mode (background with restart policy)

```bash
docker run -d --restart unless-stopped \
      --name chronicle-intel-bridge \
      -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
      -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
      -e FALCON_CLOUD="$FALCON_CLOUD" \
      -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
      -e CHRONICLE_PROJECT="$CHRONICLE_PROJECT" \
      -e CHRONICLE_REGION="$CHRONICLE_REGION" \
      -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
      -v /path/to/your/service-account.json:/gcloud/sa.json:ro \
      -v ccib-state:/ccib/data \
      quay.io/crowdstrike/chronicle-intel-bridge:latest
```

### FIPS mode

The image is built with a FIPS-validated Go toolchain, so the validated module is compiled into the binary. FIPS mode is off by default and is a pure runtime toggle:

```bash
-e GODEBUG=fips140=on   # values: on, only
```

## Development

Requires Go 1.26+.

```bash
# Build, vet, and test (matches CI — run before pushing)
go build ./...
go vet ./...
go test -race ./...

# Static analysis
golangci-lint run
gosec ./...

# Show all flags and their defaults
go run ./cmd/ccib --help

# Run locally (reads config/config.yaml relative to the working directory)
go run ./cmd/ccib
```

### Building the container locally

```bash
docker build -t ccib:latest .
```

> [!NOTE]
> The build uses Red Hat Hardened Images for the Go toolchain and runtime base, which require access to `registry.access.redhat.com`.

Then run it with the same flags as above, substituting `ccib:latest` for the Quay image.

## Statement of Support

This project is a community-driven, open source project designed to forward CrowdStrike Falcon Intelligence Indicators to Chronicle.

While not a formal CrowdStrike product, this project is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT](SUPPORT.md) file.
