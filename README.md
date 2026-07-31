# gcheck - Google Credential Validator

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Validates exposed Google and Firebase credentials. Determines whether a credential is still active and what it can access.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output statuses](#output-statuses)
- [Credential types & probe scope](#credential-types--probe-scope)
- [Example output](#example-output)
- [Development](#development)
- [Legal & ethical use](#legal--ethical-use)
- [Changelog](#changelog)
- [License](#license)

## Requirements

Python 3.12+.

Core dependencies (`requests`) install automatically. Optional extras pull in
additional dependencies only if you need them:

| Extra | Adds | Needed for |
|:---|:---|:---|
| `service-account` | `cryptography` | `--service-account-file` |
| `maps-js` | `playwright` | `--maps-js-runtime` |
| `all` | both of the above | everything |

## Installation

```bash
git clone https://github.com/TheArqsz/gcheck.git
cd gcheck
python -m venv .venv
source .venv/bin/activate

pip install .            # core only
pip install ".[all]"     # or: pull in every optional extra

# Optional: required only for --maps-js-runtime
playwright install chromium
```

This installs a `gcheck` command. Running from a source checkout without
installing also works: `gcheck ...`.

## Usage

```bash
# Auto-detect type from a raw string
gcheck --value 'AIzaSy...'

# Auto-detect from a file (plain text, JSON, google-services.json, etc.)
gcheck --file leak.txt
gcheck --file ~/.config/gcloud/application_default_credentials.json

# Specific credential types
gcheck --api-key AIzaSy...
gcheck --access-token ya29...
gcheck --refresh-token "1//..." --client-id "..." --client-secret "..."
gcheck --service-account-file sa.json
gcheck --fcm-server-key "AAAA..."
gcheck --jwt "eyJ..."
gcheck --recaptcha-secret "6..."

# Probe only services matching a substring
gcheck --api-key AIzaSy... --only maps

# Supply known project IDs for deeper IAM probing
gcheck --access-token ya29... --project my-project-id
gcheck --access-token ya29... --project prod-a,prod-b --project prod-c

# Test a browser-restricted key with context headers
gcheck --api-key AIzaSy... --referer https://example.com/
gcheck --api-key AIzaSy... --android-package com.example.app --android-cert AA:BB:...
gcheck --api-key AIzaSy... --ios-bundle com.example.ios

# Active probes (explicit authorization required)
gcheck --file google-services.json --active --signup-email you@example.com

# Referrer dictionary attack mode
gcheck --api-key AIzaSy... --referer-wordlist domains.txt
gcheck --api-key AIzaSy... --referer-wordlist words.txt --referer-template https://FUZZ.example.com/
gcheck --api-key AIzaSy... --referer-wordlist referers.txt --referer-workers 40 --referer-timeout 5
gcheck --api-key AIzaSy... --referer-wordlist domains.txt --referer-delay 0.2

# Output and display options
gcheck --file leak.txt --json            # machine-readable JSON
gcheck --api-key AIzaSy... --no-color    # disable ANSI color
gcheck --api-key AIzaSy... -v            # verbose progress logs
gcheck --api-key AIzaSy... --show-all-results # always show all per-service results
gcheck --api-key AIzaSy... --finding-report # pentest-oriented finding report

# Optional Maps JavaScript runtime verification (Playwright)
gcheck --api-key AIzaSy... --maps-js-runtime
gcheck --api-key AIzaSy... --maps-js-runtime --referer https://example.com/

# Discover available service names and permissions
gcheck --list-services      # API-key service names for use with --only
gcheck --list-perms
```

For the full flag reference: `gcheck --help`

Wordlist format for `--referer-wordlist`:

- one value per line
- comments supported with `#`
- full referer values are used as-is (example: `https://app.example.com/`)
- bare domains are expanded automatically to both `https://<domain>/` and `http://<domain>/`
- optional placeholder mode via `--referer-template`, which must contain `FUZZ`
- progress is shown automatically in percentage steps during dictionary mode

## Output statuses

| Status | Meaning |
|:---|:---|
| `VALID` | Credential accepted; probe succeeded |
| `DENIED` | Authenticated but access denied (key restriction or missing IAM permission) |
| `DISABLED` | API not enabled on the project |
| `INVALID` | Credential rejected (malformed, revoked, or expired) |
| `UNKNOWN` | Inconclusive response |
| `ERROR` | Network or runtime error |

### Maps JavaScript API note

The `Maps: JavaScript API` bootstrap endpoint can return HTTP 200 even when the key
is invalid or restricted at runtime in a real browser. By default this check may return
`UNKNOWN` with a runtime restriction message. Use `--maps-js-runtime` for an optional
headless browser probe that classifies runtime behavior more directly.

## Credential types & probe scope

| Credential | Probes |
|:---|:---|
| Google API key | Maps (Geocoding, Roads nearestRoads, Places legacy Text/Nearby/Find Place/Autocomplete, Directions, Distance Matrix, Elevation, Timezone, Static, Street View, JS), Places API (New) text search, Routes API computeRoutes, Geolocation API, Android/iOS/Referrer restriction detection, YouTube Data, Translate v2, Safe Browsing v4, Web Risk v1, Gemini, Firebase Auth, FCM legacy, Firestore REST (when project IDs are provided) |
| OAuth2 access token | tokeninfo, OIDC userinfo, Resource Manager project list, IAM `testIamPermissions`, GCS buckets, Compute zones, IAM service accounts |
| OAuth2 refresh token | Token exchange → same as access token |
| Authorized user JSON (`type=authorized_user`) | Refresh-token exchange using embedded client credentials → same as access token |
| Service account JSON | Key parse, JWT exchange → same as access token |
| Firebase config / `google-services.json` | Realtime Database read, Storage bucket list, Remote Config fetch, Firebase Auth lookup, plus API key probes for each embedded key |
| Legacy FCM server key | FCM `/fcm/send` with `dry_run: true` |
| JWT | Local decode, tokeninfo lookup |
| reCAPTCHA secret key | `siteverify` with a dummy response token |

### Default IAM permissions tested

Applied via `testIamPermissions` on each visible GCP project (access token and service account flows). Override with `--perms-file`.

```
resourcemanager.projects.get                  resourcemanager.projects.getIamPolicy
resourcemanager.projects.setIamPolicy         iam.serviceAccounts.list
iam.serviceAccounts.actAs                     iam.serviceAccounts.getAccessToken
iam.serviceAccountKeys.create                 storage.buckets.list
storage.buckets.get                           storage.objects.list
storage.objects.get                           storage.objects.create
compute.instances.list                        compute.instances.get
compute.instances.setMetadata                 compute.projects.get
compute.projects.setCommonInstanceMetadata    container.clusters.list
container.clusters.get                        cloudfunctions.functions.list
cloudfunctions.functions.call                 secretmanager.secrets.list
secretmanager.versions.access                 cloudkms.cryptoKeys.list
cloudkms.cryptoKeyVersions.useToDecrypt       logging.logEntries.list
monitoring.timeSeries.list                    bigquery.datasets.get
bigquery.jobs.create                          pubsub.topics.list
pubsub.subscriptions.list                     cloudsql.instances.list
spanner.databases.list                        appengine.applications.get
dns.managedZones.list                         run.services.list
```

## Example output

```
$ gcheck --api-key AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

[VALID]   Maps: Geocoding                   200  geocoding accepted
[VALID]   Maps: Places (Text)               200  places accepted
[DISABLED] YouTube Data: search             403  API not enabled on project
[DENIED]  Firebase Auth: createAuthUri      403  API key blocked by app/referer restrictions

Summary: VALID:2  DENIED:1  DISABLED:1
```

## Development

Repository layout:

- `gcheck.py`: CLI entry point for argument parsing, credential auto-detection dispatch, and output formatting.
- `checks/_common.py`: shared `Result`/`Status` types, HTTP helpers, and output printing used by every check module.
- `checks/*.py`: one module per credential type (`api_key.py`, `oauth_token.py`, `service_account.py`, `firebase.py`, `fcm_legacy.py`, `refresh_token.py`, `android_key.py`, `maps_js_runtime.py`), plus `detect.py` for auto-detecting credential type from raw input.

Adding a new check:
1. Add a module in `checks/` that returns a list of `Result` objects using the `Status` enum from `_common.py`.
2. Wire it into `detect.py` for auto-detection and into `gcheck.py`'s argument parser for an explicit flag.
3. Anything that creates or mutates state on the target (not just reads) must be gated behind `--active`, matching the existing modules.

No automated test suite exists yet. Verify changes manually against a real, authorized credential before submitting a PR.

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/). This is enforced by the `commitlint` CI check on every PR and drives the automated changelog and version bump.

## Legal & ethical use

This tool is intended for authorized security testing and educational purposes only. Only use it against credentials and systems you own or have explicit written permission to test. The authors accept no liability for misuse.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes, generated automatically from commit history.

## License

MIT
