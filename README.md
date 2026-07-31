# gcheck - Google Credential Validator

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Validates exposed Google and Firebase credentials. Determines whether a credential is still active and what it can access.

Read-only by default. `--active` enables probes that create artifacts on the target (e.g. Firebase Auth sign-up) and requires explicit authorization.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output statuses](#output-statuses)
- [Credential types & probe scope](#credential-types--probe-scope)
- [Example output](#example-output)
- [Legal & ethical use](#legal--ethical-use)
- [License](#license)

## Requirements

Python 3.12+.

- Required dependencies: [requirements.txt](requirements.txt)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: required only for --maps-js-runtime
playwright install chromium
```

## Usage

```bash
# Auto-detect type from a raw string
python gcheck.py --value 'AIzaSy...'

# Auto-detect from a file (plain text, JSON, google-services.json, etc.)
python gcheck.py --file leak.txt
python gcheck.py --file ~/.config/gcloud/application_default_credentials.json

# Specific credential types
python gcheck.py --api-key AIzaSy...
python gcheck.py --access-token ya29...
python gcheck.py --refresh-token "1//..." --client-id "..." --client-secret "..."
python gcheck.py --service-account-file sa.json
python gcheck.py --fcm-server-key "AAAA..."
python gcheck.py --jwt "eyJ..."

# Probe only services matching a substring
python gcheck.py --api-key AIzaSy... --only maps

# Supply known project IDs for deeper IAM probing
python gcheck.py --access-token ya29... --project my-project-id
python gcheck.py --access-token ya29... --project prod-a,prod-b --project prod-c

# Test a browser-restricted key with context headers
python gcheck.py --api-key AIzaSy... --referer https://example.com/
python gcheck.py --api-key AIzaSy... --android-package com.example.app --android-cert AA:BB:...
python gcheck.py --api-key AIzaSy... --ios-bundle com.example.ios

# Active probes (explicit authorization required)
python gcheck.py --file google-services.json --active --signup-email you@example.com

# Referrer dictionary attack mode
python gcheck.py --api-key AIzaSy... --referer-wordlist domains.txt
python gcheck.py --api-key AIzaSy... --referer-wordlist words.txt --referer-template https://FUZZ.example.com/
python gcheck.py --api-key AIzaSy... --referer-wordlist referers.txt --referer-workers 40 --referer-timeout 5
python gcheck.py --api-key AIzaSy... --referer-wordlist domains.txt --referer-delay 0.2

# Output and display options
python gcheck.py --file leak.txt --json            # machine-readable JSON
python gcheck.py --api-key AIzaSy... --no-color    # disable ANSI color
python gcheck.py --api-key AIzaSy... -v            # verbose progress logs
python gcheck.py --api-key AIzaSy... --show-all-results # always show all per-service results
python gcheck.py --api-key AIzaSy... --finding-report # pentest-oriented finding report

# Optional Maps JavaScript runtime verification (Playwright)
python gcheck.py --api-key AIzaSy... --maps-js-runtime
python gcheck.py --api-key AIzaSy... --maps-js-runtime --referer https://example.com/

# Discover available service names and permissions
python gcheck.py --list-services      # API-key service names for use with --only
python gcheck.py --list-perms
```

For the full flag reference: `python gcheck.py --help`

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
| Google API key | Maps (Geocoding, Places legacy Text/Nearby, Directions, Static, JS), Places API (New) text search, Routes API computeRoutes, Android/iOS/Referrer restriction detection, YouTube Data, Translate v2, Safe Browsing v4, Web Risk v1, Gemini, Firebase Auth, FCM legacy, Firestore REST (when project IDs are provided) |
| OAuth2 access token | tokeninfo, OIDC userinfo, Resource Manager project list, IAM `testIamPermissions`, GCS buckets, Compute zones, IAM service accounts |
| OAuth2 refresh token | Token exchange → same as access token |
| Authorized user JSON (`type=authorized_user`) | Refresh-token exchange using embedded client credentials → same as access token |
| Service account JSON | Key parse, JWT exchange → same as access token |
| Firebase config / `google-services.json` | Realtime Database read, Storage bucket list, Remote Config fetch, Firebase Auth lookup, plus API key probes for each embedded key |
| Legacy FCM server key | FCM `/fcm/send` with `dry_run: true` |
| JWT | Local decode, tokeninfo lookup |

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

### Audit log footprint

| Operation | Leaves trace |
|:---|:---|
| API key probes | No |
| tokeninfo / userinfo | No |
| Resource Manager project list | Yes (Data Read) |
| `testIamPermissions` | No (exempt from Data Access logs) |
| Service account JWT exchange | Yes (`GenerateAccessToken`) |
| Refresh token exchange | Yes (token endpoint) |
| Firebase RTDB / Storage read | Yes (Firebase request log) |
| Remote Config fetch | Yes (fetch event) |
| Firebase Auth sign-up (`--active`) | Yes (Auth dashboard + Audit Logs) |

## Example output

```
$ python gcheck.py --api-key AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

[VALID]   Maps: Geocoding                   200  geocoding accepted
[VALID]   Maps: Places (Text)               200  places accepted
[DISABLED] YouTube Data: search             403  API not enabled on project
[DENIED]  Firebase Auth: createAuthUri      403  API key blocked by app/referer restrictions

Summary: VALID:2  DENIED:1  DISABLED:1
```

## Legal & ethical use

This tool is intended for authorized security testing and educational purposes only. Only use it against credentials and systems you own or have explicit written permission to test. The authors accept no liability for misuse.

## License

MIT
