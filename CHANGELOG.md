# CHANGELOG

<!-- version list -->

## v0.2.1 (2026-08-04)

### Bug Fixes

- **api-key**: Detect Gemini unrestricted-key rejection (401 + API_KEY_SERVICE_BLOCKED)
  ([`6bad9f3`](https://github.com/TheArqsz/gcheck/commit/6bad9f39f74f4dcd1faeca98f00f97a1c2d311c1))


## v0.2.0 (2026-08-01)

### Bug Fixes

- **cli**: Support comma-separated values for --only
  ([`d1d7f5a`](https://github.com/TheArqsz/gcheck/commit/d1d7f5a8c18525370e1dc8abe0636275ac16518c))

### Features

- **api-key**: Add Geolocation API probe
  ([`1331c84`](https://github.com/TheArqsz/gcheck/commit/1331c8403aca7f2ca417286b9a5d8cc8dec9b788))

- **api-key**: Add Maps Distance Matrix, Elevation, Timezone probes
  ([`72839f6`](https://github.com/TheArqsz/gcheck/commit/72839f60628db111816c9ed28a867244ef003f19))

- **api-key**: Add Maps Embed API probe
  ([`ec99b35`](https://github.com/TheArqsz/gcheck/commit/ec99b351721c4495998c7a2962c42fd47d74a2cb))

- **api-key**: Add Maps Find Place from Text and Autocomplete probes
  ([`ce5edc4`](https://github.com/TheArqsz/gcheck/commit/ce5edc430edf478491de81dd06ecb26ce61d5f22))

- **api-key**: Add Maps Roads (nearestRoads) probe
  ([`10d01e2`](https://github.com/TheArqsz/gcheck/commit/10d01e246bd2fbb78b3e7f96aeb10f56ef786326))

- **api-key**: Add Maps Street View Static probe
  ([`d71b1ed`](https://github.com/TheArqsz/gcheck/commit/d71b1ed9c6ff478c75c8c28fabf235fed644f19a))

- **recaptcha**: Add reCAPTCHA secret key detection and validation
  ([`265c8ac`](https://github.com/TheArqsz/gcheck/commit/265c8ac2fd49b84d721a55e56a1be2714d9bdd23))


## v0.1.2 (2026-07-31)

### Bug Fixes

- **api-key**: Stop misclassifying disabled Gemini API as invalid key
  ([`b782710`](https://github.com/TheArqsz/gcheck/commit/b782710429d2c16b6ffaeb1c18054b74d578e64c))

- **maps-js-runtime**: Give clean error when chromium isn't installed
  ([`3211bd5`](https://github.com/TheArqsz/gcheck/commit/3211bd506a5ec752d2b93c3d5c4caa8fad719523))

### Documentation

- **readme**: Remove audit log footprint table
  ([`cee30f7`](https://github.com/TheArqsz/gcheck/commit/cee30f707c1952c680c5cf347b98909134ef91c3))


## v0.1.1 (2026-07-31)

### Bug Fixes

- **packaging**: Repair broken build backend and consolidate dependencies
  ([`8b9c034`](https://github.com/TheArqsz/gcheck/commit/8b9c0342cf15f1a6064801d2cbf5ba2c04d10019))

### Chores

- Set package-ecosystem to 'pip' in dependabot config
  ([`8ec8588`](https://github.com/TheArqsz/gcheck/commit/8ec858879e894e925d38b3f60500edfd1fde1af3))

- **github**: Add bug report and feature request issue templates
  ([`52797fd`](https://github.com/TheArqsz/gcheck/commit/52797fd9a76cb0ccaaf57d3cc474dd0f182464a7))

### Documentation

- Align README with actual packaging, add development and changelog section
  ([`684ff5f`](https://github.com/TheArqsz/gcheck/commit/684ff5f501a4e918b1a34e8e1de1f354a4a69ed1))


## v0.1.0 (2026-07-31)

- Initial Release
