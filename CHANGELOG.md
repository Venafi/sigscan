# Unreleased

## Security

* Migrated `go-github` from v49 to v73 (SC-001 / VC-53649) — closes 24-major-version gap; API-compatible.
* Updated `golang.org/x/crypto` v0.50.0 → v0.53.0 (pulls x/net, x/term, x/text) — closes known CVE surface.
* Removed stale `github.com/sassoftware/relic v7.2.1+incompatible` require (SC-003 / VC-53620) — dual-version resolved; only `relic/v7` remains.
* Note: `xi2/xz`, `streadway/amqp`, `tjfoc/gmsm` are required by `sassoftware/relic/v7` and `sigstore/cosign/v2` respectively; cannot be excluded without upstream changes (VC-53649 SC-002, VC-53620 LIC-001, VC-53678 SC-008 — tracked for upstream fix).

# v0.3.0

## Enhancements

* Registry compatibility improvements.
* Windows support
* Experimental SBOM/artifact signature discovery