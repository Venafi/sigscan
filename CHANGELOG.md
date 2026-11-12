# v0.4.0

## Bug Fixes

* Built with Go 1.27.3, which rejects certificate chains from the compromised eMudhra intermediate CAs (v0.3.0 was built with Go 1.20)
* Fixed `go vet` errors (non-constant format strings in `fmt.Errorf`)

## Security

* Updated `github.com/klauspost/compress` to v1.20.2 (GO-2026-6865), `golang.org/x/net` to v0.60.0 (GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6617) and `google.golang.org/grpc` to v1.83.2 (GO-2026-6348)
* Migrated `go-github` from v49 to v73 (SC-001 / VC-53649) — closes 24-major-version gap; API-compatible.
* Updated `golang.org/x/crypto` v0.50.0 → v0.53.0 (pulls x/net, x/term, x/text) — closes known CVE surface.
* Removed stale `github.com/sassoftware/relic v7.2.1+incompatible` require (SC-003 / VC-53620) — dual-version resolved; only `relic/v7` remains.
* Note: `xi2/xz`, `streadway/amqp`, `tjfoc/gmsm` are required by `sassoftware/relic/v7` and `sigstore/cosign/v2` respectively; cannot be excluded without upstream changes (VC-53649 SC-002, VC-53620 LIC-001, VC-53678 SC-008 — tracked for upstream fix).

## Others

* GitHub workflows take the Go version from go.mod
* Release workflow moved to the v4 artifact actions (v3 was retired by GitHub)

# v0.3.0

## Enhancements

* Registry compatibility improvements.
* Windows support
* Experimental SBOM/artifact signature discovery