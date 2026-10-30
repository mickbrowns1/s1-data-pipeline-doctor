# Changelog

All notable changes to Data Pipeline Doctor are documented here. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

Changes merged since the v1.6 version bump that haven't shipped under a new
version string yet.

### Added

- Auto-fix for a Windows Event Forwarding source that fails to start with
  "No checkpoint store configured" on a Docker standalone site: writes a
  `dataplane-globals.yaml` and mounts it at
  `/etc/dataplane/dataplane-globals.yaml`, keeping the mount in a
  Compose-managed site's `docker-compose.yml` in sync via a new
  `_dp_compose_add_mount` helper (same pattern as the source-ports and OOM
  Compose-sync fixes). (`ae0b190`, 2026-10-29)
- WEF/WEC integration: a startup question (Docker sites only) asking
  whether this host manages WEF/WEC-forwarding sites, remembered in
  `~/.data-pipeline-doctor/profile`. When on, the Full diagnostic scan adds
  a read-only WEF readiness section, and a new Docker menu option 15 offers
  a read-only readiness check (source found, port published, checkpoint
  store, cert readability, FIPS mode, last error, forwarders seen) plus
  "Make this site WEF-ready" — applies the checkpoint store, cert mount,
  and FIPS-disable fixes in one recreate. Adds `_dp_compose_set_env` (same
  idempotent-awk pattern as the other Compose-sync helpers) and extends
  `_dp_build_run_cmd` with a `DP_EXTRA_ENV` global for the raw-`docker run`
  recreate path. (2026-10-30)

### Fixed

- OOM memory-limit fix now also updates `docker-compose.yml`'s `mem_limit`
  (and `memswap_limit`, if set) when the site is Compose-managed, so a live
  memory bump survives a future `docker compose up -d` recreate instead of
  being silently discarded. (`cca476b`, 2026-10-20)
- Source-ports fix now keeps a Compose-managed site's `docker-compose.yml`
  in sync when opening a new port, for the same reason. (`06f7c07`,
  2026-10-13)

### Changed

- Attribution updated to "Built by SentinelOne Architecture Team" following
  the repo's ownership transition. (`ff39afa`, 2026-10-20)

## [1.6] - 2026-09-29

### Added

- Paste `.env` contents directly into the terminal instead of requiring a
  file copy onto disk first — sidesteps wrong-home-directory,
  wrong-filename, and NFS/autofs directory-cache issues that were the most
  common cause of a stuck setup wizard.

### Fixed

- Fedora is now detected as its own OS family, separate from RHEL/Rocky/
  Alma, since it uses a different Docker CE repo path.
- The real invoking user's home directory is resolved correctly when the
  tool is run via `sudo` (previously could fall back to `/root`).

## [1.5] - 2026-06-24 to 2026-07-09

Initial public release, plus the fixes and features that landed in the
weeks immediately after it.

### Added

- Initial public release of Data Pipeline Doctor, covering both
  Kubernetes/K3s and Docker standalone sites.
- OS-aware Docker install guide plus a container-based test harness for
  verifying it (`tests/test-docker-install.sh`).
- Guided setup wizard for standing up a new Docker standalone site.
- Integrated syslog test event generator (menu option 13) and a continuous
  syslog stream mode (option 14).
- Non-blocking listener-status check when opening a new source port.

### Fixed

- Source ports now accept docker-style `host:container` port input.
- Hardened Docker site setup and the syslog sender's fallback chain.
- Compose-managed sites are now brought up with `docker compose` instead of
  a raw `docker run`; fixed a false-positive outbound-connectivity failure.
