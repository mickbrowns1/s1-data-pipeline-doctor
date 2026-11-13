# Changelog

All notable changes to Data Pipeline Doctor are documented here. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.7] - 2026-11-13

Everything merged since v1.6 (2026-09-29): the container-recreate and
site-ownership fixes, a saved rebuild recipe, port add/remove improvements,
HEC and Syslog testers, and WEF/WEC integration.

### Changed

- Syslog and HEC tester/stream events now include the pipeline they were
  sent to (`pipeline=<id>:<port>` in the event body, e.g.
  `pipeline=100000000000004413:8001`) — useful once a site has more than
  one Syslog or HEC source. The id is the dataplane's own entity id (the
  console's own component name isn't in the dataplane config, only on the
  control-plane side, so it isn't available here); the port makes each
  pipeline distinct without needing the optional names file. (2026-11-02)
- Syslog tester and Syslog stream (options 13-14) now gate on an actual
  Syslog/CEF/LEEF source existing in the dataplane config, the same way
  the new HEC tester gates on a HEC source — previously any published port
  that didn't look like a known HEC/Kafka port was offered as a "(custom)"
  syslog target even with no syslog-type source configured on it at all.
  Reading `/etc/dataplane/config.yaml` surfaced a port-remap quirk: a
  privileged port the console lets you choose (e.g. `514/udp`) is actually
  bound inside the container on an unprivileged one (`10514/udp`) — already
  handled by `_dp_port_role`'s existing 514/10514 and 514/1514 pairings, so
  matching now accepts either that recognized shape or a literal port-number
  match against the source's own configured address. Verified against a
  live Syslog UDP source (`514` → `10514` remap) and a HEC-only site (now
  correctly refuses instead of offering a HEC port as a syslog target).
  (2026-11-02)
- New Site Setup now offers to paste the `.env` contents in directly as
  the default option (Enter = yes) instead of defaulting to waiting on a
  file copy. Copying the file to `~/ai-data-pipelines.env` beforehand still
  works and is detected automatically, skipping the prompt. (2026-10-30)

### Added

- **Remove a published port** (menu 12 → Remove a port). Source ports could add a
  published port but never take one away, so a mistyped mapping meant editing the
  compose file by hand. It lists the published ports with their roles, warns
  first if a source is still listening on the one you picked (its data would
  stop), and recreates the container without it — Compose sites by editing the
  file (every entry for that host port, so a duplicate goes too; the `ports:` key
  is dropped if it empties; backed up, with rollback), plain `docker run` sites by
  rebuilding the command without that `-p`, with the usual renamed backup. It only
  unpublishes the port on this host; the source in the console is not touched.
  (2026-11-13)
- **HEC on 8001–8005.** "HEC push" in New Site Setup and Source ports → Add now
  asks which port — 8088 or 8001–8005 (the HEC tester examples already used
  8001/8002) — and, like every preset, the prompt after it lets you type any
  other port. Those ports are labelled "HEC push" in the published-ports list.
  (2026-11-13)
- Source ports (menu 12) opens with the ports the container already publishes,
  with each one's role, and then asks Add / Remove / Back, so you see what's
  defined before choosing. (2026-11-13)
- **Saved rebuild recipe.** A recreate reads the live container, so it was only
  as good as the container: if the container or the host was lost there was
  nothing to rebuild from, and with no running container the Doctor went
  straight to "set up a new site". For a plain `docker run` site it now keeps
  `~/.data-pipeline-doctor/<name>.recipe` — the full `docker run`, with no
  secrets inline — next to the env file it already wrote (`<name>.env`, mode
  600, directory mode 700). It is retaken whenever the container changes
  (the previous five versions are kept as `<name>.recipe.<timestamp>`) and
  shown in the menu header. When no container is running and a recipe
  exists, the Doctor offers to rebuild from it exactly as it was, after
  checking the env file, the image and any mounted host paths (a missing one
  would otherwise be created empty and root-owned). Anything the recipe
  couldn't capture is listed in it as `# NOT CAPTURED`. Compose-managed
  sites are skipped — their compose file is the recipe. Note: the env file
  (which holds the site secrets) is now written the first time the Doctor
  sees a site, not only when it recreates it. (2026-11-13)
- HEC tester (Tools 15) and HEC stream (Tools 16), mirroring the Syslog
  tester/stream pair (options 13–14) but for Splunk HEC-push sources: send
  a real `POST /services/collector/event` to a published HEC port, either
  once or on a loop, reading the source's address, TLS flag, and token
  straight from `/etc/dataplane/config.yaml` the same read-only way
  `_dp_wef_read_config` does for WEF. Both only find a source if one is
  actually configured — with none, they say so and point at adding a HEC
  source in the console, same as the Syslog tester does when no
  syslog-capable port is published. When more than one HEC source is
  configured, offers a picker; when exactly one is found and published,
  auto-selects it. The token is read to build the request's `Authorization`
  header but is never printed. Verified against a live site with two HEC
  sources: both sent (HTTP 200), and a deliberately wrong token was
  rejected (HTTP 401). (2026-11-02)
- WEF/WEC menu (Tools 17), options 3–5 (2026-10-30):
  - **Windows forwarder setup.** Shows the site's collector address, CA
    thumbprint and subscription manager string, plus the steps for each
    Windows forwarder. It can write `wef-forwarder-setup.ps1`, which is
    ASCII-only so Windows PowerShell 5.1 parses it, and safe to re-run on
    a configured forwarder. The script was run on a live forwarder.
  - **TLS endpoint test.** Checks the certificate's SAN, CA chain, key
    match, expiry and EKU, does a verified handshake on the container
    port, and checks the published host port. It uses the container's
    OpenSSL.
  - **Forwarder activity.** Shows, per forwarder, connections and
    last-seen time; events in total and per hour; TLS handshake failures
    by cause; and recent WEF errors. The parser works with POSIX awk.
  - The cert install helper from the original design was dropped: the
    console can't select certificates placed on the host, so it wouldn't
    help.
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
  a read-only WEF readiness section, and a new Docker menu option 17 offers
  a read-only readiness check (source found, port published, checkpoint
  store, cert readability, FIPS mode, last error, forwarders seen) plus
  "Make this site WEF-ready" — applies the checkpoint store, cert mount,
  and FIPS-disable fixes in one recreate. Adds `_dp_compose_set_env` (same
  idempotent-awk pattern as the other Compose-sync helpers) and extends
  `_dp_build_run_cmd` with a `DP_EXTRA_ENV` global for the raw-`docker run`
  recreate path. (2026-10-30)
- WEF/WEC follow-ups from the live Make-ready test (2026-10-30):
  - A "yes" at startup now leads somewhere. Once the container is found,
    Doctor checks WEF readiness and offers "Make it WEF-ready now? [Y/n]",
    and the answer itself is acknowledged.
  - The Full diagnostic scan raises a single `wef-not-ready` issue, and
    the fix pass runs Make-ready for it. That replaces the checkpoint-only
    fix, which used to leave the certs and FIPS broken.
  - The host cert directory prompt defaults to `/etc/s1/wef` (the vendor
    guide's path), or to the source's own cert folder when it exists on
    the host.
  - Turning FIPS off also updates `OPENSSL_CONF` in the Compose service's
    `env_file`, backed up first, so it no longer disagrees with the
    Compose override.
  - Every private key in the cert folder is set to 600. Before, only the
    first `.key` found was, and the rest stayed world-readable.
  - Files written under sudo get the invoking user's group as well as
    their owner.
  - Every prompt exits cleanly on EOF, not just the two top-level menus.
  - When Doctor runs without root against a root-owned Compose file, it
    warns at startup. Make-ready stops with a `sudo` hint before it
    writes anything.
- WEF-ready new-site setup. With WEF/WEC mode on, a new Docker site is
  built WEF-ready on its first start, with no later recreate. Setup asks
  for the WEF listener port (default 5986) and publishes it. It mounts
  `/etc/s1/wef` read-only, creating it owned by uid 1000, plus the
  checkpoint store, and offers to turn FIPS off in the env file (with a
  warning, default No). It finishes with next steps: certs still to copy,
  the console source's listen address, callback and cert paths, the
  Windows subscription manager string, and Tools 17 → 1 to verify.
  Right after this setup, the startup readiness check is skipped, because
  the console hasn't pushed the pipeline yet. (2026-10-30)

### Fixed

- New Site Setup's port step gave no way to change a preset's port: picking
  "HEC push" always meant `8088:8088`, so a site that wanted HEC elsewhere had to
  pick "Custom" and retype everything — and picking the same preset twice by
  mistake wrote the mapping into the compose file twice. Setup now uses the same
  prompt as Source ports → Add: the preset only suggests a port ("default 8088 —
  or type a different port") and accepts `HOST`, `HOST:CONTAINER` or `/udp`.
  Both flows now refuse a mapping that was already added, or that reuses a host
  port/protocol already taken (Source ports checks what the container already
  publishes), and validate ports as 1–65535. (2026-11-13)
- A site set up (or later edited) through Doctor run under `sudo` no longer
  ends up with root-owned `ai-data-pipelines.env` and
  `docker-compose-observo.yml`. Those files were written as root, so the
  login user got `open …/ai-data-pipelines.env: permission denied` from the
  very `docker compose … [up -d|down|logs|restart]` command New Site Setup
  prints as its closing hint, and had to use `sudo` for everything. New Site
  Setup now hands both files to the invoking user; the compose helpers (open
  a port, memory limit, add a mount, set an env value) keep the file's owner
  and mode when they rewrite it (a bare `mv` of the temp file used to give a
  user-owned 640 file to root with mode 644); and the compose backups keep
  their owner. A site already set up that way is repaired the next time
  Doctor runs under `sudo`: root-owned env/compose files (symlinks are left
  alone — the real file may be shared) are handed back and it says so.
  (2026-11-13)
- Doctor no longer replaces a symlinked env or compose file with a local copy
  when it edits it. The compose helpers (open a port, set the memory limit, add
  a mount, set an environment value) write a temp file and `mv` it over the
  original, and the FIPS env edit uses `sed -i`; a rename onto a symlink
  replaces the symlink itself, so a site whose `~/ai-data-pipelines.env` or
  `~/docker-compose-observo.yml` pointed at a shared (e.g. NFS) copy silently
  stopped sharing on the first edit. A new `_dp_real_path` helper resolves a
  file to its real path only when it is a symlink, so regular files take the
  exact same path as before (verified byte-identical output on Debian and
  Fedora). If `readlink -f` is unavailable the original path is used.
  (2026-11-03)

- Recreating the container (editing source ports, adding mounts, restoring a
  backup, make-ready) no longer drops `--tmpfs /etc/secrets`. Docker doesn't
  list `--tmpfs` mounts under `.Mounts`, only under `HostConfig.Tmpfs`, so the
  rebuilt `docker run` silently came back without the in-memory secrets
  mount and the container's secrets landed in its writable layer on disk.
  `_dp_build_run_cmd` now carries `HostConfig.Tmpfs` over. (2026-11-13)
- The same recreate also silently reset every other setting it didn't know
  about: network mode (a `--network host` site came back on the default
  bridge with its listeners unreachable; user-defined networks lost their
  aliases and fixed IP), `--dns`/`--dns-search`/`--add-host`, `--user`,
  `--group-add`, `--ulimit`, `--cap-add/--cap-drop`, `--privileged`,
  `--security-opt`, `--read-only`, `--sysctl`, `--device`, `--init`, log
  options, pids/shm/cpu/memory-reservation/oom limits, explicit `--hostname`,
  `--workdir`, stop signal/timeout, labels, and an entrypoint/command
  override. All are now carried over, each only when it differs from the
  image's own default, so an unmodified site's command is unchanged. What a
  plain flag can't restore (extra networks beyond the first, a custom health
  check, IPC/PID/UTS/userns modes, `--runtime`, `--volumes-from`, `--link`,
  `-P`, an inline seccomp profile) is listed in a warning before the
  recreate instead of being dropped silently. Compose's own labels are left
  off a `docker run` recreate. (2026-11-13)

- Make this site WEF-ready (Tools 17 → 2) no longer "succeeds" with a plain
  restart when the running container is stale. It used to decide nothing needed
  changing by comparing the Compose and env *files* before and after its own
  edits; when those files already held the changes (another host's Doctor, a
  file sync, or a hand edit got there first) it only ran `docker restart`,
  which never applies Compose or env changes, so the container kept running
  with no cert mount, no checkpoint store, FIPS on, and its port unpublished.
  It now restarts only when the container already has the checkpoint mount, no
  FIPS change is pending, and the cert directory is mounted (a permissions-only
  problem); in every other case `docker compose up -d` recreates it. Normal
  single-site behavior is unchanged. Reproduced by rebuilding a standby from a
  pre-WEF compose backup while the real compose file was current: the patched
  Make-ready recreated it with both mounts. (2026-11-03)
- New Site Setup's Syslog TCP/TLS/UDP port presets published the host port
  to a *different* container port (`514:10514`, assuming a privileged-port
  remap inside the container). That assumption was wrong: the dataplane
  binds directly to whatever address the console source is configured
  with — a source on `0.0.0.0:514` is a real process bound to literal port
  514 inside the container (confirmed via the owning PID's open file
  descriptors), not 10514. The old preset left nothing listening on the
  published side, so Syslog UDP traffic silently vanished with no error
  anywhere — the tester still reported success since UDP sends don't
  confirm delivery, and nothing showed up in SDL. Presets now publish the
  same port on both sides (`1514:1514`, `6514:6514`, `514:514/udp`),
  matching what the Source ports menu (option 12) already did correctly.
  The Syslog tester's own port picker had the same remap assumption baked
  into its matching logic and has been fixed the same way: a port is only
  offered if the container-side port literally equals a configured
  source's address port. Found and fixed live after a real test event
  sent to a `514:10514` mapping never reached SDL. (2026-11-02)
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
