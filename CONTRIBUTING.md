# Contributing to Data Pipeline Doctor

Data Pipeline Doctor is a single bash script. Keep it that way — no new
language runtimes, no package managers, no external dependencies beyond
what's already required (`docker`/`kubectl`, `openssl`, optional
`python3`).

## Script organization

Entry point flow: `parse_args` → `preflight` → routes into either the
Kubernetes or Docker menu loop based on `--site-type`. The two menu systems
are independent but share the same dispatch pattern described below.

## The scan → issue → fix pattern

Every check is a **scan function** (`docker_scan_*` / the Kubernetes
equivalents). A scan inspects state — logs, `docker inspect`, `s6-svstat`,
pod status, whatever's relevant — and calls `add_issue("tag: message")`
when it finds something wrong. The tag is what routes the issue to a fix.

**Worked example:** `docker_scan_init` reads `control-plane-init`'s log and
classifies a failing retry loop into one of three tags by pattern-matching
the log text — `connectivity` (`EOF`/`connection refused`/timeout),
`tls-ca-trust` (`certificate signed by unknown authority`), or
`malformed-token` (`token is malformed`/`unauthorized`). Each tag has a
matching fix function (`docker_fix_connectivity`, `docker_fix_tls_ca_trust`,
etc.) that gets offered once the scan is done.

New checks should follow this shape: scan function raises a tagged issue,
fix function is named to match the tag, and the fix is only ever offered —
never applied — without the scan having found something first.

## Safety requirements for new fixes

- **Always confirm before changing anything.** Every existing fix function
  wraps its action in `confirm "..."` and only proceeds on an explicit yes.
  Don't add a fix that acts without asking.
- **Don't guess at values a recreate would need.** If a fix would require
  new mounts or env vars the tool can't determine safely on its own (a CA
  bundle path, a proxy URL), print the exact command and let the operator
  decide — see `docker_fix_connectivity` and `docker_fix_tls_ca_trust` for
  the pattern. Only auto-apply changes that are safe to make on a live
  container without guessing (see `docker_fix_oom`, which uses
  `docker update` directly since memory limits can change in place).
- **Preserve the recreate safety net.** Any fix that does recreate a
  container must rename the existing one to `<name>_old` before removing
  it, and print the one-line rollback
  (`docker rm -f` → `docker rename ..._old ...` → `docker start ...`). A
  bad recreate must always be reversible.

## Docker Compose state sync

If a fix changes anything a `docker compose up -d` recreate would read from
the compose file (ports, mounts, env, resource limits), it must also write
that change into the compose file when the site is Compose-managed —
otherwise the change is silently discarded the next time the site gets
recreated.

- Detect a Compose-managed container with `_dp_compose_info` — it checks
  the `com.docker.compose.project.config_files` label rather than assuming
  a path, and locates the real compose file from that.
- Two existing helpers follow the same shape and are the precedent to copy:
  `_dp_compose_add_port` (source ports) and `_dp_compose_set_mem_limit`
  (OOM memory bumps). Both are idempotent awk-based edits — update the key
  in place if it already exists, otherwise insert it near a stable anchor
  line (`container_name:` or an existing sibling key).

## Testing

- `tests/test-docker-install.sh` verifies OS detection and package-install
  logic against real base images in Docker. Run it (optionally against a
  single image by name) before touching anything in the OS-detection or
  install path.
- There's no formal unit-test runner for the rest of the script yet. For a
  self-contained function — the Compose-sync helpers are the example — the
  practice has been: write a small fixture compose YAML, source just the
  function under test, assert on the rewritten file's content, then confirm
  the result with `docker compose config` to make sure the real Compose
  parser still accepts it.

## Commit & PR conventions

- Branch names: `feature/<short-description>` or `fix/<short-description>`.
- Commit messages are Conventional-Commits-flavored: `feat(scope): ...`,
  `fix(scope): ...`, `chore: ...`, `docs: ...`.
- Open a PR against `main`. If your change adds, removes, or changes the
  behavior of a menu option or auto-fix, update `README.md`'s menu table
  and add an entry to `CHANGELOG.md`'s `[Unreleased]` section.
- Bump the version string (splash screen + banner) only for a
  release-worthy batch of changes, not on every PR.

## Questions

Mick Brown (mick.brown@sentinelone.com) owns the repo day to day.
