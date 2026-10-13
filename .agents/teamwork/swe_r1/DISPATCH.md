## 2026-10-12T22:51:13Z
You are the SWE Light orchestrator for the net-specter project.

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter\.agents\teamwork\swe_r1
Project root: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter
Original request file: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter\.agents\teamwork\ORIGINAL_REQUEST.md

Task Requirements:
R1: Implement JA4 & JA4S Modern TLS & QUIC Fingerprint Engine in src/ja4.rs (< 500 lines).
R2: Wire CLI subcommand nspecter ja4 in src/cli.rs and src/main.rs.
R3: Write integration tests in tests/ja4_test.rs (< 500 lines).
R4: Update scripts/ARCHITECTURE_MAP.md, TASK_BACKLOG.md, ROADMAP.md, README.md, CHANGELOG.md.

Acceptance Criteria:
- All checks pass via `node scripts/check.mjs` and `node scripts/verify_assets.mjs` with exit code 0.
- All files modular (< 500-700 lines).
- 100% safe Rust, zero secrets, zeroize memory hygiene.

Maintain your progress in progress.md and BRIEFING.md inside your working directory.
When finished and all checks pass, report completion and handoff.md back to the sentinel.
