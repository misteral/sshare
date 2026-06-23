# Completed Execution Plans

Archived plans, kept so a later agent can reason about earlier decisions without needing a
human to re-supply context. Move a plan here from `../active/` when its sub-tasks are done;
append an outcome note (what shipped, what changed vs the plan).

- [connected-vaults.md](connected-vaults.md) — vault registry + `connect`/`disconnect`/
  `vaults` + `--vault` (shipped in v0.1.3).
- [signed-members.md](signed-members.md) — tamper-evident member list: SSHSIG signing +
  TOFU pinning + verify-before-encrypt (ships in v0.2.0).
