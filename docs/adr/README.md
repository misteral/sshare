# Architecture Decision Records

Short, numbered records of decisions that shape sshare's architecture or security posture —
the *why* behind a choice, kept next to the code. Format is [Nygard](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
(Context / Decision / Consequences). A shipped ADR is **immutable**, like a CHANGELOG entry:
a later decision supersedes an earlier one by adding a new ADR that references it, never by
editing the old one.

Design *proposals* — with alternatives weighed — live in
[../design-docs/](../design-docs/); an ADR records a *decision* and may point at a design doc
for the detail.

| ADR | Status | Title |
|---|---|---|
| [0001](0001-first-security-review.md) | Accepted — 2026-09-02 | First security review — internal and adversarial; no third-party audit claimed |
