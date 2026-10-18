# barred-audit-harnesses

Small, self-contained C harnesses used to independently adjudicate vulnerability predicates from the BARRED Track 1 evidence audit.

Each harness reproduces a single, concrete memory-safety claim from a code seed and observes whether the claimed bad operation is actually reachable. The goal is to separate **pipeline acceptance** (did a debate accept the claim?) from **independent correctness** (does the code actually do what the claim says?).

## Harnesses

### `harness60/` — GSSAPI `gss_get_mic` arbitrary-pointer dereference (seed 60)

Reproduces the claim that `gss_get_mic` dereferences an unvalidated `context_handle` (cast to `gss_union_ctx_id_t`) and reads `ctx->internal_ctx_id` / `ctx->mech_type` without a handle-registry or magic-number check.

The harness defines `gss_union_ctx_id_t` from the upstream mechglue layout, implements `val_get_mic_args` and `gss_get_mic` verbatim from the seed, and supplies a stub `gssint_get_mechanism` that dereferences its `mech_type` argument (mirroring the real mechglue lookup). It calls `gss_get_mic` with a crafted handle whose `internal_ctx_id != GSS_C_NO_CONTEXT` (passes the NULL check) and whose `mech_type` points to unmapped memory.

**Observed result:** crash (SIGSEGV/SIGBUS) — the dereference is reachable given a crafted handle. Attacker reachability (whether any real caller passes attacker-influenced data) remains a separate, unresolved threat-model question.

### `harness70.c` — Perl `grow_gap` size_t wraparound (seed 70)

Reproduces the claim that `grow_gap` in HTML::Parser computes `SvGROW(sv, e_offset + grow + 1)` where `grow = repl_len - (s - t)`, and that an overflow wraps to a small allocation followed by an out-of-bounds `Move`.

The harness creates an SV, then calls `SvGROW(sv, (STRLEN)-1)` (a max-size request simulating the overflowed value) under Perl 5.44.0 (`usemymalloc='n'`, system allocator).

**Observed result:** the process exited with status 9 without returning to `main`; stdout contained the pre-SvGROW lines, the post-SvGROW line was not printed, stderr was empty. This does not establish *why* (allocator rejection vs. other internal checks) and does not generalize to other builds. It does show that on this build a max-size request does not silently succeed. The residual risk remains: SvGROW cannot tell that a *small* requested size is the result of an overflow, so if the arithmetic wraps to a small value, `SvGROW(sv, small)` allocates `small` bytes and the subsequent `Move` copies the full (large) span — the OOB write. Protection must come from checked arithmetic on the complete expression `e_offset + grow + 1`.

## Building

### harness60

```sh
cd harness60
cc -O1 -g harness.c -o harness
./harness
```

No external dependencies (standard C library only).

### harness70

Requires Perl development headers.

```sh
cc $(perl -MExtUtils::Embed -e 'ccopts') harness70.c $(perl -MExtUtils::Embed -e 'ldopts') -o harness70
./harness70
```

Tested with Homebrew Perl 5.44.0 on macOS (darwin). The harness includes `EXTERN.h` before `perl.h` (required for `EXTCONST`).

## Notes

- These harnesses are **diagnostic**, not security proofs. A crash on a crafted input demonstrates a memory-safety mechanism; it does not establish attacker reachability.
- Raw wait status, stderr, and build configuration should be recorded alongside any conclusion (see the CodeRabbit review notes in the audit reports).
- The corresponding evidence audits live in the `modular-metacog-swarm-v3` repository under `agent_training/silver-one/reports/`.
