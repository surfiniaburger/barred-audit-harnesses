# barred-audit-harnesses

Small, self-contained C harnesses used to independently adjudicate vulnerability predicates from the BARRED Track 1 evidence audit.

Each harness reproduces a single, concrete memory-safety claim from a code seed and observes whether the claimed bad operation is actually reachable. The goal is to separate **pipeline acceptance** (did a debate accept the claim?) from **independent correctness** (does the code actually do what the claim says?).

## Harnesses

### `harness60/` — GSSAPI `gss_get_mic` arbitrary-pointer dereference (seed 60)

Reproduces the claim that `gss_get_mic` dereferences an unvalidated `context_handle` (cast to `gss_union_ctx_id_t`) and reads `ctx->internal_ctx_id` / `ctx->mech_type` without a handle-registry or magic-number check.

The harness defines `gss_union_ctx_id_t` from the upstream mechglue layout and implements `val_get_mic_args` and `gss_get_mic` verbatim from the seed. `gssint_get_mechanism` is a faithful stub: the real mechglue (Sun GSSAPI glue, 1998) is not available as a linkable library in this environment, so the stub reproduces the dereference the real lookup performs (`mech_type->length`). The crash therefore demonstrates the mechanism in the reproduced `gss_get_mic` call sequence, not a property of a separately linked library.

**Observed result:** crash (SIGSEGV/SIGBUS) — the dereference is reachable given a crafted handle. Attacker reachability (whether any real caller passes attacker-influenced data) remains a separate, unresolved threat-model question.

### `harness70.c` — Perl `grow_gap` size_t wraparound (seed 70)

Reproduces the claim that `grow_gap` in HTML::Parser computes `SvGROW(sv, e_offset + grow + 1)` where `grow = repl_len - (s - t)`, and that an overflow wraps to a small allocation followed by an out-of-bounds `Move`.

The harness creates an SV, then calls `SvGROW(sv, 2)` — the wrapped value of `e_offset + grow + 1` when `grow` is maximal (`e_offset = 2`, `grow = (STRLEN)-1`) — under Perl 5.44.0 (`usemymalloc='n'`, system allocator).

**Observed result:** on Perl 5.44.0 (`usemymalloc='n'`, system allocator), `SvGROW(sv, 2)` (the wrapped value of `e_offset + grow + 1` when `grow` is maximal) returns without rejecting the size — SvGROW neither allocates a (possibly wrapped) small buffer nor croaks; it is effectively a no-op because the existing buffer is already at least that large. This confirms SvGROW does not detect the overflow. It does **not** demonstrate the subsequent out-of-bounds `Move`: executing that path in a way that reliably lands outside the buffer requires constructing an SV whose allocation is exactly the wrapped capacity and running the Move in an isolated/instrumented process, which this harness does not do. The residual risk (a wrapped small size leading to an undersized allocation and an OOB Move) stands on the arithmetic, not on this probe. Protection must come from checked arithmetic on the complete expression `e_offset + grow + 1`.

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
