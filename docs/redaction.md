# Log redaction — what `redactSensitiveText` covers, and what it does not

`src/redaction.ts` scrubs credentials out of text before it is displayed, logged
or returned over MCP. This file is the coverage record for that function.

It exists because the coverage record previously lived only in pull request
bodies. A PR body cannot be corrected once merged, is not greppable from a
checkout, and — most importantly — a reader who finds their shape handled in one
concludes the whole surface is closed. **A partial list that reads as exhaustive
is the same failure as a partial redactor that announces itself.** Keep this file
in the same change as any edit to `src/redaction.ts`.

## The failure mode this redactor is built around

A raw credential in a log is recognisably raw. A credential printed *after* a
`[REDACTED]` marker reads as already handled, so the next reader greps, finds it
masked where they looked, and stops. That output is worse than no redaction at
all, and every fix in this file's history has been one of them.

Two classes are therefore tracked separately below:

- **misleading** — the credential survives **and** a marker is printed. Treated as
  a defect to fix.
- **honest gap** — the credential survives with no marker. Still a gap, but it
  does not lie to the reader. Named here rather than silently carried.

## Covered

Measured by execution against `src/redaction.ts`, 31-shape probe, synthetic
fixtures throughout — no real credential is used or rendered at any point.

| shape | result |
|---|---|
| `Authorization: Basic <b64>` (any scheme, any case) | redacted |
| `authorization=Basic <b64>` — `=` instead of `:` | redacted |
| `authorization = Basic <b64>` — spaces around the separator | redacted |
| `HTTP_AUTHORIZATION=`, `AUTHORIZATION_HEADER=`, `authorization_header:` | redacted |
| `proxy_authorization=` (underscore) and `proxy-authorization=` (hyphen) | redacted |
| `X-Authorization:`, `Proxy-Authorization:` | redacted |
| the header anywhere in a line, not only at its start | redacted |
| `{"Authorization": "Basic <b64>"}` and nested serialized JSON | redacted |
| quoted, single-quoted and `export`-prefixed spellings | redacted |
| AWS SigV4 trailing `Signature=`, bare / in-header / in a query string | redacted |
| a line **truncated mid-value** by a byte limit, so the closing quote is missing | redacted |
| the value masked **without deleting the fields beside it** (`authorization=denied user=bob` keeps `user=bob`) | preserved |
| `sk-`, `gsk_`, `csk-`, `AKIA…` provider keys | redacted |
| `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*` assignments | redacted |

Two details are load-bearing and easy to undo by accident:

1. **The `authorization` key pattern carries no `\b`.** `_` is a word character,
   so a leading `\b` can never match inside `HTTP_AUTHORIZATION` or
   `proxy_authorization`. That single fact accounted for an entire family of
   leaks. The match simply starts at `authorization` and leaves any prefix
   outside the match, which produces identical output.
2. **The key run is bounded on both sides.** There is no `[A-Za-z0-9_-]*` before
   the literal, and the run *after* it is capped at 32. An unbounded run on
   either side rescans the remaining input from every position the literal
   matches, which is quadratic. A real key suffix is `_header` or similar, so the
   cap costs nothing.
3. **The closing quote is optional and the scheme is not consumed across a
   `key=value`.** Both were found by adversarial review of the first version of
   this rule; see the covered table above. Neither is cosmetic — the first left a
   credential in every truncated log line, the second deleted adjacent fields.

### Performance, measured rather than asserted

An earlier version of this file claimed this redactor had "no quadratic" and ran
in "single-digit milliseconds". **That was wrong, and it was wrong about `main`
as much as about the change that introduced the claim.** Measured on an idle
host, interleaved in one process, input of repeated `HTTP_AUTHORIZATION_` tokens:

| | 6.25k | 12.5k | 25k | 50k | growth |
|---|---|---|---|---|---|
| `main` before this change | 5.1ms | 20.1ms | 80.7ms | 323.6ms | **4.0×/doubling** |
| with this change | 5.1ms | 20.2ms | 80.5ms | 323.8ms | **4.0×/doubling** |

So: **this redactor already had a quadratic path on that input, this change does
not add to it, and this change does not remove it.** The growth ratio per
doubling is the load-independent statistic — absolute figures move with machine
load, ratios do not. On bare repeated characters both are linear (~0.5ms at 50k).

The quadratic is pre-existing and comes from the generic `[A-Z0-9_]*…[A-Z0-9_]*`
key rules, not from the Authorization rule. It is listed as an open residual
below rather than claimed absent.

## Not covered — known residuals

**This is the complete list as measured. It is short on purpose: if you find a
shape that leaks and is not here, that is a bug in this file as much as in the
code.**

| shape | class | why it is still open |
|---|---|---|
| bare `Bearer <token>` with no `authorization` key | honest gap | The only rule that closes it — `/Bearer\s+[A-Za-z0-9._~+/=-]+/gi`, which `hasnaxyz/iapp-sms` carries — over-redacts ordinary prose: `Bearer authentication is required` becomes `Bearer [REDACTED] is required`. Closing this gap would trade a marker-free gap for a real over-redaction regression. Deliberately deferred, not overlooked. |
| a bare high-entropy value with no recognisable key or prefix | honest gap | Structural. No keyword and no prefix means nothing to key on; this cannot be closed by pattern matching. |
| quadratic growth on repeated `*AUTHORIZATION*`-shaped tokens | availability, P2 | **Live and pre-existing**, 4.0×/doubling, ~324ms at 50k, byte-identical before and after this change. Comes from the generic `[A-Z0-9_]*…[A-Z0-9_]*` key rules. Fixing it means restructuring those rules, not widening a pattern. |
| Unicode or non-ASCII spellings of header names | unmeasured | Never probed. Absence of a finding here is absence of evidence, not evidence of absence. |
| whether every runtime call site actually routes through this function | unmeasured | This file measures the function, not its callers. A correct redactor on a path nothing calls redacts nothing. |

**Over-masking that is intentional, stated so it is not mistaken for a bug.**
Any key containing `signature` has its value masked, so `signature_algorithm=RSA-SHA256`
and `SignatureVersion=4` are masked too. Over-masking a non-secret is cheap; a
leaked signature is not. `hasnaxyz/iapp-sms` does **not** mask `SignatureVersion`
— its rule requires a `-`/`_` boundary — so the two repos genuinely differ here.
Both behaviours are pinned by tests so neither drifts silently.

The same applies to any key containing `authorization`: its value is masked even
when that value is not a secret, so `authorization=denied` becomes
`authorization=[REDACTED]`. What must **not** happen is the fields *beside* it
being deleted, which is a separate matter and is tested.

## Divergence from `hasnaxyz/iapp-sms`

The two redactors are **not** symmetric, and assuming they are has already
produced wrong residual lists. Measured differences at the time of writing:

- `tai` leaks bare `Bearer <tok>`; `iapp-sms` does not (it has a dedicated rule).
- `iapp-sms` had a serialized-JSON string path that `tai` never had.

A shared residual list would be wrong in a different direction for each repo.

## Testing rule — non-negotiable

**Assert that the credential literal is ABSENT. Never assert that a `[REDACTED]`
marker is PRESENT.** A marker-present assertion passes against every misleading
output above, and would certify these bugs as fixed.

`tests/redaction.test.ts` also carries a **positive control**: the same literal in
free prose is left alone and *is* found. Without it, `not.toContain` could be
passing vacuously. When changing a pattern, revert the production change, keep
the tests, and confirm they fail — a test that passes against the broken code
proves nothing.
