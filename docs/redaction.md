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

Measured by execution against `src/redaction.ts`, with synthetic fixtures
throughout — no real credential is used or rendered at any point.

| shape | result |
|---|---|
| single-token `Authorization` values such as `Basic <b64>` or `Bearer <token>` (any scheme case) | redacted |
| `Authorization: Digest ... response="<digest proof>"` | redacted |
| parameterized `Authorization` schemes such as `Scheme sig=<proof>` or `MAC mac=<proof>` | redacted |
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
3. **The closing quote is optional, and parameterized schemes are redacted before
   adjacent-field preservation runs.** Both were found by adversarial review of
   the first version of this rule; see the covered table above. Neither is
   cosmetic — the first left a credential in every truncated log line, and the
   second could either delete adjacent fields or leave `sig=...` beside a marker.

**Correction carried forward from #13 — the sibling's quadratic is
`URL_USERINFO_PATTERN`, not `redactNamedAssignments`.** Earlier versions of this
note cited `hasnaxyz/iapp-sms` as carrying a `~8.4s/50k` quadratic in
`redactNamedAssignments`. Per-pattern at n=50000 on a single repeated character:
`URL_USERINFO_PATTERN` 2947ms, `NAMED_ASSIGNMENT_PATTERN` 0.2ms. The difference
is the **anchor**, not the star — `NAMED_ASSIGNMENT_PATTERN` opens with
`(^|[^A-Za-z0-9_-])` so an unbroken alnum run has one viable start position,
while `URL_USERINFO_PATTERN` opens with a bare `[a-z]` and retries at every
position. The `~8.4s` figure was station01; `~2.9s` is station02. Quote the box
with the number.

### Performance, measured rather than asserted

An earlier version of this file claimed this redactor had "no quadratic" and ran
in "single-digit milliseconds". **That was wrong, and it was wrong about `main`
as much as about the change that introduced the claim.** The quadratic is real:
on repeated `HTTP_AUTHORIZATION_` tokens, growth is **4.0×/doubling** on every
version measured, before and after. It is pre-existing and comes from the generic
`[A-Z0-9_]*…[A-Z0-9_]*` key rules, not from the Authorization rule. It is listed
as an open residual below rather than claimed absent.

**A SECOND CORRECTION, and it retracts this section's own previous numbers.**
This section used to carry a table reading `323.6ms` before and `323.8ms` after
at 50k, and concluded that the change "does not add to it, and does not remove
it". **Both halves of that conclusion are false, in opposite directions, and the
figures are not reproducible.** Re-measured per commit — station01, loadavg ~18,
median of 9 reps after a warmup pass at every size, reproduced in two independent
runs:

| version | auth-dense 50k | digest-shape 50k |
|---|---|---|
| `main` before this change (`47de35d`) | 1420ms | 2.6ms |
| commit 1 — truncation + adjacent-field (`9f52c8c`) | 923ms | 2.6ms |
| commit 2 — Digest `response=` rule (`4b10ea5`) | 955ms | **65ms** |
| merged (`62f8f14`) | 939ms | **60ms** |

Two effects, each attributable to one commit:

* **auth-dense got ~34% FASTER**, from commit 1 onward — 0.65–0.67× `main`,
  reproduced, and independently corroborated by two earlier measurements at
  0.66–0.67×. Not parity.
* **the digest shape got ~23× SLOWER**, and it starts exactly at commit 2, the
  commit that introduces the `response=` rule. 2.6ms → 65ms at 50k.

**The growth ratio, not the absolute figure, is what makes this checkable.** This
section already said absolute numbers move with machine load while ratios do not
— which is precisely why a *before/after ratio measured in one process on one
box* is load-independent evidence, and why 0.66× cannot be explained away as
"their host was busier". Growth stays 4.0×/doubling throughout, so the
pre-existing quadratic is unchanged; what moved is the constant factor, in both
directions.

Note the digest regression is a **constant-factor** change, not a new quadratic:
growth on that shape stays ~2.0×/doubling (linear) above 25k, with a reproducible
threshold jump between 12.5k and 25k. Calling it "a new quadratic" would be a
different and unsupported claim.

On bare repeated characters both are linear (~0.5ms at 50k).

## Not covered — known residuals

**Known leaking shapes measured at `127ffc4` on 2026-07-31 (UTC), station02.
This list is NOT exhaustive, and a shape's absence from it is not evidence
that the shape is safe.**

It records what was actually exercised: a 31-shape coverage probe and a
12-shape residual probe, both concentrated on the `authorization` /
`signature` family, each run with a positive control so an "absent" result
is an observation rather than a broken probe. Shapes outside that corpus were
not probed at all. The list therefore tells you **scope, never
completeness**. If you find a shape that leaks and is not here, add a row —
that is this file working, not this file failing.

| shape | class | why it is still open |
|---|---|---|
| bare `Bearer <token>` with no `authorization` key | honest gap | The only rule that closes it — `/Bearer\s+[A-Za-z0-9._~+/=-]+/gi`, which `hasnaxyz/iapp-sms` carries — over-redacts ordinary prose: `Bearer authentication is required` becomes `Bearer [REDACTED] is required`. Closing this gap would trade a marker-free gap for a real over-redaction regression. Deliberately deferred, not overlooked. |
| `Cookie: session=<tok>` | honest gap | **Live.** Nothing keys on `session`. An agent logging an HTTP request is exactly where this appears, and it is not covered by the structural row below — `session=` **is** a recognisable key, just not one this file recognises. |
| `Set-Cookie: sid=<tok>; HttpOnly` | honest gap | **Live.** Same cause; `sid` is likewise not keyed on. |
| URL userinfo — `scheme://user:<tok>@host` | honest gap | **Live.** `tai` has no userinfo rule at all. `hasnaxyz/iapp-sms` redacts this via `URL_USERINFO_PATTERN`; this is a genuine divergence, not a shared gap. |
| PEM private key armour — a `-----BEGIN … PRIVATE KEY-----` block | honest gap | **Live.** No rule keys on PEM armour, and the body is bare base64 across newlines with no assignment shape to anchor on. (Written with an ellipsis on purpose so this row does not itself trip a secret scanner. Do not "fix" it back.) |
| `authorization.value=Basic <cred>` — `.` as a key separator | honest gap | **Live.** The trailing key run is `[A-Za-z0-9_-]*`, which excludes `.`, so the match stops at `authorization` and never reaches the `=`. |
| `authorization%3DBasic%20<cred>` — percent-encoded | honest gap | **Live.** Nothing percent-decodes free text before matching, so no key is ever seen. |
| a bare high-entropy value with no recognisable key or prefix | honest gap | Structural. No keyword and no prefix means nothing to key on; this cannot be closed by pattern matching. |
| quadratic growth on repeated `*AUTHORIZATION*`-shaped tokens | availability, P2 | **Live and pre-existing**, 4.0×/doubling on every version measured. Comes from the generic `[A-Z0-9_]*…[A-Z0-9_]*` key rules. Fixing it means restructuring those rules, not widening a pattern. The absolute cost is **not** unchanged by this change — see the performance section: auth-dense is 0.66× (faster), the digest shape ~23× (slower). A `~324ms at 50k, byte-identical` figure previously stood here and is retracted as unreproducible. |
| digest-shape input costs ~23× more than before the `response=` rule | availability, P2 | **Live, and introduced by this change** at `4b10ea5`: a long `Authorization: Digest … response="` line goes 2.6ms → 60ms at 50k on station01. Growth stays linear (~2.0×/doubling), so this is a constant-factor regression rather than a new quadratic. Untriaged: the rule is correct and the input is adversarial-shaped, so this is a cost question, not a correctness one. |
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
- `tai` does not redact URL userinfo; `iapp-sms` does.
- **Both are quadratic, on different inputs — an earlier version of this file
  implied `tai` was not.** On a 50k single repeated character `tai` is linear
  and fast (0.6ms) while `iapp-sms` is quadratic (2.9s, `URL_USERINFO_PATTERN`).
  On a 50k `authorization`-dense run `tai` still has a generic-key quadratic
  path, because the `[A-Z0-9_]*…[A-Z0-9_]*` rules can retry from many positions.
- `tai` now carries the optional closing quote, bounded Authorization key run,
  adjacent-field preservation, and parameterized Authorization scheme guards in
  this file. Do not copy a residual list from another repo without re-running
  that repo's exact source.

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
