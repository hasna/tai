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

Measured by execution against `src/redaction.ts` at `127ffc4` on 2026-07-31
(UTC), station02. 31-shape probe, synthetic fixtures throughout — no real credential is used or rendered at any point.

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
| `sk-`, `gsk_`, `csk-`, `AKIA…` provider keys | redacted |
| `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*` assignments | redacted |

Two details are load-bearing and easy to undo by accident:

1. **The `authorization` key pattern carries no `\b`.** `_` is a word character,
   so a leading `\b` can never match inside `HTTP_AUTHORIZATION` or
   `proxy_authorization`. That single fact accounted for an entire family of
   leaks. The match simply starts at `authorization` and leaves any prefix
   outside the match, which produces identical output.
2. **The key is not prefixed with `[A-Za-z0-9_-]*`.** A star before the literal
   makes the scan quadratic on long inputs.

   **Two corrections to what this note used to say, both measured on
   station02 with the regexes read from source rather than retyped.**

   *The sibling's quadratic is `URL_USERINFO_PATTERN`, not
   `redactNamedAssignments`.* Earlier versions of this note cited
   `hasnaxyz/iapp-sms` as carrying a `~8.4s/50k` quadratic in
   `redactNamedAssignments`. Per-pattern at n=50000 on a single repeated
   character: `URL_USERINFO_PATTERN` 2947ms, `NAMED_ASSIGNMENT_PATTERN`
   0.2ms. The difference is the **anchor**, not the star —
   `NAMED_ASSIGNMENT_PATTERN` opens with `(^|[^A-Za-z0-9_-])` so an unbroken
   alnum run has one viable start position, while `URL_USERINFO_PATTERN`
   opens with a bare `[a-z]` and retries at every position. The `~8.4s`
   figure was station01; `~2.9s` is station02. Quote the box with the number.

   *And `tai` is NOT exempt.* This note used to say `tai` "stays at
   single-digit milliseconds on the same input". That is true **only** for
   the single-repeated-character input (0.6ms at 50k, 2.0x per doubling),
   and it was read as "`tai` has no quadratic", which is false. On an
   `authorization`-dense 50k run `redactSensitiveText` is **470ms at 4.0x
   per doubling — quadratic** (691ms on an all-lowercase `authorization`
   run). See the residual table. **One input class cannot establish the
   absence of a quadratic**, and generalising from one is exactly how this
   claim became wrong.

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
| a value **truncated before its closing quote**, e.g. a log line cut at a byte limit — `{"headers":{"authorization":"Basic <cred>` | honest gap | **Live.** The quoted alternative requires its closing `\2` and the unquoted branch cannot start, because `"` is excluded from `[^\s'"]+`. So the rule **does not match the line at all** and the whole line passes through **unredacted, with no `[REDACTED]` emitted anywhere**. That last part is the operationally important bit: **grepping logs for the marker to find affected lines will find none of them.** syslog truncates at 1024B; journald and CloudWatch truncate too, so this is a normal way a long JSON log line ends, not an edge case. `hasnaxyz/iapp-sms` closed this by making the closing quote optional (`\2?`); that fix has **not** been applied here. |
| `Cookie: session=<tok>` | honest gap | **Live.** Nothing keys on `session`. An agent logging an HTTP request is exactly where this appears, and it is not covered by the structural row below — `session=` **is** a recognisable key, just not one this file recognises. |
| `Set-Cookie: sid=<tok>; HttpOnly` | honest gap | **Live.** Same cause; `sid` is likewise not keyed on. |
| URL userinfo — `scheme://user:<tok>@host` | honest gap | **Live.** `tai` has no userinfo rule at all. `hasnaxyz/iapp-sms` redacts this via `URL_USERINFO_PATTERN`; this is a genuine divergence, not a shared gap. |
| PEM private key armour — a `-----BEGIN … PRIVATE KEY-----` block | honest gap | **Live.** No rule keys on PEM armour, and the body is bare base64 across newlines with no assignment shape to anchor on. (Written with an ellipsis on purpose so this row does not itself trip a secret scanner. Do not "fix" it back.) |
| `authorization.value=Basic <cred>` — `.` as a key separator | honest gap | **Live.** The trailing key run is `[A-Za-z0-9_-]*`, which excludes `.`, so the match stops at `authorization` and never reaches the `=`. |
| `authorization%3DBasic%20<cred>` — percent-encoded | honest gap | **Live.** Nothing percent-decodes free text before matching, so no key is ever seen. |
| quadratic blow-up in the `authorization` key rule | availability, P2 | **Live.** 470ms for a 50k `HTTP_AUTHORIZATION_` run and 691ms for a 50k lowercase `authorization` run, both at **4.0x per doubling** (station02). Cause: the **trailing** `[A-Za-z0-9_-]*` rescans the remaining run from every position the literal matches. `hasnaxyz/iapp-sms` fixed the identical shape by bounding that run at 32, which restored 2.0x per doubling there; the bound has **not** been applied here. Not addressed in this change, which is documentation only — bounding the run alters what the pattern accepts and must be re-run against the over-redaction set. |
| a bare high-entropy value with no recognisable key or prefix | honest gap | Structural. No keyword and no prefix means nothing to key on; this cannot be closed by pattern matching. |
| Unicode or non-ASCII spellings of header names | unmeasured | Never probed. Absence of a finding here is absence of evidence, not evidence of absence. |
| whether every runtime call site actually routes through this function | unmeasured | This file measures the function, not its callers. A correct redactor on a path nothing calls redacts nothing. |

**One over-redaction destroys data rather than masking it, and is not
intentional.** `authorization=denied user=bob reason=scope` becomes
`authorization=[REDACTED] reason=scope` — **`user=bob` is deleted**, because the
optional scheme group consumes `denied ` as a scheme and then eats the next
whole token. An adjacent audit field is silently lost. Fail-safe as to leaking,
but a log that quietly drops fields is its own defect. `hasnaxyz/iapp-sms` fixed
this with a lookahead; that fix is not here, and its own lookahead introduced a
separate regression, so this should be fixed deliberately rather than by copying.

`signature`-keyed values are redacted conservatively: any key containing
`signature` has its value masked, so `signature_algorithm=RSA-SHA256` is masked
too. That is intentional — over-masking a non-secret is cheap, and a signature
reaching a log is not.

## Divergence from `hasnaxyz/iapp-sms`

The two redactors are **not** symmetric, and assuming they are has already
produced wrong residual lists. Measured differences at the time of writing:

- `tai` leaks bare `Bearer <tok>`; `iapp-sms` does not (it has a dedicated rule).
- `iapp-sms` had a serialized-JSON string path that `tai` never had.
- `tai` does not redact URL userinfo; `iapp-sms` does.
- **Both are quadratic, on different inputs — an earlier version of this file
  implied `tai` was not.** On a 50k single repeated character `tai` is linear
  and fast (0.6ms) while `iapp-sms` is quadratic (2.9s, `URL_USERINFO_PATTERN`).
  On a 50k `authorization`-dense run `tai` is quadratic (470ms, 4.0x per
  doubling) while `iapp-sms` is now linear (0.7ms), because it bounded its
  trailing key run at 32 and `tai` has not.
- **`iapp-sms` has since diverged further and `tai` is behind on three fixes it
  has not received**: the optional closing quote for truncated lines, the
  bounded key run above, and preservation of the field beside the masked value.
  Conversely `iapp-sms` alone carries a scheme-skip lookahead that reintroduces
  a **misleading** leak for `Authorization: <Scheme> <non-sensitive-key>=<cred>`
  (measured 5 of 9 keys there, **0 of 9 here**). Neither repo's residual list is
  valid for the other — copying rows between them has already produced wrong
  lists twice.

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
