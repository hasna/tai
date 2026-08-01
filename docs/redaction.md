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
| `Authorization: Digest ... response="<digest proof>"` — the **plain header** form | redacted |
| the same Digest value inside JSON — `{"authorization":"Digest ... response=\"<proof>\""}` | redacted |
| `Hawk id="…", mac="<proof>"`, plain **and** inside JSON | redacted |
| parameterized `Authorization` schemes such as `Scheme sig=<proof>` or `MAC mac=<proof>` | redacted |
| `authorization=Basic <b64>` — `=` instead of `:` | redacted |
| `authorization = Basic <b64>` — spaces around the separator | redacted |
| `HTTP_AUTHORIZATION=`, `AUTHORIZATION_HEADER=`, `authorization_header:` | redacted |
| `proxy_authorization=` (underscore) and `proxy-authorization=` (hyphen) | redacted |
| `X-Authorization:`, `Proxy-Authorization:` | redacted |
| the header anywhere in a line, not only at its start | redacted |
| `{"Authorization": "Basic <b64>"}` — a JSON **object**, one level | redacted |
| quoted, single-quoted and `export`-prefixed spellings | redacted |
| AWS SigV4 trailing `Signature=`, bare / in-header / in a query string | redacted |
| `Cookie:` / `Set-Cookie:` — **every** `;`-delimited pair value, whatever the cookie is named (`session`, `sid`, `PHPSESSID`, `JSESSIONID`, `connect.sid`, `laravel_session`, `__Host-*`, `__Secure-*`) | redacted |
| the same, in any header spelling: `set-cookie:`, `HTTP_COOKIE=`, `cookie_header:`, `cookie=`, `cookie = `, `{"cookie":"…"}`, `'…'`, and a line truncated before its closing quote | redacted |
| a credential-bearing pair that is **not first** in the header — `Cookie: theme=dark; sid=<tok>; lang=en` | redacted |
| an RFC 6265 attribute name reused as a request cookie name — `Cookie: sid=1; path=/<tok>` / `domain=<tok>.example` | redacted |
| Set-Cookie attributes (`Path`, `Domain`, `Expires`, `Max-Age`, `SameSite`, `HttpOnly`, `Secure`, …) beside a masked cookie | preserved |
| ordinary log fields beside a cookie header (`cookie: sid=<tok> status=200 user=bob`) | preserved |
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
4. **The cookie rule's exemption table lists ATTRIBUTES, not cookie names, and
   that direction is the whole point.** Cookie names are chosen by the
   application and are unbounded, so a table of credential-bearing names fails
   OPEN on the next framework. RFC 6265 §4.1.1 fixes the *attribute* vocabulary,
   and RFC 6265bis adds `Partitioned` — a closed set. The exemption is applied
   only in the `Set-Cookie` direction; request `Cookie` headers have no
   attributes, so every pair is masked even when its name is `path`, `domain` or
   another RFC attribute word. In `Set-Cookie`, the attribute's **value shape** is
   checked as well as its name, and the **first pair is never exempt**, so
   `Set-Cookie: sid=1; path=<credential>` does not walk through the exemption.
   Both properties are pinned by tests.
5. **Those value shapes were measured too loose to be that guard, and the note
   claiming otherwise had generalised from one fixture.** `expires` was
   `^[A-Za-z0-9:+-]{1,32}$` — not a date check in any meaningful sense, but
   precisely the shape of a 32-character session id — and `domain` was
   length-unbounded and matched an 87-character JWT-shaped token; 12 of 14
   attribute-named probes preserved a synthetic credential. `expires` now takes
   only an RFC 1123 weekday, `domain` requires bounded labels and a **purely
   alphabetic final label**, `max-age` an integer. A value longer than
   `MAX_COOKIE_ATTRIBUTE_VALUE` (256) never reaches a shape test at all and is
   masked — which fails closed *and* removes an engine-dependent backtracking
   cliff (60× between 64 and 128 KiB on JavaScriptCore, absent on V8) that an
   earlier "free of nested quantifiers" claim had denied existed.
6. **Pairs are counted, not tokens.** Counting tokens let a valueless `Secure`
   flag ahead of the cookie spend the opening-pair protection on itself, after
   which the exemption applied to the *real* first pair and
   `Set-Cookie: Secure; path=/<credential>` survived.
7. **Masking preserves the structure around the value.** A trailing run of
   serialization closers (`"`, `'`, `]`, `}`, `)`) is re-emitted rather than
   swallowed, so a cookie logged inside JSON stays parseable —
   `{"set-cookie": ["a=1", "sid=<tok>"]}` keeps its quotes and brackets. The
   idempotence guard for that is deliberately *the marker followed by closers
   only*, never `startsWith("[REDACTED]")`: the loose form would wave through a
   value that opens with the literal marker and continues into a real
   credential. `[REDACTED]` ends in `]`, so without the guard a second pass peels
   the bracket and grows `[REDACTED]]` on every run.
8. **A value that is ENTIRELY closers is still masked, and skipping it was a
   leak.** `cookie:AUTH=",<credential>` tokenises to `AUTH="` — the comma is a
   pair separator — so its value is the single character `"`. An early return
   that left such a token alone put a **dangling open quote** in the line, and
   the generic `*AUTH*` rule downstream pairs `(["'])…\2`: it mis-paired across
   to the next field's opening quote, or declined to match, and the credential
   printed **with no marker at all**. The same input was masked before the cookie
   rule existed, so the rule was making that line *worse* — the misleading-output
   class this whole file is organised around, produced by the fix rather than by
   the gap. Found by adversarial review at 13 occurrences in a 300,000-case
   sweep, and it was also the root of a non-fixed-point on inputs such as
   `Set-Cookie: api_key="; session="`. **Dropping `"` and `'` from the closer set
   closes the leak too, and was rejected on measurement**: it also gives back the
   JSON structure the re-emission exists for (`["a=[REDACTED], "sid=[REDACTED]]}`
   against `["a=[REDACTED]", "sid=[REDACTED]"]}`). Masking the all-closer value
   keeps both. Measured across 214,427 distinct fuzzed strings: 0 regressions and
   0 non-fixed-points, where the early return produced 5,745 and 9,579.

**On the fuzzing that found it, because the corpus was wrong first.** The
reviewer's original generator used `s = (s*1103515245 + 12345) & 0x7fffffff`,
whose multiply exceeds 2^53 — precision is lost and the sequence **cycles after
10,579 states**. Two verdicts of "300,000 cases, 0 regressions" rested on roughly
10.5k distinct draws wearing a six-figure number: *a vacuous corpus looks
rigorous where a vacuous control looks thin*. Re-run with `mulberry32`
(`Math.imul`, 32-bit throughout), 300,000 draws yield **214,427 distinct
strings** and surfaced this defect immediately. Any figure quoted from a
generated corpus in this file should be accompanied by its **distinct-string
count**, not its draw count.

### A probe that PASSES FOR THE WRONG REASON hides a missing mechanism

This is a distinct failure from the one the rest of this file guards against, and
it is worth naming because the defence against it is different.

The known hazard is a check that **cannot fail** — a grep whose pattern cannot
match, an absence claim from a truncated read. The defence is a positive control.
This is the other shape: a check that **passes, correctly, for a reason unrelated
to the capability being checked**. A positive control does not catch it, because
the instrument really does fire.

Measured on `main` at `b75e651`, before this change, with the same synthetic
value in every row:

| shape | result before the cookie rule existed | why |
|---|---|---|
| `Cookie: __Secure-next-auth.session-token=<value>` | **redacted** | the generic `*TOKEN*` key rule matched the substring `token` in the cookie **name** |
| `Cookie: session=<value>` | leaked | — |
| `Cookie: sid=<value>` | leaked | — |
| `Cookie: PHPSESSID=<value>` | leaked | — |
| `Set-Cookie: sid=<value>; Path=/; HttpOnly` | leaked | — |

Nine of ten cookie shapes leaked. **There was no cookie handling in this file at
all** — and yet a reviewer's most likely single spot-check came back clean,
because the cookie name people reach for first tends to contain the word `token`
or `auth`. An incidental match by an unrelated rule masked an entirely absent
mechanism, and would have gone on masking it.

Two consequences, both applied here:

1. **A fixture must not contain a substring any other rule keys on.**
   `COOKIE_CREDENTIAL` in `tests/redaction.test.ts` deliberately carries no
   `token`, `secret`, `auth`, `key`, `sk-` or `gsk_`. A fixture another rule
   happens to catch cannot detect the rule under test.
2. **Vary the axis the capability lives on, and check that the *majority* of it
   behaves the same way.** One passing shape out of a family is evidence about
   that shape, never about the family. Here the family is the cookie *name*,
   which the application chooses and which is therefore unbounded.

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

| version | auth-dense 50k | digest, unterminated 50k |
|---|---|---|
| `main` before this change (`47de35d`) | 1420ms | 2.6ms |
| commit 1 — truncation + adjacent-field (`9f52c8c`) | 923ms | 2.6ms |
| commit 2 — Digest `response=` rule (`4b10ea5`) | 955ms | **65ms** |
| commit 3 — parameterized auth rule (`6d3ae9f`) | 939ms | 60ms |
| merged (`62f8f14`) | 939ms | **60ms** |

Two effects, each attributable to one commit:

* **auth-dense got ~34% FASTER**, from commit 1 onward — 0.65–0.67× `main`,
  reproduced, and independently corroborated by two further measurements at
  0.66–0.67× and 0.685×. Not parity.
* **the digest path got slower**, starting exactly at commit 2, the commit that
  introduces the `response=` rule. **How much slower depends on the shape, and
  the shapes differ in COMPLEXITY CLASS — see the next subsection, which is the
  part that matters.**

**The growth ratio, not the absolute figure, is what makes this checkable.** This
section already said absolute numbers move with machine load while ratios do not
— which is precisely why a *before/after ratio measured in one process on one
box* is load-independent evidence, and why 0.66× cannot be explained away as
"their host was busier". On the auth-dense input growth stays 4.0×/doubling
throughout, so that pre-existing quadratic is unchanged and only its constant
factor moved.

#### The `response=` rule adds a NEW quadratic, on a shape this file first missed

**An earlier version of this section stated flatly that the digest regression was
"a constant-factor change, not a new quadratic", and that calling it a quadratic
"would be a different and unsupported claim". That was measured on exactly ONE
shape and stated without the qualifier. It is wrong as a general statement**, and
an adversarial review caught it. Both facts below are reproduced:

| shape (50k → 100k) | before `47de35d` | merged `62f8f14` | growth after |
|---|---|---|---|
| one header, **unterminated** `response="` + padding | 13.7 → 5.4ms | 91 → 172ms | ~1.9×/doubling — **linear** |
| repeated `Authorization: Digest ` on **one line** | 2.0 → 4.3ms | 267 → 1060ms | **3.97×/doubling — QUADRATIC** |
| the same content **newline-separated** | 1.9 → 3.9ms | 4.1 → 7.5ms | ~1.9×/doubling — linear |

So the constant-factor finding is true **for the unterminated single-header
shape** and is kept for that reason. It does not generalise: on repeated
`Authorization: Digest` tokens within a single line the rule is a clean new
quadratic, 168× at 100k against `main` and widening with n.

**The newline-separated row is the control that identifies the mechanism**, not
just the symptom. The rule's `[^\r\n]*?` between `Digest\s+` and
`\bresponse\s*=` scans forward to end-of-**line** from every position at which
`authorization…Digest` matches. Many matches on one line means many full-line
rescans, which is O(n²); the identical bytes split across lines bound each rescan
and the cost collapses back to linear. Newlines are what the pattern uses to
stop, so a single long line is the adversarial input.

On bare repeated characters every version above is linear, but the `~0.5ms at
50k` figure that stood here does not reproduce and named no character: measured
at 50k, `47de35d` ranges `-` 1.7ms through `a` 3.7ms, `62f8f14` ranges 1.8–2.8ms.
The cost is character-dependent, so quote the character with the number.

#### The cookie rule: the ReDoS that was measured BEFORE it was written

The natural way to mask every pair inside a captured cookie header is one global
regex, `/([^\s;,=]+)=([^\s;,]*)/g`. **It is quadratic, and this repo shipped a
ReDoS inside a credential-leak fix once already**, so it was measured before being
written rather than after.

Adversarial input — one run of non-delimiter characters carrying **no `=` at
all**, so every start position must scan the run and fail. station01, loadavg
10.3, `bun`:

| 1 KiB | 2 KiB | 4 KiB | 8 KiB | ratios |
|---|---|---|---|---|
| 3.60ms | 14.35ms | 57.22ms | 228.89ms | **3.98× / 3.99× / 4.00×** |

A first probe at 16–128 KiB had to be killed at 120s. The mechanism: `[^\s;,=]+`
followed by a literal `=` backtracks across the whole run at every start position,
and every retry position holds a character that is *by construction* not `=`.
128 KiB is exactly the `maxBuffer` bound in `src/agentic.ts`, and
`src/mcp/index.ts` applies no bound at all — the same two call sites that made the
Digest quadratic a ReDoS rather than a slow function.

So the header value is captured by regex and then scanned by a **hand-written
single forward pass** (`redactCookiePairs`). Every character is visited once and
nothing is re-scanned, so it is linear *by construction* rather than by
measurement. Shipped behaviour, base `b75e651` vs this change, median of 9 after a
warmup, 16/32/64/128 KiB:

| shape | base ratios | this change | absolute @128 KiB |
|---|---|---|---|
| cookie-dense, one line | 1.99 / 1.95 / 2.01 | 2.05 / 1.91 / 1.97 | 22.8ms → 20.2ms |
| cookie-dense, newline-separated (control) | 2.02 / 2.01 / 1.98 | 2.05 / 1.91 / 1.97 | 22.5ms → 18.1ms |
| `cookie` literal repeated, **no separator** | 2.05 / 2.00 / 2.02 | 2.01 / 2.01 / 2.01 | 4.2ms → 8.4ms |
| digest-dense, one line | 2.03 / 1.88 / 2.03 | 1.97 / 2.00 / 1.99 | 7.0ms → 7.0ms |
| auth-dense, the pre-existing quadratic | 3.94 / 4.00 / 4.04 | 3.95 / 3.97 / 4.02 | 1612.0ms → 1613.4ms @64 KiB |

The last row is the honest one: **the pre-existing generic-key quadratic is
neither added to nor removed by this change** — 1612.0ms against 1613.4ms is
parity, and it stays listed as an open residual below. The `cookie`-literal row
costs 2× the base constant because a rule that did not exist now runs; the
exponent is unchanged.

#### The perf guard for that rule COULD NOT FAIL, on this file's own headline defect

**The two perf assertions that shipped with the cookie rule did not test what
their comment said, and an adversarial reviewer proved it by installing the
rejected naive pattern and running them:** they returned **1.97, 2.00 and 1.87 —
all green, with the ReDoS in place.**

Two causes, and the first is this file's own axes lesson pointed at a perf
harness:

1. `growthPerDoubling` enlarges its input by **repeating a fixed unit**, so the
   NUMBER of runs grows and no single unbroken run ever gets longer. The
   quadratic is **per run**, O(run²). The harness could not express the axis the
   defect lives on — **at any size**.
2. `"cookiecookiecookie"` **never triggers the rule at all**: no `:` or `=`
   follows the literal, so the outer regex never matches.

The replacement grows the **run**. Measured at 8/16/32 KiB against a mutant
carrying the naive pattern, versus the shipped forward scan:

| shape | shipped scan | naive mutant | discriminates? |
|---|---|---|---|
| `"cookie=" + x*N` | 1.819 (0.73/1.23/2.41 ms) | **4.010** (231.6/927.1/3724.4 ms) | **yes** |
| `"Set-Cookie: " + x*N` | 1.987 (0.62/1.19/2.45 ms) | **4.004** (231.7/941.7/3714.3 ms) | **yes** |
| `"Cookie: sid=" + x*N` | 1.876 | 2.064 (0.1/0.1/0.2 ms) | **NO — removed** |

**The third row is why the shape matters more than the size.** A first attempt at
this test used it and it does not discriminate: `sid=` satisfies the literal
immediately, so the scan never has to fail, and the naive pattern completes in
0.1 ms instead of 231 ms. **The discriminating shape has no `=` in the header
value at all.** Both shipped assertions now put the whole run after the header
separator and before any `=`.

Sizes are chosen so the failing case fails *fast* — 8/16/32 KiB rather than
32/64/128 — because **a test that can only fail by timing out reports its budget,
not a duration.**

**The estimator takes the FASTEST sample, not the median.** CPU contention is
strictly *additive* noise — another process can slow a sample but never speed one
up — so on a loaded box the minimum is the sample closest to uncontended
execution while the median drags with load. A median-based estimator failed the
newline control at ratio **6.40** at loadavg 25, and was measured failing 2 runs
in 10. With the fastest sample the suite ran **6 of 6 green at loadavg ~21**.
The thing to check before changing an estimator is whether it weakens the guard,
and it does not: a quadratic implementation has a quadratic *minimum* too — the
naive mutant still returns **3.99995** and still fails. Verified against the
mutant after the change rather than assumed.

The original two assertions are kept and relabelled as what they genuinely pin —
the **outer** regex's start-position cost — with the measurement that the naive
mutant passes them written beside them.

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

**A corpus's coverage is bounded by its AXES, not its size — so name them.** The
cookie work added a 32-shape coverage corpus and a 251-shape A/B output-drift
corpus (base vs this change, 0 drift, with a positive control proving the
comparison *can* report drift). Between them they vary: cookie **name**; header
**spelling** and **case**; **separator** (`:` / `=` / spaced); **quoting**
(bare / double / single / unterminated); the credential's **position** among
several pairs; **pair count**; presence of **Set-Cookie attributes**; an
attribute name **reused** as a cookie name; header **position within the line**;
and **multi-line** inputs.

**Axes they do NOT vary, and the defect class demonstrably lives on some of
them:** any **encoding** of the header name or separator (percent-encoding,
Unicode/fullwidth, HTML entities), and **line folding**. Both were probed
separately after the fact and both leak — see the rows below. No amount of
additional shapes along the axes above would have found either, because the
generators cannot express them.

| shape | class | why it is still open |
|---|---|---|
| **headers serialized into a JSON string field** — `{"raw":"{\\"headers\\":{\\"authorization\\":\\"Basic <tok>\\"}}"}` (two `JSON.stringify` levels; pino / winston / an axios error object). Leaks for **all four** schemes. | honest gap | The escaped-quote fix (todos `d841b3e1`) closed the rung where a rule ENGAGES and terminates early. This is the rung ABOVE it: at two levels the backslash sits between `authorization` and its `:`, so the key prefix `['"]?\s*[:=]\s*` never matches and **no rule engages at all** — hence no marker. Closing it means teaching the key prefix to cross backslash escaping, which is adjacent to the normalisation-layer decision ruled a documented won't-fix in todos `4afd4361`, and was deliberately kept out of the `d841b3e1` fix so that change stayed one mechanism wide. **Measured, not assumed:** 4/4 schemes leak at two levels on `06cc7de` and on the branch that fixes one level. |
| bare `Bearer <token>` with no `authorization` key | honest gap | The only rule that closes it — `/Bearer\s+[A-Za-z0-9._~+/=-]+/gi`, which `hasnaxyz/iapp-sms` carries — over-redacts ordinary prose: `Bearer authentication is required` becomes `Bearer [REDACTED] is required`. Closing this gap would trade a marker-free gap for a real over-redaction regression. Deliberately deferred, not overlooked. |
| ~~`Cookie: session=<tok>`~~ | — | **CLOSED.** Covered by the cookie rule; see the covered table above. |
| ~~`Set-Cookie: sid=<tok>; HttpOnly`~~ | — | **CLOSED.** Same rule. |
| a cookie pair separated from the header by **whitespace only**, `Cookie: a=1 sid=<tok>` | honest gap | **Live**, and deliberate. RFC 6265 delimits cookie pairs with `;`, so the rule masks a pair only when it opens the header or follows a `;` or `,`. Without that condition a cookie header sitting mid-line turns the rest of the line into markers — `cookie: sid=<tok> status=200 user=bob` would lose `status` and `user`, which is the adjacent-field destruction this file has already had to fix once. Browsers and servers emit `; `, so the shape is non-conformant. Measured: `Cookie: a=1 sid=<tok>` → `a=[REDACTED] sid=<tok>`. |
| a **non-conformant cookie value containing whitespace**, `Cookie: sid=abc def` | honest gap | **Live**, same cause. `cookie-octet` excludes SP, so a value with an interior space is not a cookie value; the rule masks up to the space. Measured: `Cookie: sid=abcSYNTH defSYNTH` → `sid=[REDACTED] defSYNTH`. |
| ~~a request Cookie credential that happens to match an attribute's value shape, under that attribute's name and not in first position — `Cookie: a=1; path=/<tok>`~~ | — | **CLOSED.** Request `Cookie` headers no longer apply the `Set-Cookie` attribute exemption; `Cookie: a=1; path=/<tok>` and the domain-shaped equivalent are masked. `Set-Cookie` attributes remain preserved. |
| **obs-fold** — a header value continued on the next line with leading whitespace | honest gap | **Live**, and shared with every other rule in this file: each value class excludes `\r\n`, so a folded continuation is never part of the match. Measured: `Cookie: a=1;\n sid=<tok>` → the continuation survives. Obsolete since RFC 7230 §3.2.4 but still produced by some proxies. |
| URL userinfo — `scheme://user:<tok>@host` | honest gap | **Live.** `tai` has no userinfo rule at all. `hasnaxyz/iapp-sms` redacts this via `URL_USERINFO_PATTERN`; this is a genuine divergence, not a shared gap. |
| PEM private key armour — a `-----BEGIN … PRIVATE KEY-----` block | honest gap | **Live.** No rule keys on PEM armour, and the body is bare base64 across newlines with no assignment shape to anchor on. (Written with an ellipsis on purpose so this row does not itself trip a secret scanner. Do not "fix" it back.) |
| `authorization.value=Basic <cred>` — `.` as a key separator | honest gap | **Live.** The trailing key run is `[A-Za-z0-9_-]*`, which excludes `.`, so the match stops at `authorization` and never reaches the `=`. |
| `authorization%3DBasic%20<cred>` — percent-encoded | honest gap | **Live.** Nothing percent-decodes free text before matching, so no key is ever seen. **Measured to apply to the cookie rule identically**: `cookie%3Dsid%3D<tok>` and `cookie%3A%20sid%3D<tok>` both survive. It is one gap in the decoding layer, not one per rule. |
| a bare high-entropy value with no recognisable key or prefix | honest gap | Structural. No keyword and no prefix means nothing to key on; this cannot be closed by pattern matching. |
| quadratic growth on repeated `*AUTHORIZATION*`-shaped tokens | availability, P2 | **Live and pre-existing**, 4.0×/doubling on every version measured. Comes from the generic `[A-Z0-9_]*…[A-Z0-9_]*` key rules. Fixing it means restructuring those rules, not widening a pattern. The absolute cost is **not** unchanged by this change — see the performance section: auth-dense is 0.66× (faster). A `~324ms at 50k, byte-identical` figure previously stood here and is retracted as unreproducible. |
| **NEW quadratic in the `response=` rule, on repeated `Authorization: Digest` within one line** | availability, **P1** | **Live, and introduced by this change** at `4b10ea5`. 2.0ms → 267ms at 50k and 4.3ms → 1060ms at 100k, **3.97×/doubling**, widening with n — a complexity-class change, not a constant factor. The same bytes newline-separated stay linear, which locates the cause in the `[^\r\n]*?` scan to end-of-line. **Reachable** — see the ReDoS row below. Tracked as `a0b7904f`; deliberately NOT fixed in the docs change that recorded it, because a documentation PR must not quietly alter redaction behaviour. |
| digest, **unterminated** single-header shape costs ~23× more | availability, P2 | **Live, same origin** (`4b10ea5`): 2.6ms → 60ms at 50k. On *this* shape growth stays linear (~1.9×/doubling), so it is a constant-factor regression. Recorded separately from the row above because the two shapes differ in complexity class, and an earlier version of this file generalised from this one and got the other wrong. |
| the `response=` quadratic is reachable from real call sites | **ReDoS, P1** | **Live.** `src/agentic.ts:97-98,105-106` redacts shell stdout/stderr — and `redactSensitiveText(stdout).slice(0, 12000)` truncates **after** redaction, so the 12k slice does **not** bound the regex input; the real bound is `maxBuffer: 128 * 1024`. Measured at 128KiB: **7ms → 2339ms**. `src/mcp/index.ts:107` redacts caller-supplied MCP tool text with **no maxBuffer at all**: at 512KiB, **30ms → 29058ms**. Single-threaded runtime, so this blocks the event loop. Anyone who can influence command output or call the MCP tool can spend it. |
| Unicode or non-ASCII spellings of header names | honest gap | **Live, and now measured** rather than merely suspected: a fullwidth `ｃookie: sid=<tok>` survives, because every key pattern in this file is an ASCII literal and nothing normalises the input first. Previously listed here as *unmeasured*; one probe moved it. The same is expected — but **not** measured — for the `authorization` and `signature` keys. |
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
- ~~`iapp-sms` had a serialized-JSON string path that `tai` never had.~~
  **RETRACTED — this row was read as "`tai` has no serialized-JSON exposure",
  which is false.** `tai` leaks at the next nesting level; see the two-level row
  in the open table above.
- `tai` does not redact URL userinfo; `iapp-sms` does.
- **`iapp-sms` is NOT a superset of `tai`, and must not be transplanted.**
  Measured 2026-08-01 with a canary carrying no provider prefix: on a plain
  `Authorization: Digest ... response="<tok>"` header, `iapp-sms` returns
  `Authorization: [REDACTED], realm="r", … response="<tok>"` — the credential
  surviving beside a marker — where `tai` returns `Authorization: [REDACTED]`,
  because `tai` has a dedicated Digest rule that `iapp-sms` lacks. Across a
  12-cell matrix (4 schemes × JSON nesting depth 0/1/2) `iapp-sms` leaked 8 cells
  to `tai`'s 6. **Copying its mechanism wholesale would have regressed `tai`.**
- **THE AXIS THAT MAKES THE COMPARISON LIE IS THE CANARY, NOT THE SHAPE**, and
  it is the reason `iapp-sms` has been read as clean here more than once. Varying
  only the canary on one fixed shape (depth-1 JSON Digest):

  | canary | `iapp-sms` | `tai` (before the fix) |
  |---|---|---|
  | matches no prefix rule | leaks, with a marker | leaks, with a marker |
  | `sk-…` prefixed | redacted | redacted |
  | `sms_…` prefixed | redacted | leaks, with a marker |

  A canary carrying a recognisable prefix is masked by the **provider-prefix**
  rule, so the **structural** rule under test never runs and a broken one scores
  clean. Both zeros are real; only the prefix-free one is evidence about the
  mechanism. Probe redaction with a value that matches no prefix rule, or the
  probe passes for the wrong reason.
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
