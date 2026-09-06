# Changelog

## 0.8.1, 2026-09-06

**`Sources/` is byte identical to 0.8.0. One test was wrong and it shipped red.**

`testEvidenceOnlyLeavesALocalIdentifierAlone` asserted a precondition that is false:
that the full pass set takes `session 'a1b2c3'`. It does not. Whitespace is the weakest
separator in the labelled pass and `session` is deliberately absent from
`whitespaceSeparableNames`, so the whitespace form is left alone by design. The shape
that actually reproduces the Grux defect is `session_id: sh-...`, where the colon is a
strong separator.

The tag before this one stays resolvable, like every other tag here. What it carries is
a red suite, not a leak.

Both forms are now pinned, so the asymmetry between them is on the record rather than
rediscovered by whoever writes that test the obvious way next.

## 0.8.0, 2026-09-06

**Additive: `redact(_:passes:)` lets a caller choose which passes run.** The existing
`redact(_:)` is unchanged and runs everything, so no behaviour moved for any current
caller.

The redactor has five passes and they are not the same KIND of judgement. Two work from
evidence: a known provider key format, or a `user:pass@` URL. Three infer: from a name
next to the value, from an auth scheme, or from shape alone. Inference is what makes the
redactor good, and it is also what makes it unsafe to run twice over a string the caller
wrote itself.

Grux found this the hard way. It runs every shell tool result through the redactor a
second time as defence in depth, and that string carries its own session ids. `session`
is in `credentialWords` deliberately, because an HTTP session identifier is exactly what
a stolen cookie replays, so:

```
session_id: sh-20260906-143022-a1b2c3   ->   session_id: [REDACTED:ASSIGNED_SECRET]
```

Every call after that failed with `session '[REDACTED:ASSIGNED_SECRET]' not found`. The
rule was right and the second application was wrong.

```swift
SecretRedactor.redact(untrustedInput)                          // unchanged, all five
SecretRedactor.redact(ownOutput, passes: .evidenceOnly)        // branded + URL credentials
SecretRedactor.redact(text, passes: [.branded, .entropy])      // or any combination
```

`.evidenceOnly` is not a way to turn redaction down. A branded Anthropic key and a
`user:pass@` URL still go, because a known credential FORMAT is evidence rather than
inference. Four tests cover it, including that the default is byte identical to
`.all` and that a single pass can run alone.

119 tests, 0 failures.

## 0.7.0, 2026-09-06

**Breaking, and it is the only change: the module is renamed from `Grux` to
`GruxGuardrails`.** Every consumer's `import Grux` becomes `import GruxGuardrails`, and
`.product(name: "Grux", package: "grux-guardrails")` becomes
`.product(name: "GruxGuardrails", package: "grux-guardrails")`. No source behaviour
moved: the redactor and the URL guard are byte identical to 0.6.2.

**The rename was forced, not chosen.** The application this library was extracted from,
`dotcomjack/grux`, has an application target also called `Grux`. Two modules of the same
name cannot coexist in one build graph, so the app could not link this package at all.
That is not a theoretical limit. Measured 2026-09-06:

```
error: multiple similar targets 'Grux' appear in package 'aliastest' and
'grux-guardrails', this may indicate that the two packages are the same
```

SwiftPM's `moduleAliases` is the documented escape hatch and it does not apply here,
because aliasing is unavailable when the ROOT package owns the clashing name. The only
remaining move is to rename the library, so the library is renamed.

**Why it matters beyond a build error.** The app shipped its own older copy of both
controls rather than depending on this package, and six of eight defects disclosed in
the advisories for 0.1.0 through 0.4.0 were still live in it. The name collision is the
reason nobody folded the app back onto the hardened code. Removing the collision is what
makes that possible.

Migration is two lines:

```swift
// before, 0.6.x
.package(url: "https://github.com/dotcomjack/grux-guardrails.git", from: "0.6.2")
.product(name: "Grux", package: "grux-guardrails")

// after, 0.7.0
.package(url: "https://github.com/dotcomjack/grux-guardrails.git", from: "0.7.0")
.product(name: "GruxGuardrails", package: "grux-guardrails")
```

The README install guard now knows three module eras rather than two: `GruxKit` below
0.6.0, `Grux` from 0.6.0, `GruxGuardrails` from 0.7.0. Longest name first, because `Grux`
is a prefix of both of the others and asking about it first misreads every snippet from
either other era. Both new rules ship with a planted control that proves they fire.

115 tests, 0 failures.

## 0.6.2, 2026-08-15

**No source change. `Sources/` is byte identical to 0.6.1.** This release exists because the
documentation shipped INSIDE the 0.6.1 tag told readers to install 0.6.0.

A tag is immutable, and a README is vendored into every checkout that resolves it. So the
copy of the README a stranger reads on the 0.6.1 release page, and the copy sitting in their
`.build` directory, both said `from: "0.6.0"` and `**Use 0.6.0.**` while the launch site
advertised 0.6.1. Correcting `main` did not correct either of those, because a fix on a
branch is not a fix in a tag.

The fix is structural rather than a one-off correction: the version now moves in the SAME
commit that gets tagged, so the tag's own documentation names the tag it lives in. Bumping
after tagging would have reproduced the bug one release later, which is what nearly happened.

Also in this release, all documentation rather than code:

- The published bare 40-character credential leak rate was corrected from "roughly 1.3%" to
  roughly 0.85%. 1.3% was the PRE-0.5.0 figure. 0.5.0 took the rate to 0.875% and updated the
  CHANGELOG and nothing else, so `docs/CORPUS.md`, `CONTRIBUTING.md` rule 6 and the comment
  above the assertion in `CorpusTests.swift` all carried a number three releases stale.
  Measured across 8 runs on three machines: 0.78% to 0.97%.
- The 2.0% guard on that rate is UNCHANGED and its looseness is now written down. At 20,000
  trials the sampling deviation is about 0.065 points, so 2.0 sits roughly 18 deviations above
  the mean and the rate could more than double before it trips. `CONTRIBUTING.md` rule 6 asks
  for a guard "just above" the measured value, so 2.0 does not meet the project's own
  standard. It is recorded as a known gap rather than quietly narrowed, because moving a
  published threshold in either direction changes the claim the library makes.
- `docs/THREAT-MODEL.md` said "Grux is two pure functions and nothing else". The public API is
  five: `redact`, `evaluate`, two `wrapAsUntrusted` overloads and `newFenceID`. A threat model
  that names two entry points invites a reviewer to review two.
- `docs/CORPUS.md` gained a provenance column separating numbers a test recomputes every run
  from numbers measured once against corpora that are not in this repository. Three rows cited
  a test that structurally could not produce the number beside it.
- The complexity row cited CHANGELOG 0.5.0 for the 65x curly-apostrophe cliff. That entry is
  under 0.3.0; the only 65x inside 0.5.0 is an unrelated measurement with a coincidentally
  identical multiplier. The same row called the test's input "smaller" than the 296KB cliff
  when it is 8,000 repetitions of a 41 character unit, so 328,000 characters, which is larger.
- The install-snippet coherence test no longer requires a code block to contain
  `let package = Package(`, so the README's primary one-line snippet is checked for the first
  time. It selects fenced Swift blocks by what they contain rather than by line number, so it
  cannot be broken by moving text around the README.

## 0.6.1, 2026-08-13

Three changes, all of them narrow on purpose. Two more findings from the same audit round
are disclosed in the README rather than fixed, and the reason is stated below.

**The minimum platform is now macOS 14, up from 13.** This is a real break for anyone on
13 and it is not cosmetic tidying. `testEveryUnicodeSpellingOfALoopbackHostIsDenied`
defends against a homograph loopback SSRF, and it holds because Foundation's `URL.host`
applies UTS46 mapping. macOS 15 ships the rewritten swift-foundation URL parser; 13 and 14
ship the older one. CI was raised to a matrix to test the declared minimum, and the
`macos-13` runner never scheduled: 31 minutes queued while 14 and 15 finished in about two,
and it held the whole run in `queued` so CI could never conclude at all. GitHub is retiring
that runner. Rather than keep advertising a floor no CI leg can ever prove, the floor moved
to the lowest version that is proven. macOS 14 passing is the evidence that matters here,
because 14 ships the same older parser the concern was about.

**Two provider patterns added: Docker Hub `dckr_pat_` and Linear `lin_api_`.** Both were
invisible to every pass. They are distinctive prefixes that appear in no ordinary text, so
adding them widens what is caught without widening what is destroyed. That is the entire
reason these two shipped and the leaks below did not.

**RFC 2765 IPv4-translated IPv6 is now decoded.** `::ffff:0:127.0.0.1` was the fourth
member of the embedded-IPv4 family and the only one this guard did not judge by the address
it carries. It is not routable on macOS today, so it was hardening rather than a live
bypass, but the guard already denies `0x7f.0.0.1` on the chance a resolver reads it as
loopback, and already denies deprecated site-local fec0::/10.

The first attempt at that fix was wrong in a way worth recording: it pinned the `ffff` group
to one byte position, which catches `::ffff:0:a.b.c.d` and misses `::ffff:0:0:a.b.c.d`,
because how many explicit zero groups the author writes moves the group from index 5 to 4 to
3. The check now judges the family by SHAPE, the leading twelve bytes being all zero except
at most one aligned `ffff` group, which covers every spelling.

**Disclosed, not fixed, and both are in the README's limits section.** A labelled credential
inside a JSON array or YAML sequence survives, and so does one inside an XML or plist
element body. Both are the same adjacency problem: the credential-word rules read a name and
the value next to it, and a bracket or a tag between them breaks that. Widening those rules
is the one change measured to make things worse, because they already destroy 20 of 30
ordinary config lines whose field name merely contains a credential word, including
`"author"` in every package.json and the OIDC `auth_url` and `token_url`.

115 tests, 0 failures.

## 0.6.0, 2026-08-13

**Breaking, and it is the only change: the module is renamed from `GruxKit` to `Grux`.**
Every consumer's `import GruxKit` stops compiling and becomes `import GruxGuardrails`. The package
identity changes with it, so `.product(name: "GruxKit", package: "grux-kit")` becomes
`.product(name: "GruxGuardrails", package: "grux-guardrails")`, and the repository moves to
`github.com/dotcomjack/grux-guardrails`.

Migration is two lines and there is no behaviour change to test against:

```swift
// before, 0.5.0 and earlier: whichever URL you already have, plus
.product(name: "GruxKit", package: "grux-kit")

// after, 0.6.0
.package(url: "https://github.com/dotcomjack/grux-guardrails.git", from: "0.6.0")
.product(name: "GruxGuardrails", package: "grux-guardrails")
```

Be precise about what breaks, because `from:` is a range and not a pin. `from: "0.6.0"`
means `[0.6.0, 1.0.0)`, so it can only ever resolve to a tag that carries the `Grux`
product. What fails is a constraint that actually holds you at or below 0.5.0:
`.exact("0.5.0")`, an `upToNextMinor` range, or `from: "0.5.0"` evaluated before 0.6.0
is tagged. In any of those, `import GruxGuardrails` fails to resolve with
`product 'Grux' not found`, because 0.5.0 declares the product as `GruxKit`.

Also removed: a generated banner file that shipped inside the built library, imported
Darwin, read `ProcessInfo` environment and called `isatty`, and that nothing referenced.
No redaction or URL-policy behaviour changed in this release.

**A known leak is disclosed rather than fixed in this release, and you should read it
before upgrading.** A labelled credential inside a JSON array or YAML sequence survives
redaction: `{"passwords": ["s3cretPassw0rdForProd"]}` comes back untouched while
`POSTGRES_PASSWORD=` with the same value is caught. It predates this release and is present
in every earlier tag. It is not fixed here because the credential-word rules are already the
least precise part of the matcher, destroying 20 of 30 ordinary config lines whose field
name merely contains a credential word, and widening them to walk collections would make
that materially worse. Pinned by
`testKnownDefectCredentialsInsideAJSONArrayOrYAMLSequenceSurvive`. The test count is stated in
the release tag, measured on the tagged commit, rather than here where it goes stale every
time a test lands.

## 0.5.0, 2026-08-10

Eight audit rounds of the redactor and the URL guard. Every defect below was found by
measurement or by planting a failure, and the numbers are from real runs rather than
estimates. Read the round-eight sections first: two of them describe defects that a fix in
this same release had introduced.

### Eighth audit, the path heuristic

Round seven closed with one confirmed and unfixed defect: a GitHub permalink came out as
`https://github.[REDACTED:HIGH_ENTROPY].md`. Fixing it properly meant measuring it first,
and the measurement said the defect was roughly two orders of magnitude larger than the
bug report. **Across 814 real paths and URLs taken off a working machine, 357 were
destroyed, 43.9%.**

The permalink was not a special case, it was the visible one. The common cause is a `.`
anywhere earlier in the string. `.` is outside the token alphabet, so the entropy match
begins after it, and that single fact defeats both existing path signals at once: the
leading separator that `leadingEmpty` reads is gone, and the segment statistics the
mean-length rule reads are re-based on whatever follows the dot. Any Swift build directory
did it. `/Users/x/proj/.build/arm64-apple-macosx/debug/ModuleCache/Foundation-RFLD5H6WW7NI.swiftmodule`
matched from `build` onward and went out as a single redaction.

**Why it survived seven rounds is worth more than the fix.** There was a test called
`testPathsStillSurviveWithSlashInTheClass`, it asserted on a GitHub permalink, and it
passed. Its fixture was `github.com/a/b/blob/<sha>/File.swift`. A single-letter owner and
a single-letter repository are exactly what drag the mean segment length under 10.
Substitute real names, which are longer, and the same URL is destroyed. The fixture had
been fitted to the implementation rather than to reality, and so the test agreed with the
code about something they were both wrong about.

- **A third path signal, based on content rather than shape.** A path segment is a NAME:
  four characters or more, letters plus at most a hyphen or an underscore, no digits, and
  at least one vowel. Three such names forming a majority of at least four segments means
  the token is a path. The vowel test is not decoration. Runs like `mtgk`, `DTZfp` and
  `CRKFLDvGh` clear letters-only by accident, and dropping the vowel requirement makes
  this rule cost 31 spared secrets per 400,000 instead of 12.

- **The floor of four segments is set by the AWS secret access key.** Its two slashes leave
  three segments, so it can never reach the new rule at all. That is the single most
  valuable credential the generic pass is responsible for, and it stays caught.

**Measured on both sides, causally.** 100,000 random base64 strings at each of 40, 64, 128
and 200 characters, generated from a fixed seed and run through the redactor with and
without the rule, so the difference is the exact set of secrets newly spared rather than a
sampling estimate. That distinction mattered: a first pass at N=20,000 with an unseeded
generator appeared to show a regression at 128 characters that a seeded rerun showed was
noise. **Cost: 24.0 per 400,000, measured over ten seeds and 4,000,000 trials as 240 newly
spared against zero newly caught, individual seeds ranging 15 to 31, every one carrying
three or more slashes. Benefit: real
path mangling fell from 357 of 814 to 2, and the project's own corpus from 41 of 9,323 to
40.** No secret that was caught before is missed now.

Three plants confirmed red is reachable: deleting the rule fails the path test, widening it
fails the AWS key test, and neutering the vowel check alone fails three fixtures, so the
vowel requirement is covered rather than merely asserted. The must-stay-redacted cases sit
in the same file as the must-stay-allowed ones, deliberately, so the trade cannot drift in
one direction unnoticed.

README.md's description of the path heuristic was stale in two ways and is rewritten. It
still described the round-five single-signal rule, "a token with any segment shorter than
four characters is a path", and it claimed GitHub permalinks pass through untouched "and
there are tests asserting each one", which was false at the time it was written.

### Eighth audit, part two, two live bugs behind three doc claims

Eight findings from round seven were carried forward unadjudicated and described as
"doc-accuracy and test-quality, no leaks". Adjudicating them found that description was
wrong: two were live defects in shipped behaviour, and they had been filed as README drift
because the README sentence was the visible symptom.

- **A plus-addressed email address was destroyed.**
  `support+order-confirmation-and-shipping-updates@example.com` came out as
  `[REDACTED:HIGH_ENTROPY]@example.com`. All lowercase, no digits, nothing
  secret. `+` set the base64-padding flag, and that shortcut returns true before any other
  rule is consulted, so nothing downstream could object. The brake is that `+` is the
  base64 tell only in a base64 alphabet: standard base64 is `A-Za-z0-9+/`, base64url is
  `A-Za-z0-9-_`, and a run carrying a `+` alongside a `-` or `_` is neither.

- **"Most specific wins" was false wherever a credential actually sits.**
  `postgres://user:sk_live_...@db` and `curl -u alice:sk_live_...` both came out
  `[REDACTED:URL_CREDENTIAL]` and `[REDACTED:BASIC_CREDENTIAL]`. The pattern pass ran first
  and correctly wrote `[REDACTED:STRIPE_LIVE_SECRET]`, and then the URL and flag passes
  matched that marker AS a value and overwrote it. Nothing leaked; the casualty was the
  audit trail, which is the only thing the tag is for. The claim is stated as load-bearing
  in README.md and again in the file's own doc comment. Those passes now skip a value that
  is already a marker, and an unrecognised credential in the same position still gets the
  generic tag, which is pinned by its own test.

Five of the remaining six were tests that could not fail:

- **The quadratic-regression test never reached the code it guarded.** Its repeated unit
  was 36 characters and `entropyRegex` requires 40, so `replaceHighEntropy` returned at its
  `guard !matches.isEmpty` line and the loop carrying the entire defect never ran. With the
  quadratic form planted, the measured ratio was 1.126 against 1.136 for the fixed code,
  which no bound could separate. The `max(1.0, ...)` floor was a second layer of the same
  problem: it evaluated to about 20 seconds on that input. The unit is now 41 characters,
  the bound is a plain 2.5x ratio, and an assertion fails if the body ever drifts back
  below the floor. Planted, it now fails at 3.06x.

- **`testMostSpecificPatternWins` used a 38-character fixture**, below the 40-character
  entropy floor, so `XCTAssertFalse(contains("HIGH_ENTROPY"))` was true for a reason
  unrelated to ordering. The fixture is now long enough for both passes to compete.

- **The `leadingEmpty` branch had no coverage at all.** Deleting it left the whole suite
  green, and the compiler said so: the build emitted "variable 'leadingEmpty' was written
  to, but never read", because that line was the flag's only reader. Every fixture in the
  test that claimed to cover it was rejected by a different signal first.

- **`testBlankTrustedLANEntriesMatchNothing` never probed an empty host**, which is the
  only thing its `!isEmpty` guard can decide. Both its probe URLs had non-empty hosts, so
  the comparison was never what denied them. A host CAN be empty: `http://./` parses to
  "." and the trailing-dot loop strips it to "". The guard turns out to be genuinely
  load-bearing, so the finding was right about the test and wrong to imply the guard was
  decoration.

- **`testAllowlistMatchesSubdomains` asserted that a public hostname was allowed**, which
  it is with the allowlist emptied. The allowlist has exactly one observable power: it is
  consulted before `privateNetworkReason`, so it overrides a denial. The test now pins
  that, and states the consequence plainly, that allowlisting a domain also allowlists
  subdomains of it which spell a private address.

The sixth was genuine documentation drift, the stale path heuristic already rewritten
above.

Six more plants, each confirmed red then reverted green, for nine across the round. One of
them is the reason this section exists at all: the panel that produced these eight findings
was told to default to refuted, and it still returned all eight as confirmed. Verifying each
at file and line myself is what separated the two live bugs from the doc drift they were
filed as.

### Eighth audit, part three, the IPv6 registry was 8 rows of 25

The IPv4 special-purpose table has been registry-complete for several rounds. The IPv6 one
classified 8 of the 25 IANA rows and allowed the other 17. That was never a decision, it
was an absence, and an audit is supposed to turn absences into decisions. Every row was
driven through the real `evaluate` before and after, so "was allowed" is measured.

**Three of the seventeen were genuine holes and they share a shape.** RFC 7723, RFC 8155
and RFC 9665 assign anycast addresses at `2001:1::1`, `2001:1::2` and `2001:1::3`. Anycast
means the nearest responder absorbs the packet, and for all three that responder is
infrastructure on the local network: the PCP-capable NAT or firewall, an operator TURN
relay, the local-link DNS-SD registrar. They read as ordinary global unicast, they were
allowed, and they are a direct path to a device the caller was never meant to reach.

**Teredo was the last prefix with embedded-IPv4 semantics still undecoded.** `2001::/32`
carries the tunnel server's IPv4 in bytes 4 through 7 in the clear and the client's IPv4 in
the trailing four bytes obfuscated by a bitwise NOT. 6to4 and both NAT64 prefixes were
already decoded; this one was not, so it is now judged by the same IPv4 policy.

The remaining rows are discard-only and dummy prefixes, ORCHID, ORCHIDv2 and DET
cryptographic identifiers, SRv6 SIDs, benchmarking and the two documentation blocks. None
is a live hole, all are free to deny, and each is now a decision with a reason string
rather than a gap.

**The prefix trap, which is why this is a row-by-row table.** The obvious implementation is
to deny `2001::/23`, the whole IETF Protocol Assignments block, which closes the three
anycast holes plus Teredo, ORCHIDv2 and DETs in one line. It also denies `2001:3::/32`,
which is AMT, and `2001:4:112::/48`, which is AS112-v6. Both are globally reachable
services carrying real traffic. The carve-outs are checked first and return explicitly.

`3fff::/20` was the same mistake caught a second time, and caught by measurement rather
than by review. Written as "b[0] is 0x3f and the high nibble of b[1] is 0xf" it spans
`3ff0::` through `3fff::` and denied `3ffe::`, which is public. A /20 fixes the first 20
bits, meaning b[0], b[1] and the HIGH NIBBLE OF b[2], so the block is `3fff:0000::` to
`3fff:0fff::`. The must-stay-allowed list found it within a minute of the rule being
written, which is the second time in two rounds that keeping both directions in one file
has caught an over-denial before it shipped.

Three of the `/28` masks had the same byte-order error in the opposite direction and never
matched their own rows at all. `2001:20::` puts `0x00` in b[2] and `0x20` in b[3], not the
reverse. They were still denied, by the `2001::/23` catch-all, with a misleading reason,
which is the kind of defect that only shows up if you read the reason string and not just
the boolean.

**Round seven's lesson, applied before it could repeat.** That round found that the IPv4
table had grown while the tag map had not, so the newest denials reported as generic
`URL_DENIED` and an alert keyed on `PRIVATE_NETWORK` silently stopped seeing them. Adding
twenty rows is exactly how that happens again, and eight of the new reason strings did in
fact carry none of the needles the tag map scans for. Every new row now asserts its tag as
well as its verdict.

Three more plants: deleting the table fails 20 assertions, the naive `2001::/23` blanket
fails on AMT and AS112-v6, and the wrong `/20` mask fails on `3ffe::`. Twelve across the
round.

### Eighth audit, part four, the review found a leak I had just introduced

An independent review of the whole aggregate diff, by an agent that wrote none of it, found
two real defects and cleared four categories. Both defects were mine, from earlier in this
same round.

- **The base64 brake I added to fix the plus-addressed email spared a whole class of real
  token.** `aojyTcDoAfFSVWztzGhCANprePvlznHDQqs-oTX-PQ==` went from `[REDACTED:HIGH_ENTROPY]`
  to fully in the clear. That is raw `base64.urlsafe_b64encode()` output with its padding
  left on, which is the ordinary shape of a password-reset token, an email-verification
  token or a signed cookie.

  The error was one character wide. Standard base64 is `A-Za-z0-9+/` and base64url is
  `A-Za-z0-9-_`, so a `+` alongside a `-` or `_` really is impossible, and that is what the
  README said. The CODE tested `+` **or** `=`, and `=` is padding shared by both alphabets,
  so it says nothing about which is in use. A base64url token with its padding retained
  tripped a brake meant for something else, carried no `/` so no path rule could rescue it,
  and if it also carried no digit the final test let it go too.

  Worth recording precisely because the prose was right and the code was wrong. Checking
  the code against its own documentation would have caught this; checking the documentation
  against the code, which is the usual direction, would not have.

  The test that was supposed to cover this could not: every fixture in
  `testRealBase64WithPaddingIsStillCaught` used `+` and `==` with no `-` or `_` anywhere, so
  the brake was never evaluated. Five base64url fixtures were added and, planted, they fail.

  **Verified independently of its own fixtures.** The reviewer generated 208,675 realistic
  url-safe-base64-with-padding tokens and measured the leak count fall from 75 to zero, and
  separately confirmed the original plus-addressed email is still spared. Five fixtures
  passing says the examples were fixed; that says the class was.

- **A measured number was published as though it were exact.** "12 out of 400,000" appeared
  in README.md, CHANGELOG.md and the source comment. The reviewer reproduced the stated
  methodology and got 22. A third seed gives 19. All three are honest samples; the mistake
  was mine, in reading a fixed seed as removing sampling error. A seed makes the COMPARISON
  exact, because both sides see identical inputs, and does nothing about the variance of the
  sample. The figure now reads as a range in all three places.

- A stale comment claiming `-` and `_` "carry no signal" survived three lines below the case
  that gives them one. Removed.

Four categories came back clean and are worth naming, since a clean category is a result:
the marker-preserving replacement's cursor arithmetic, including idempotence across twenty
consecutive matches in one string; every bit mask in the new IPv6 table, swept across 46
boundary addresses; the Grux config ladder; and the rest of the README and CHANGELOG claims.

### Eighth audit, part five, the leading slash was most of the published leak rate

Chasing the reviewer's note on the previous item turned up something larger. This file has
published a bare 40-character leak rate of "about 1.2 to 1.3%" for several rounds, and it
was being read as a general weakness of the entropy rule. It was not. It was one hole.

`leadingEmpty` fired on ANY token beginning with `/`. A random base64 secret begins with `/`
one time in 64, which is 1.56%. That is very nearly the whole published figure, and the
resemblance was not a coincidence.
`/JalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12` walked out in the clear while the identical forty
characters without the leading slash were redacted.

A real absolute path of forty characters or more has more than one component, so the rule
now wants three segments, the empty leading one plus two more. Measured on identical inputs
under one seed:

  bare 40-char leak rate   1.295%  ->  0.875%
  real paths mangled        2/814  ->   2/814
  project corpus          40/9,323 -> 40/9,323

A third of the leak closed at no precision cost at all. Two plants bracket the threshold
from both sides: reverting to `leadingEmpty` alone leaks the secret again, and tightening to
seven segments breaks a real path fixture. Fifteen plants across the round.

### Correction: three bugs in the notes above never shipped in any tag

A pre-public audit checked this changelog's narrative against a real 0.4.0 build rather than
against the commit messages, and found that three defects described in the sections above
were introduced AND fixed entirely inside the unreleased window. A consumer pinned to 0.4.0
was never exposed to them:

- The quadratic denial of service. Measured directly on 0.4.0 with the exact shape that took
  11 seconds mid-window: 0.007 seconds. The scanner that carried the defect did not exist yet.
- `curl -u` swallowing the following URL. 0.4.0 does not mangle it, because the basic-auth
  pass did not exist yet. It also does not redact the password, which is on the leak list.
- "Most specific wins" downgrading a Stripe key inside a `postgres://` URL. At 0.4.0 the
  URL-credential pass that caused the downgrade did not exist, so the Stripe pattern tagged
  it correctly on its own.

The sections above are accurate about the code at the time each was written. They read, if
you come to them cold, as though every defect listed is something a released version
exposes, and for these three that is wrong. The released-version story is simpler and worse:
0.4.0 leaks badly, for the reasons now listed in README.md, and none of these three is among
them.

### Eighth audit, part six, the fix for the install instructions was itself unpasteable

A document review of the README as shipped, rather than as a diff, found two defects in the
section written one commit earlier to fix the install instructions.

- **The block labelled "the whole manifest" was not a whole file.** It opened at
  `let package = Package(` with no `// swift-tools-version:` pragma and no
  `import PackageDescription`. Pasted literally into an empty file it fails with "package is
  using Swift tools version 3.1.0 which is no longer supported", an error that names nothing
  the reader did and sends them looking in the wrong place. Verified by pasting it.

  Worth noticing what happened here. The previous commit fixed an install section that did
  not build, and the fix it shipped also did not build, for a different reason. Both defects
  have the same cause: every test in this repo builds the LIBRARY, and until this round none
  of them had ever been a CONSUMER of it.

- **A paragraph was duplicated**, an append that never replaced the passage it was rewriting.
  The stale copy still read "the lowest of the three" three lines below the corrected text
  saying ten seeds and a range of 15 to 31, so the section contradicted itself about its own
  headline number, and the duplicate had been glued onto the end of an unrelated paragraph.

`testEveryManifestInTheReadmeIsPasteable` now reads the real README, finds every fenced
Swift block that declares a `Package`, and fails the build if one lacks the pragma, the
import, or the `platforms` line that was the original defect. Same shape as the pattern-count
and tag-table tests, and planted, it fails. Sixteen plants across the round.

Everything else in the README verified against code or a real build: the 0.4.0 claim list in
full and nothing in it overstated, the `branch: "main"` dependency resolving to this exact
commit, all five URLGuardConfig claims, and the fence determinism claim, where the label
`screen_ocr` really does derive `f942782c85ee7d92` every time, which is the value the source
comment names.

### Seventh audit, URLGuard and the audit surface

This one covers `URLGuard`, the fence and the test suite, none of which round six
touched: it audited the redactor diff and nothing else.

**No SSRF bypass was found.** Thirty URL spellings were probed against `evaluate`,
including backslash-before-userinfo, circled digits, the ideographic full stop, a
percent-encoded IPv6 zone id, ports, uppercase, bare `0`, hex-form IPv4-mapped IPv6 and
Alibaba's CGNAT metadata address. All thirty were denied. The two limitations a reader
might assume are covered, redirects and DNS rebinding, are already documented prominently
in both README.md and SECURITY.md, so that concern is refuted rather than filed.

What was wrong was the part that tells you an attack happened.

- **`illegal character in host` was tagged `URL_DENIED`.** That is the null-byte smuggling
  denial, `http://127.0.0.1%00.example.com/`, the only signal this guard produces that
  implies deliberate intent rather than a typo. It sat in the same audit bucket as
  "empty URL" and "missing host", while README.md tells you to alert on the tag. It now
  has its own tag, `HOST_SMUGGLING`.

  This is the second time the tag map has silently fallen behind. The first was when the
  IPv4 table grew; the fix then was to add needles to a hand-maintained list, which is a
  fix that expires. **A test now pins the whole reason-to-tag table**, and a second test
  fails the build if the code can emit a tag the README does not document. The README's
  tag list used to end in an ellipsis, which is precisely how a tag nobody alerts on goes
  unnoticed, so it is now an exhaustive table.

  One existing test had pinned the defect, asserting `URL_DENIED` with a comment reasoning
  that the denial is structural rather than a private-network hit. The reasoning was right
  and the conclusion was still wrong.

- **A denylist entry written any of four ordinary ways blocked nothing at all.**
  `https://evil.com`, `evil.com:443`, `evil.com/path` and `*.evil.com` all silently
  matched no host while looking completely correct in a config file. A denylist fails OPEN
  when it fails to match, which the code's own comment says, and case, whitespace, dots
  and punycode had all been handled for exactly that reason. Schemes, ports, paths and the
  wildcard spelling every other tool accepts had not. `canonicalEntry` now strips all four.

  The port stripper deliberately refuses to fire when the entry holds more than one colon,
  because a bare IPv6 entry has many and truncating at the last one would silently turn it
  into a different, possibly public, address. There is a test for that specific mistake.

A second pass, run as a six-lens adversarial sweep with three skeptics voting on every
finding, then re-verified by hand at file and line. It found four reachable bypasses the
first pass missed.

- **`http://127.0.0x.1/` was allowed.** The hex-label check required more than two
  characters, so a bare `0x` was neither decimal nor hex, the whole host was judged
  non-numeric and fell through. `inet_aton` reads a bare `0x` as zero, so that host is
  loopback: confirmed with `getaddrinfo(AI_NUMERICHOST)`, which parses it as an IP literal.
  `0x.0x.0x.0x` was allowed the same way and is `0.0.0.0`.

- **`http://127.0.0.1.nip.io/` was allowed.** Wildcard resolvers answer
  `<anything>.10.0.0.1.nip.io` with that address, which turns any private target into an
  ordinary public-looking domain. The metadata table already carried
  `169.254.169.254.nip.io`, so the technique was known and exactly one instance of it was
  blocked while the general shape was not. The embedded ADDRESS is judged now, in both the
  dotted and dashed spellings, rather than the service, because blocking a list of these
  costs the attacker one domain registration to defeat.

  `lvh.me` and `localtest.me` are the other half of that problem and need the opposite
  answer. They resolve to loopback without carrying an address in the name, so there is
  nothing to extract and naming them is the only option available. That list is best
  effort by construction, and the general case is the same limitation as DNS rebinding:
  this guard does not resolve, so it cannot see where a name points. Said plainly in the
  README rather than implied.

- **NAT64 local-use read the wrong bytes, and the first fix for it was also wrong.**
  RFC 6052 puts the embedded IPv4 in a different place for every Network-Specific Prefix
  length, and only the `/96` position was ever read, so `64:ff9b:1:7f00:0:1:808:808`
  carried loopback where the standard puts it for a `/48` and a public decoy where the
  code was looking.

  Adding the `/48` position closed that one input and nothing else.
  `64:ff9b:1:808:a:0:100:0` parks a public `8.8.10.0` in the `/48` slot and a public
  `1.0.0.0` in the `/96` slot while carrying `10.0.0.1` where a `/64` NSP puts it, and it
  was still allowed. RFC 8215 reserves the whole `/48` for local use, so an operator may
  deploy any NSP length inside it and nothing in the address says which, which makes
  checking one length a guess rather than a fix. All six positions are checked now.

  Being aggressive costs nothing here, because every address in that range is by
  definition a translation of some IPv4 and there is no legitimate public IPv6 host to
  over-deny. A slot whose first octet is zero is skipped, since that is what an unused
  slot reads as: without that, the empty slots of an ordinary `/96` translation denied it,
  and an existing must-stay-allowed test is what caught it.

- **`http://evil.com../` walked past the denylist.** `evaluate` stripped one trailing dot
  while `canonicalEntry` stripped all of them, so the two never compared equal. The same
  class as the single trailing dot the strip was written to fix, reintroduced by fixing
  only one side of a comparison.

- **The attacker chose the audit label.** `tag` scanned the denial reason for substrings,
  and the bad-scheme reason interpolates the attacker's own scheme into itself, so
  `denylist://x` reported as `USER_DENYLIST` and `credential://x` as `CREDENTIAL_URL`.
  Anyone counting denial classes was reading numbers hostile input could move. Fixed
  reasons now match exactly and the scheme reason matches on its prefix. `unparseable URL`
  was landing on `PRIVATE_NETWORK` for the same reason, inflating the one tag the README
  tells you to alert on.

- **An indented PEM leaked its body verbatim.** The whole-block pattern is line-anchored
  and had no tolerance for leading whitespace, so a key inside YAML, JSON, a markdown
  block or a code sample matched its header and stopped. The body then depended entirely
  on the entropy pass, which needs mixed case AND a digit, so a single-case base64 line
  walked out underneath a header that had been helpfully replaced with `[REDACTED:PEM]`.
  The unindented form was consumed whole, which is exactly what made it look covered.
  This is the third instance of one defect: the comment on the JSON-escaped variant
  describes the same thing happening with escaped newlines.

- **The fence neutralised one tag, in one case.** The body could open a SECOND block with
  an attacker-chosen `kind`, so a page could print
  `<untrusted_data kind="operator_policy">` and invite the model to read what follows as a
  more trusted class. This does not escape the fence, the real closer still carries the
  real id, so the original framing of it as an escape was wrong. `</UNTRUSTED_DATA>` also
  passed through untouched, and a model reading a transcript does not owe you case
  sensitivity when every markup language it has seen treats tags as case-insensitive.
  Both tags are neutralised now, case insensitively.

**Two findings did not reproduce and were not acted on.** An alleged idempotence failure,
`redact(redact(x)) != redact(x)`, held on all seven shapes probed including the new tags.
An alleged verbatim leak from an indented PEM was real only in the sharper form above: the
reported version was rescued by the entropy pass, and it took a deliberately single-case
body to make it leak.

**A test in the suite was measured as vacuous, and it was one written last round.**
Neutering `isWhitespaceSeparable`, the brake that got its own CHANGELOG paragraph in round
six, left all 82 tests green. Every benign line written to justify it was actually being
saved by the locator brake beside it, because each happened to contain a URL, a path or a
filename. Four corpus lines now exist that only that brake can save.

Real-corpus precision is unchanged by this round: 41 of 9,062 lines, and the identical
number with the previous redactor on the identical corpus, so the shift from the 0.396%
quoted above is the corpus growing with new prose rather than a regression.

### Sixth audit, the redactor scanner

A sixth audit. Round five replaced the label regex with a scanner and closed six leak
classes; this round measured what that cost and found the scanner had traded away
precision and linearity without anyone checking either.

**The finding that matters most is a method one.** The benign corpus was thirty
hand-picked lines and all thirty passed. Run against this project's own 8,590 lines of
source and documentation instead, the redactor was destroying **0.780% of them**, roughly
one line in 128, including URLs, filenames and Swift function names. A hand-picked corpus
tells you about the cases you thought of. It is now 0.396%, and the measurement is the
gate rather than the sample.

- **The scanner was quadratic on attacker-chosen text.** Every start position inside one
  run of name characters shares that run's end, so restarting one character along
  re-walked the whole remainder. 48KB of `keykeykey` took 11 seconds and 80KB of
  `auth.auth.` took 20. Now linear: 1MB of the same input takes about 3s. **The committed
  superlinearity test already covered this shape and passed anyway**, because 8KB stays
  under an absolute time budget. It now tests the growth ratio as well as the clock, and
  at a scale where the difference shows: with the fix reverted, that test reports 8x input
  costing 65x and taking 121 seconds.
- **A credential word anywhere inside any token made the NEXT token disappear.**
  `curl -u bot:hunter2Passw0rd https://api.acme.io` ate the URL, and `see the auth
  README.md` ate the filename. Whitespace-as-separator now requires the whole name to be
  one of eleven exact credential names, and rejects values that are URLs, paths or
  filenames. This was the single largest source of destroyed text.
- **Four separator shapes that leaked**: `apiKey => "..."` read the value as a bare `>`,
  `setApiKey("...")` had no separator the scanner recognised, and YAML that puts the value
  on the next line, plainly or behind a `>-` block indicator, was missed entirely. The
  call form requires a quote, so `decryptWithKey(masterKeyMaterial)` is left alone.
- **Session identifiers are credentials.** `Set-Cookie: session=`, `JSESSIONID=`, `Cookie:`
  and `csrf=` carry no credential word in the name and went out in full. A session id is
  what a stolen cookie replays.
- **`Bearer <token>` with no header name in front of it**, which is how `curl -v` and most
  request logs print it. Lowercase hex is the usual shape and the entropy pass cannot see
  it, because that rule requires mixed case. Also `curl -u user:password`, which is the
  same credential as `https://user:pass@host` wearing a flag instead of a scheme.
- **Supabase `sbp_` tokens** added to the provider patterns, which is what the README
  pattern-count test immediately caught as drift. That test earned its place.
- **The punctuation-only value brake moved from 12 characters to 20.** It was eating
  `"key": "projects_json"` out of every blueprint and `key.anthropic` out of every config
  enum. Measured, not guessed: 0.547% of lines destroyed to 0.396%, leak corpus unmoved.

**Known leaks, stated rather than fixed.** Four classes still survive and each was a
decision: `<password>value</password>` and `<input name="password" value="...">` need
markup awareness, and treating `>` as a separator would redact the value of every `<key>`
in every plist. `mysql -phunter2` glues the value to a one-letter flag with nothing to
distinguish it from `-project`. `signature=` was declined because a webhook signature is a
MAC over one payload rather than a reusable credential, and adding the word redacts
`signature = inspect.signature(fn)` in ordinary Python.

**Unchanged and still true:** a bare 40-character credential with no label and no provider
prefix leaks at about 1.2%, measured over 20,000 samples on every run.

## 0.4.0

**Use this one.** Every earlier tag leaks credentials, see below.

Fixes what a fourth adversarial audit found in 0.3.1. The theme is that two rounds of
tuning one number could not solve the problem, because the number was the wrong dial.

- **Secrets are now recognised by their label.** `HF_TOKEN=`, `AWS_SECRET_ACCESS_KEY=`,
  `"api_key":` and friends have their value redacted regardless of its length or shape.
  This replaces two failed attempts: a 40-character floor that leaked every `NAME=value`
  secret shorter than that, and a 32-character floor that started eating ordinary
  identifiers like `kCVPixelFormatType_32BGRA_FullRange`.
- **The path heuristic was discarding real keys.** It rejected any token with one segment
  under four characters, which base64 produces by chance. Measured over 200,000 random
  AWS secret access keys it threw away 14% of them, rising to 34% at session-token
  length. It now requires two independent signals, which takes the LABELLED form
  (`AWS_SECRET_ACCESS_KEY=...`) to 0%. **Correction:** an earlier version of this entry
  claimed 0% without qualification. That was wrong. A BARE 40-character key with no label
  still leaks at about 1.5%, measured over 20,000 samples. The 0% figure came from
  measuring the labelled form and generalising, which is the same mistake this project
  keeps making: a number verified in one shape and asserted in another.
- **Private keys inside JSON now lose their bodies.** Where newlines are escaped as
  `\n`, as in a GCP service account file, the line-based pattern matched only the header
  and let 4 of 25 body lines reach the model behind a `[REDACTED:PEM]` tag.
- **Named cloud metadata endpoints are denied.** `metadata.google.internal`,
  `host.docker.internal`, `kubernetes.default.svc` and others were reachable. The IP was
  blocked and the name, which is the form everybody actually types, was not.
- **Six providers the generic pass structurally cannot see**: HuggingFace and Shopify
  tokens carry no digit or are single case, so no entropy rule reaches them without
  eating ordinary text. Added as explicit patterns, along with GitLab, npm, DigitalOcean
  and SendGrid.
- **A test that pinned a leak as correct behaviour has been rewritten.** It asserted
  `redact(s) == s` against a live-shaped bearer token, so the next person to fix the leak
  would have had to delete an assertion that looked deliberate.
- **A performance regression, caught before release.** The first version of the label
  pattern opened with a wildcard before its alternation and cost 0.711s on 760KB of
  ordinary prose containing no secrets. Anchoring on the keyword brought that to 0.076s.

## 0.3.1

**Superseded and unsafe, do not use.** Fixes label-swallowing, the NAT64 local-use
prefix, and version signposting. Its one functional change traded a cosmetic complaint
for a security regression: every `NAME=value` secret shorter than 40 characters went out
in plaintext, and a test was added that pinned the leak as correct. Both fixed in 0.4.0.

## 0.3.0

**Superseded and unsafe, do not use.** It allows `64:ff9b:1::` straight to loopback, and
the path heuristic added here discards 14% of AWS secret access keys.

Fixes seven regressions that the 0.2.x security fixes introduced. They were found by
attacking the fixed code on the assumption that a fix is the most likely place for the
next bug, which turned out to be correct twice over.

- **Redactor went blind to base64 secrets.** Dropping `/` from the entropy alphabet to
  protect file paths also dropped it from standard base64, so the AWS secret access key
  leaked in full. `/` is back; paths are now excluded structurally, by rejecting any
  token with a segment under four characters.
- **One non-ASCII character made redaction quadratic.** A single curly apostrophe took
  296KB from 0.030s to 1.970s, because converting `NSRange` to a Swift String range is
  O(n) on non-ASCII input. Rewritten as one forward pass: 0.049s.
- **PEM tail leaked.** Body lines required 16+ characters and a real key's final base64
  line is often shorter, so the last quantum survived while the block was stamped as
  redacted.
- **Entropy floor lowered to 32 ate ordinary identifiers.** Back to 40, which is the
  shortest credential the generic pass is responsible for.
- **Fence ids were silently weakened.** A caller label was filtered to its hex characters,
  so `screen-capture` became `id="ceecae"`: six guessable characters. Non-hex labels are
  now hashed to full width.
- **`tag()` missed the newest denials.** The IPv4 table grew and the tag mapping did not,
  so Oracle Cloud metadata reported as `URL_DENIED` and any alert keyed on
  `PRIVATE_NETWORK` stopped seeing it.
- **Denylist failed open for internationalized domains.** `URL.host` is punycode, entries
  were compared raw. Entries are punycoded now, and blank entries can no longer match.

Breaking: fence ids under 16 hex characters are hashed rather than used verbatim.

## 0.2.1

Fixes an O(n²) denial of service introduced in 0.2.0: the PEM pattern's lazy scan meant
every `BEGIN` marker rescanned the rest of the document. 1.2MB of hostile input took 72
seconds. **Still leaks the AWS secret access key, do not use.**

## 0.2.0

Fixes eight defects found in the first audit round, including two criticals: PEM blocks
where only the header was redacted while the key body reached the model, and a forgeable
`</untrusted_data>` fence that any web page could close itself.

**Superseded and unsafe, do not use.** It introduced the base64 blindness and the
quadratic pass fixed in 0.3.0.

## 0.1.0

First release. **Do not use.** It ships two critical defects:

- `SecretRedactor` matched only the `BEGIN` line of a PEM block, tagged it as redacted,
  and then passed the entire private key body through to the model.
- `wrapAsUntrusted` closed with a fixed literal, so any untrusted text containing
  `</untrusted_data>` escaped the fence and the remainder read as operator instructions.

It also destroyed ordinary text, turning `task-management-system` into
`ta[REDACTED:OPENAI_KEY]`, and its denylist failed open on any entry with a trailing dot.
