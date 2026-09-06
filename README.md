
# Grux

[![CI](https://github.com/dotcomjack/grux-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/dotcomjack/grux-guardrails/actions/workflows/ci.yml)
[![Licence](https://img.shields.io/badge/licence-MIT-8C6A2F)](LICENSE)


Guardrails for desktop AI agents, in Swift. MIT licensed. Short version: [gruxai.com](https://gruxai.com).

```text
SecretRedactor.redact  "deploy with sk-ant-api03-..."  ->  "deploy with [REDACTED:ANTHROPIC_KEY]"
URLGuard.evaluate      "http://[64:ff9b::7f00:1]/"     ->  denied, tag PRIVATE_NETWORK

125 tests, 0 failures, on macOS 14 and macOS 15.  26 patterns.  0 external packages.
2 of 814 real paths mangled.  40 of 9,323 corpus lines leaked.  6 of 9 tags leak credentials.
```

Everybody wants their own Jarvis. Most of the public attempts are demos: a loop that
pipes a microphone into a model and executes whatever comes back. They are impressive
for an afternoon and then you notice that the thing reading your screen is also
transcribing your password manager, and that it will fetch any URL a web page tells it
to.

This library is the unglamorous half of that problem, extracted from a Mac agent that
has been running against a real workload daily. It does not include the agent. It
includes the parts you would otherwise write badly at 2am and never test.

**Be precise about whose credentials leaked.** This library failed to redact its users' secrets.
No credential of mine has ever been in this repository: the only AWS-shaped string in the
whole history is `AKIAIOSFODNN7EXAMPLE`, AWS's own published documentation example, and it
sits in a test fixture. Nothing was deleted or force pushed, because the record is the point.

**Status: early.** Two modules today, both production code with real coverage. More
listed under Roadmap. It is versioned honestly, so what is here is here and nothing is
promised as shipped that is not.

## Install

```swift
// Package.swift
.package(url: "https://github.com/dotcomjack/grux-guardrails.git", from: "0.7.0")
.product(name: "GruxGuardrails", package: "grux-guardrails")
// then, in your source
import GruxGuardrails
```

Requires macOS 14, and the Swift 5.9 tools version or newer. Zero external packages, and
you need not take that on trust: `grep -c '.package(' Package.swift` returns 0 and there
is no `Package.resolved`. The library also builds clean on iOS, watchOS and Linux, and
the TEST SUITE is macOS only, both measured under
[Platforms and the whole manifest](#platforms-and-the-whole-manifest).

**Use 0.7.0.** The six tags before 0.5.0 all leak credentials, and each one looked fine
when it was cut. That disclosure has its own section:
[Earlier tags leak credentials](#earlier-tags-leak-credentials).

## Limits

Read this part. It is the section a security library is actually judged on, and each
module has its own longer one, [for SecretRedactor](#secretredactor-what-it-does-not-do)
and [for URLGuard](#urlguard-what-it-does-not-do). What this library is responsible for and
what it deliberately is not, written out as attacker, asset and boundary rather than left
implied by a feature list, is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). The short
version, with every line below pinned by a test so it cannot drift quietly:

- **SecretRedactor is a matcher, not a parser**, so a credential in a format no pattern
  covers passes straight through, by construction.
- **It destroys some ordinary text.** Across 30 ordinary config lines whose field NAME
  merely contains a credential word, 20 were destroyed. Base64 data URIs and
  `integrity="sha384-..."` hashes go the same way.
- **A labelled credential inside a JSON array, a YAML sequence, or an XML or plist
  element body survives.** Disclosed, not fixed, and pinned by `testKnownDefect` tests.
- **Single-case hex is deliberately exempt**, which keeps git SHAs and checksums intact
  and lets a 32 or 64 character lowercase-hex API secret through untouched.
- **URLGuard does not follow redirects.** It judges one string. You must re-evaluate
  every hop, and the delegate below shows the shape that actually fails the task.
- **URLGuard does not resolve DNS**, so it cannot stop rebinding, and it cannot tell a
  private TLD from a public domain.
- **`allowlist` overrides the private-network denial.** That is the whole point of it
  and also its teeth.

**There is no fuzz target, and fuzzing is not yet performed.** The adversarial corpus is
what stands in for it: 125 tests, table-driven, with the must-stay-redacted cases sitting
in the same file as the must-survive cases so the trade cannot drift in one direction
unnoticed. Three of those tests are honest known-defect expectations rather than passes.

## Earlier tags leak credentials

Six tags were published before 0.5.0 and all six were later found to leak, including by
audits of code that had already survived several earlier ones. 0.5.0 is the most heavily
audited state this library has been in and that is a statement about effort, not a
guarantee. 0.6.0 is 0.5.0 with the module renamed and nothing else. 0.6.1 is 0.6.0 plus
two provider patterns, an RFC 2765 decode, and a platform floor raised to macOS 14. 0.6.2
is 0.6.1 with no source change at all: `Sources/` is byte identical, and the release exists
because the documentation shipped inside the 0.6.1 tag told readers to install 0.6.0. 0.7.0
renames the module from `Grux` to `GruxGuardrails` and changes nothing else.

**The module was `GruxKit` up to and including 0.5.0, and is `Grux` from 0.6.0 onward.**
That rename is the only breaking change in 0.6.0, and it is why every snippet here asks
for a version at or above 0.7.0. They ask for 0.7.0 specifically because that is the
current tag and it carries fixes 0.6.0 does not.

Be precise about what breaks, because `from:` is a range and not a pin. `from: "0.7.0"`
means `[0.7.0, 1.0.0)`, so it can only ever resolve to a tag that has the `GruxGuardrails`
product.
What fails is a constraint that actually holds you at or below 0.5.0: `.exact("0.5.0")`,
or an `upToNextMinor` range, or `from: "0.5.0"` evaluated before 0.6.0 is tagged. In any of
those, `import GruxGuardrails` fails to resolve with `product 'Grux' not found`, because 0.5.0
declares the product as `GruxKit`. If you are held at 0.5.0 or earlier for any reason, keep
`import GruxKit` until you bump.

What the earlier tags actually do. 0.1.0 passes private key bodies straight through to the
model and has a forgeable injection fence. 0.2.0 and 0.2.1 leak the AWS secret access key,
and 0.2.0 additionally carries the base64 blindness and the quadratic pass that 0.3.0
fixed. 0.3.0's own path heuristic discards 14% of AWS secret access keys. 0.3.1 sends every
`NAME=value` secret shorter than 40 characters out in plaintext, and shipped a test that
pinned that leak as correct behaviour, which is the worst kind because the suite was green
the whole time. Both were fixed in 0.4.0. And
0.4.0, measured against a real build of it rather than inferred from its changelog, allows
the loopback and NAT64 SSRF bypasses and leaks indented PEM bodies, `PGPASSWORD=`, session
cookies, `Set-Cookie`, bare `Bearer` headers and `curl -u` passwords. Worst of that set,
and the one to check if you have ever pinned it: **a denylist entry written any way other
than a bare host matches nothing at all.** `https://evil.com`, `evil.com:443` and
`*.evil.com` are all silently inert against `denylist: ["evil.com"]`, so your own denylist
fails open and looks configured.

Earlier tags stay resolvable so existing checkouts do not break, and are documented in
[CHANGELOG.md](CHANGELOG.md) so nobody adopts one by accident. Each one also has its own
GitHub release saying plainly that it leaks and what to move to. The per-tag disclosure,
with a severity and a vector for each, is in
[docs/DISCLOSURE-2026-08.md](docs/DISCLOSURE-2026-08.md).

Pre-1.0, so treat the minor version as breaking. If pinning exactly matters to you, pin
`.exact("0.7.0")`, which is the current tag, and not an earlier one.

## Platforms and the whole manifest

**Your own manifest needs `platforms: [.macOS(.v14)]` too.** That line is not optional and
leaving it out is a build failure, not a warning:

```
error: the library 'YourAgent' requires macos 10.13, but depends on the product 'Grux'
which requires macos 14.0
```

So the whole manifest, and this time it really is the whole file, opening pragma and import
included. Without those two lines a literal copy of the block fails with an error about
Swift tools version 3.1.0, which tells you nothing about what is actually wrong:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "YourAgent",
    platforms: [.macOS(.v14)],
    products: [.library(name: "YourAgent", targets: ["YourAgent"])],
    dependencies: [.package(url: "https://github.com/dotcomjack/grux-guardrails.git", from: "0.7.0")],
    targets: [
        .target(name: "YourAgent",
                dependencies: [.product(name: "GruxGuardrails", package: "grux-guardrails")]),
    ]
)
```

Both claims here were checked by building them. A fresh `swift package init` plus the two
isolated snippets above and nothing else fails on the platform mismatch; adding the
`platforms` line builds clean. The block immediately above was pasted byte for byte into an
empty file and built on its own.

**macOS 14 is the floor CI can prove, not a limit of the code.** Both source files import
Foundation and nothing else, with no platform conditionals anywhere, so the library builds
well outside its declared floor. Measured: `xcodebuild -scheme Grux -destination
'generic/platform=iOS'` reports `** BUILD SUCCEEDED **`, watchOS reports the same, and
`swift build` in the official `swift:6.1` Linux image exits 0 from a clean build path.
tvOS and visionOS are untested here only because those platforms are not installed on the
machine that ran the check.

**The test suite is macOS only, and that is a real gap.** Three tests use
`XCTExpectFailure`, which ships with Apple's XCTest and not with swift-corelibs-xctest. So
on Linux `swift build` exits 0 while `swift build --build-tests` exits 1 with three
`cannot find 'XCTExpectFailure' in scope` errors. If you clone this on Linux, `swift test`
does not compile. Nothing in CI catches that today, because there is no Linux leg, and a
compatibility badge built from `swift build` alone will show Linux green regardless.

## SecretRedactor

An agent that can see your screen will eventually see a secret, and the moment that text
is interpolated into a prompt it leaves your machine.

```swift
let clean = SecretRedactor.redact(ocrText)
// "deploy with sk-ant-api03-…"  ->  "deploy with [REDACTED:ANTHROPIC_KEY]"
```

Twenty-six patterns plus a generic high-entropy pass. Two properties are
load-bearing and both are pinned by tests:

**Most specific wins.** A Stripe live key is tagged `[REDACTED:STRIPE_LIVE_SECRET]`, not
the generic entropy tag. Precision is what makes the audit trail worth reading later.

**It is idempotent.** `redact(redact(x)) == redact(x)`. Prompts get assembled from
fragments that were each cleaned on the way in, so the function runs over its own output
constantly. It holds because `[`, `]` and `:` sit outside every character class, so a
marker is only ever seen as the short runs `REDACTED` and `HIGH_ENTROPY`, both well under
the length floor.

PEM blocks are consumed whole, header through footer, including a truncated block with no
footer. Redacting the header alone would tag the block and then hand the model every byte
of the key, which is the failure this library exists to prevent.

The generic pass considers a 40+ character run carrying mixed case **and** digits, or one
containing base64 padding in a base64 alphabet, and then applies the path exclusions below
before deciding. Both halves of that sentence are load-bearing. "Considers" rather than
"fires on", because a run can clear the character test and still be spared as a path. And
"in a base64 alphabet", because standard base64 is `A-Za-z0-9+/` while base64url is
`A-Za-z0-9-_`, and neither contains both: a run carrying a `+` alongside a `-` or `_` is
not base64 in either spelling. Without that qualifier a plus-addressed email address was
destroyed the moment its local part reached 40 characters.

**`=` is not part of that test, and getting it wrong was a leak.** Padding belongs to both
alphabets, so it says nothing about which is in use. Only `+` is exclusive to standard
base64 and only `-` and `_` are exclusive to base64url. An implementation that tested
`+` **or** `=` against `-` or `_` spared raw `base64.urlsafe_b64encode()` output with its
padding left on, which is the ordinary shape of a password-reset token, an
email-verification token or a signed cookie. Those carry no `/`, so no path rule applies
either, and one without a digit walked out completely in the clear. The sentence above was
already written correctly when the code was not, which is the argument for checking code
against its own documentation rather than the other way round.

That fix was verified independently rather than by its own fixtures. A reviewer that wrote
none of this code generated 208,675 realistic url-safe-base64-with-padding tokens and
measured the leak count fall from 75 to zero, which is the class closing rather than five
examples passing.

What stays traded away: a plus-addressed local part of 40 or more characters containing no
hyphen and no underscore is still redacted. That case annoys. The other one harms.

That rule exists because **a redactor that mangles ordinary
text is a redactor people switch off**, and a switched-off redactor protects nothing.
Mixed case with digits is what separates a random token from prose, an identifier, or a
hex digest, and hex digests being single case by convention is exactly what keeps git
SHAs and checksums intact.

Paths are excluded structurally rather than by dropping `/` from the alphabet, which
matters more than it sounds. Dropping `/` was tried, and because standard base64 contains
`/` it blinded the redactor to the AWS secret access key, which is the half of the AWS
pair that actually grants access. Trading a cosmetic false positive for a total miss on
the highest-value credential is a worse bug than the one it fixed.

So paths are recognised instead, on three independent signals. An empty leading segment,
because an absolute path opens with a separator. Several short segments together with a
mean segment length under ten, because a path is short names joined by separators while a
blob split by an incidental slash leaves long runs either side. And, since round eight,
the segments reading as NAMES: four characters or more, letters plus at most a hyphen or
an underscore, no digits, and at least one vowel, with three such names forming a majority
of at least four segments.

That third signal is the one that covers a dot. `.` is outside the token alphabet, so a
match starts after it, which discards the leading separator the first signal reads and
re-bases the second signal's statistics on the remainder. Measured across 814 real paths
and URLs, the first two signals alone destroyed 357 of them, 43.9%, including every GitHub
permalink with a real owner and repository name. All three together leave 2.

The cost is published rather than implied. Against 100,000 random base64 strings at each of
40, 64, 128 and 200 characters, generated from a fixed seed so the comparison is causal, the
name signal newly spares 24.0 secrets per 400,000, every one of them carrying three or more
slashes. Measured over ten seeds and 4,000,000 trials: 240 newly spared, zero newly caught,
individual seeds ranging 15 to 31. Two earlier one-off runs gave 12 and 22, and an earlier
version of this file published that 12 alone as though a fixed seed made it exact. Seeding
makes the COMPARISON exact, since both arms see identical inputs, and does nothing about the
spread of the estimate.

Two numbers in this section are audit-trail figures from a specific run rather than
assertions you can re-run: the 814 paths were taken off a working machine and are not in
this repo, and "the project's own corpus" is measured against this source tree, which grows.
The pattern count and the tag table are different, and both are mechanically pinned by
tests that fail if the README drifts.

**The first signal was also the largest hole in the published leak rate, which nobody had
noticed because the number was being read as a general weakness.** An empty leading segment
fires on ANY token beginning with `/`, and a random base64 secret begins with `/` about one
time in 64, or 1.56%, against a reported bare-token leak rate of roughly 1.3%. The two were
very nearly the same number and that was not a coincidence.
`/JalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12` walked out in the clear while the same forty
characters without the slash were redacted. Requiring a real absolute path to have more
than one component takes the 40-character rate from 1.295% to 0.875%, measured on identical
inputs, and leaves the path corpus at 2 of 814 and the project corpus at 40 of 9,323
exactly where they were.

The price is pinned as an assertion rather than left to be discovered: a SINGLE-component
absolute path of 40 characters or more carrying mixed case and a digit is now redacted.
No path in the 814 has that shape, and the real single-component entries under `/` are
short. If you hit a genuine one you get a failing test naming the trade rather than a
silent mangle, and the fix then is a word-shape test on the component, not loosening the
segment count, which is the thing that was leaking.

Absolute paths, GitHub permalinks, DerivedData directories, ModuleCache
filenames, kebab-case identifiers, md5 sums and fifty consecutive digits all pass through
untouched, and there are tests asserting each one, with the must-stay-redacted cases sitting
in the same file so the trade cannot drift in one direction unnoticed.

There is also a fence for the injection half of the problem, which is a different problem
from the secrets half:

```swift
let block = SecretRedactor.wrapAsUntrusted("screen_ocr", pageText)
// <untrusted_data kind="screen_ocr" id="9f3a2b7c1d4e8a05"> … </untrusted_data id="9f3a2b7c1d4e8a05">
```

Text the agent *read* and text you *typed* are indistinguishable once concatenated into a
prompt.

**The random id in the tag is load-bearing.** A fixed `</untrusted_data>` closer is
forgeable by the very input it is meant to contain: any web page that prints that literal
string escapes the block, and everything after it reads as your instructions. That is a
one-line bypass, written by the attacker, in the exact input class this function exists to
handle. With an unguessable id in both tags a forged closer does not match. Tell the model
in your system prompt that only the closer bearing the matching id ends the block.

**Which means you need the id BEFORE you write the system prompt**, and the two-argument
form above generates one internally where you cannot reach it. Mint it yourself and pass it
in:

```swift
let fenceID = SecretRedactor.newFenceID()
// ... put fenceID in your system prompt ...
let block = SecretRedactor.wrapAsUntrusted("screen_ocr", pageText, id: fenceID)
```

Do not pass a human-readable label as the id. It is only unguessable if it is random, and a
label defeats the entire mechanism: `"screen_ocr"` always derives the same id, so an
attacker who sees one transcript can forge the closer in every future one.

The fence still does not make injection impossible. It gives the model a boundary it can
act on, and it is not a substitute for withholding capabilities the agent did not need.

### SecretRedactor: what it does not do

It is a matcher, not a parser, so it cannot catch a secret that does not look like one.
A password, a session cookie with a short opaque value, an internal hostname, or a
credential in a format no pattern covers all pass straight through. New providers appear
constantly and this list will always trail them.

**Ordinary config lines are destroyed when the field NAME merely contains a credential
word.** This is the limitation most likely to affect you, and it fires on text that is not
secret at all. Measured directly:

```
"author": "Alice Smith and Bob Jones"      ->  "author": "[REDACTED:ASSIGNED_SECRET]"
"keywords": "swift, security, redaction"   ->  "keywords": "[REDACTED:ASSIGNED_SECRET]"
auth_url: https://accounts.example.com/... ->  auth_url: [REDACTED:ASSIGNED_SECRET]
token_url: https://oauth2.example.com/...  ->  token_url: [REDACTED:ASSIGNED_SECRET]
```

`author` appears in every `package.json`. `auth_url` and `token_url` are the standard OIDC
discovery fields. The rule cannot tell "this name contains auth" from "this value is a
credential", so it takes the value. Across 30 ordinary config lines of this shape, 20 were
destroyed. If you feed an agent config files, expect that.

**The same blind spot covers an XML or plist element BODY.**
`<password>s3cretPassw0rdForProd</password>` survives, while the attribute form
`<user password="...">` is caught. Maven `settings.xml` and Apple `.plist` files both put
credentials in element bodies, so if an agent reads either, expect the value through. It is
the same adjacency problem as the JSON case and it is not fixed for the same reason.

**A labelled credential inside a JSON array or a YAML sequence survives.**
`POSTGRES_PASSWORD=s3cretPassw0rdForProd` is caught. The same secret written as
`{"passwords": ["s3cretPassw0rdForProd"]}` is not, and comes back untouched. The
credential-word rules read a name and the value that follows it, and a bracket between the
two breaks that adjacency, so the value is never examined. Any config format that groups
secrets under a plural key is affected, which includes a great deal of real Kubernetes,
Docker Compose and CI configuration.

This is not fixed, and the reason is the sentence above about false positives rather than
laziness. Widening the credential-word rules to walk into collections makes them fire on
far more text, and they are already the least precise thing here: measured over 30 ordinary
config lines whose field name merely CONTAINS a credential word, 20 of them were destroyed.
Trading one missed shape for twenty mangled configs is the wrong direction for a tool whose
whole argument is that destroying ordinary text is worse than missing. It is pinned by
`testKnownDefectCredentialsInsideAJSONArrayOrYAMLSequenceSurvive` so it cannot regress
quietly, and it is written here so nobody discovers it the hard way. If you feed an agent
structured config, do not rely on this to catch secrets inside collections.

**Base64 data URIs and integrity hashes get destroyed, and that one is paid in the other
direction.** Inline images, inline fonts, CSS `url(data:...)` and the
`integrity="sha384-..."` on every CDN script tag are all long high-entropy runs in a base64
alphabet, which is precisely the shape of a credential. Nothing here can tell them apart by
shape, so if you feed an agent raw HTML, expect inline assets to come back redacted. The
obvious fix, exempting whatever follows `;base64,`, is a trap: that prefix appears in text
the agent is reading, so an attacker writes `data:image/png;base64,sk_live_...` and walks a
live key straight through. The cost is pinned by a test instead of removed. One asymmetry
worth knowing: a JPEG data URI survives, because its body opens `/9j/` and the leading
slashes land it in the path exclusions. Same construct, opposite outcome, decided by the
payload rather than by any rule.

**Single-case hex strings are deliberately exempt, and that is a real gap, not just a
feature.** It is what keeps git SHAs, md5 and sha256 checksums intact, and those appear
constantly in the logs and diffs an agent reads. The cost is that a 32 or 64 character
lowercase-hex API secret, which several providers still issue, goes through untouched.
A Twilio auth token is the everyday example: `auth_token=<32 hex>` is caught by the
assignment rule, and the same 32 characters standing alone in a log line are not. It
is a tradeoff and I would make it again, but you should know which side of it you are on.
If your stack uses hex secrets, add a pattern for them rather than relying on the generic
pass.

It is the last line, not the only one, and it is not a reason to feed an agent credentials
it did not need.

## URLGuard

The threat is server-side request forgery with a language model as the confused deputy.
Your agent runs on your laptop, inside your network, and it will follow a link that came
from a web page, an email, or its own hallucination.

```swift
let decision = URLGuard.evaluate(url, config: config)
guard decision.isAllowed else {
    log("blocked", decision.tag)
    return
}
```

`tag` is the complete set below, and it is complete on purpose: this list used to end in
an ellipsis, and a denial reason quietly landing outside the tags anyone was alerting on
is a defect that has now happened twice. A test fails the build if the code can emit a tag
this table does not name.

| Tag | Means |
|---|---|
| `PRIVATE_NETWORK` | Loopback, RFC 1918, link-local, CGNAT, metadata hostnames, `.local`, single-label names, and every IPv6 equivalent. |
| `HOST_SMUGGLING` | An illegal character in the decoded host, for example `127.0.0.1%00.example.com`. Somebody is trying to get a loopback target past the parser. **Alert on this one loudest**, it is the only tag that implies intent. |
| `CREDENTIAL_URL` | `user:pass@host`. Denied with no override. |
| `USER_DENYLIST` | Your own denylist matched. |
| `BAD_SCHEME` | Not `http` or `https`. |
| `URL_DENIED` | Empty, unparseable, or no host. Ordinary noise, not an attack signal. |

Default posture: `http` and `https` only, credential-bearing URLs always denied with no
override, and loopback, private ranges, link-local, carrier-grade NAT, `.local` and bare
single-label hostnames all denied.

The interesting work is that last check, because "is this address private" has more wrong
answers than right ones. All of these reach loopback or the cloud metadata endpoint, and
none of them survive a naive dotted-quad parse:

```
0177.0.0.1              octal
0x7f.0.0.1              hex
127.1                   shorthand
2130706433              bare 32-bit integer
[::ffff:127.0.0.1]      IPv4-mapped IPv6
[::ffff:7f00:1]         the same thing spelled in hex
[64:ff9b::7f00:1]       NAT64 well-known prefix
[64:ff9b:1:7f00:0:1:808:808]  NAT64 local-use /48, target where RFC 6052 puts it for
                        a /48, with a public decoy parked in the trailing bytes
[::ffff:169.254.169.254] cloud metadata in an IPv6 costume
127.0.0x.1              a bare `0x` label, which inet_aton reads as zero
127.0.0.1.nip.io        a wildcard resolver that answers with the address in the name
10-0-0-1.nip.io         the same thing in the dashed spelling
lvh.me                  resolves to loopback with NO address in the name, so it has to
                        be named rather than derived, and that list is best effort
[64:ff9b:1:808:a:0:100:0] 10.0.0.1 at the /64 NSP slot, with public decoys parked in
                        both of the slots a naive check reads
evil.com.               trailing-dot FQDN, resolves identically, different string
evil.com..              and the same trick with a second dot, which is a different
                        string again and has to reduce to the same entry
[2001:1::1]             PCP anycast, absorbed by the nearest responder, which is your
                        own NAT or firewall. Reads as ordinary global unicast.
[2001:1::2]             the same shape for TURN, [2001:1::3] for DNS-SD SRP
[2001:0:0:1::1]         Teredo, which carries the tunnel server's IPv4 in the clear and
                        the client's IPv4 bitwise-inverted in the trailing bytes
```

Every line above is a test case. The trailing dot one matters more than it looks: it has
to be normalized *before* list matching, not after, or one appended character walks past
your denylist.

Both IANA special-purpose registries are now covered row by row, IPv4 and IPv6. The IPv6
table used to classify 8 of its 25 rows, which was an absence rather than a decision. The
three anycast addresses above were the genuine holes in it; the rest were unroutable
identifiers, documentation ranges and discard blocks, where denying costs nothing.

Denying by prefix is where this gets dangerous, and the tests carry both directions for
that reason. `2001::/23` would close five of those rows in one line and would also deny
AMT at `2001:3::/32` and AS112-v6 at `2001:4:112::/48`, which are globally reachable
services carrying real traffic. `3fff::/20` is a second instance: it fixes the first 20
bits, so the documentation block runs `3fff:0000::` to `3fff:0fff::` and `3ffe::` is
ordinary public space. Every deny assertion sits next to the allow assertions for its
neighbours.

`evaluate` is pure and synchronous, which is what makes the policy table-testable. Wire
your own auditing around it.

### URLGuard: what it does not do

Read this part. A guard whose limits you do not know is worse than no guard, because you
stop looking.

**It does not follow redirects, and that is the biggest gap.** `evaluate` judges one
string. A perfectly public URL is free to answer `302 Location: http://127.0.0.1:8080/`,
and nothing here will see it. **You must re-evaluate every hop.** With `URLSession` that
means refusing the redirect in the delegate:

```swift
final class GuardedRedirects: NSObject, URLSessionTaskDelegate {
    let config: URLGuardConfig
    private(set) var blocked: URLGuardDecision?
    init(config: URLGuardConfig) { self.config = config }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        let next = newRequest.url?.absoluteString ?? ""
        let decision = URLGuard.evaluate(next, config: config)
        guard decision.isAllowed else {
            blocked = decision
            completionHandler(nil)   // refuses the hop, but the task still SUCCEEDS
            task.cancel()            // this is what makes the caller see a failure
            return
        }
        completionHandler(newRequest)
    }
}
```

**The `task.cancel()` is not optional.** Passing `nil` to the completion handler refuses
the redirect, and then the task completes normally carrying the 302's own body and no
error. The overwhelmingly common Swift shape is `if let error { handle } else { trust }`,
so a caller written that way treats a blocked SSRF attempt as a successful fetch, which is
worse than not checking at all because it looks like the guard worked.

**It does not resolve DNS, so it cannot stop rebinding.** `totally-fine.com` is allowed
here and is free to resolve to `10.0.0.5`, and it can return a different answer on the
second lookup than it gave on the first. Closing that properly means resolving, pinning
the address, checking the address rather than the name, and connecting to the pinned one.
That needs a real network stack and is out of scope for a pure evaluator. If you are
fetching genuinely hostile URLs, put an egress proxy or a firewall rule behind this, not
just this.

**It cannot detect a dotted name with a private TLD** (`host.corp`, `sub.media-server`),
because that is textually indistinguishable from a public domain without a resolver or a
public-suffix list. Put yours on the denylist. There is a test pinning this so it cannot
change quietly.

**`trustedLANHosts` ships empty.** A default naming somebody's hardware would be a hole in
your network rather than a convenience, so name your own.

### The three lists, and the one with teeth

```swift
URLGuardConfig(allowlist: [], denylist: [], trustedLANHosts: [])
```

`denylist` and `allowlist` match a host **and all of its subdomains**. `trustedLANHosts` is
exact match only. Denylist beats allowlist.

**`allowlist` overrides the private-network denial, and that is the whole point of it and
also its teeth.** It is consulted before the private-address checks, so it is how you say
"I mean it" about a host this guard would otherwise refuse. The consequence is that
allowlisting a domain allowlists every subdomain of it, **including one that spells a
private address**. Measured: with `allowlist: ["corp.example"]`, `10-0-0-1.corp.example`
goes from denied to allowed. A domain with wildcard DNS therefore hands back exactly the
SSRF surface this guard exists to remove.

That is the operator's call to make, which is why it is not disabled, but it should be a
decision rather than a discovery. There is a test pinning both directions.

What it *does* cover is the string-level evasion, which is the part people get wrong by
hand: every IP spelling in the table above, credential smuggling, and percent-decoded
hosts. That last one was found by adversarial probing before the first release rather than
after it. `URL.host` percent-decodes, so `127.0.0.1%00.example.com` arrives carrying a
literal NUL byte, parses as an ordinary multi-label name, and reads as plain loopback to
any resolver that truncates at NUL. It is denied now, on structural grounds, with a
regression test.

## Verifying this yourself

Nothing here asks to be believed. Every claim in this section is one command.

**125 tests, 0 failures**, on macOS 14 and macOS 15, which is the CI matrix. Run
`swift test`. Count them with `grep -rho 'func test' Tests/ | wc -l`. There is no coverage
percentage anywhere in this repo on purpose: a high one is easy to reach with weak tests,
and the corpus files are the honest artifact instead. What is in those corpora, how they
are built, and which direction each one is allowed to fail in is in
[docs/CORPUS.md](docs/CORPUS.md).

**Tags are signed from 0.6.0 onward, and 0.1.0 through 0.5.0 are not.** Check with
`git tag -v 0.6.2`. Expect the output to read `Good "git" signature`, with the word `git`
in quotes, which is what git prints for an SSH signature and is not a warning.

**Zero external packages.** `grep -c '.package(' Package.swift` returns 0, and there is no
`Package.resolved`, so the dependency graph this library can drag in is empty by
construction rather than by discipline.

**What CI cannot prove is stated rather than hidden.** macOS 13 is not supported, and the
reason is in the workflow comments: its hosted runner queued for 31 minutes while 14 and 15
finished in about two, and held the whole run in `queued`, so the homograph loopback
defence could never be verified there. 0.6.1 raised the floor to macOS 14 rather than keep
advertising a minimum no CI leg could ever reach.

## Roadmap

In the order they are coming out of the private codebase, each one landing with its
tests rather than as a sketch:

- **Tiered approval.** Green, yellow and red action classes. What runs silently, what
  asks first, what is never automated.
- **Cost metering.** Per-call accounting and budget ceilings, because an agent in a
  retry loop is a billing incident.
- **Swarm orchestration.** Fan-out to parallel workers with structured results.
- **Voice hallucination guard.** Near-silent audio makes Whisper emit confident garbage,
  often a loop of its own vocabulary hints. The hard constraint is the false-positive
  side: it must never reject ordinary dictated speech.

## Contributing

Issues and pull requests welcome. Two asks. Ship a test with behaviour changes, since
every module here is table-driven for that reason. And no em dashes or en dashes in code,
comments or docs, which is a house style the linter enforces. The longer version is in
[CONTRIBUTING.md](CONTRIBUTING.md).

Found a bypass? That is the report worth sending, and it does not belong in a public
issue. Use GitHub's private vulnerability reporting on this repository, and see
[SECURITY.md](SECURITY.md) for what is in scope and what is already documented as a limit.

## Licence

MIT. See [LICENSE](LICENSE).

<!-- THREE SWIFT PACKAGE INDEX BADGES WERE REMOVED HERE, AND THEY GO BACK IN LATER.
     Do not re-add them until swiftpackageindex.com has actually indexed this package.
     SPI clones and BUILDS a package to produce those badges, so it only ever sees a
     public repository. While this one was private the two dynamic badges rendered the
     literal word "pending" in grey (measured, not assumed: the shields endpoint was
     fetched and its SVG text read), and the Documentation badge rendered fine but
     linked to a page SPI had never built.

     That is three of five badges in the first hundred pixels either admitting they know
     nothing or pointing at nothing, on a README whose whole argument is that every claim
     on it is either proven or an admitted failure. A grey "pending" is the only thing on
     the page that reads as unfinished rather than honest, which is a strange note to open
     a launch on.

     PUT THEM BACK once SPI lists the package, which needs the repo public first:

     [![Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fdotcomjack%2Fgrux%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/dotcomjack/grux)
     [![Swift](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fdotcomjack%2Fgrux%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/dotcomjack/grux)
     [![Documentation](https://img.shields.io/badge/documentation-gray?logo=swift&logoColor=white)](https://swiftpackageindex.com/dotcomjack/grux/documentation)

     Check first, and check the rendered SVG rather than the HTTP status, because a
     pending badge is a perfectly healthy 200:
       curl -sSL "https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fdotcomjack%2Fgrux%2Fbadge%3Ftype%3Dplatforms" | grep -o '>[^<>]*</text>'
     It is ready when that prints macOS instead of pending.

     .spi.yml stays regardless. It is the submission manifest and costs nothing while
     unlisted. -->
