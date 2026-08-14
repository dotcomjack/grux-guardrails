# Threat model

What Grux defends, what it deliberately does not, and where the line sits.

Written for 0.6.1. Every claim below is either a line of source you can open or a test
symbol you can run. Where a defence has a hole, the hole is named here rather than left
for a reader to find.

## The system in one paragraph

Grux is five public functions and nothing else. Two of them do the work:
`SecretRedactor.redact` takes a string and returns a string, and `URLGuard.evaluate` takes
a string and returns a decision. The other three are named here so a reviewer knows the
surface is five and not two: the two `wrapAsUntrusted` overloads, which fence untrusted
text, and `newFenceID`, which mints the identifier those overloads use. None of the five
opens a socket, reads a file, spawns a process, or keeps state between calls. The only
`import` in either source file is `Foundation`, and the package declares zero
dependencies. That is what makes the whole policy table-testable, and it is also the
source of every limit in this document.

## The asset

Two things, and they are not the same kind of thing.

1. **Credentials that pass in front of an agent.** An agent that can read your screen, your
   files and your tool output will eventually read a secret. The moment that text is
   interpolated into a prompt it leaves the machine, lands in a provider's logs, and is
   outside your control forever. There is no revoking a prompt.
2. **Reachability of your private network.** The agent runs on your laptop, inside your
   network, holding whatever tools you gave it. `http://169.254.169.254/` is cloud
   metadata. `http://router/` is your router's admin page. Neither looks alarming in a
   prompt, and the model has no idea which addresses are yours.

## The adversary

**Text.** That is the entire adversary model, and it is worth stating plainly because it
sets the boundary for everything below.

The attacker controls bytes the agent reads: a web page it fetched, an email in view, a
README in a cloned repository, a filename, a code comment, OCR of whatever is on screen,
an ambient microphone transcript. The attacker does not control the process, the operator's
own instructions, or the host.

**Explicitly NOT in the model: a compromised host.** If the attacker is executing code on
the same machine, they read the secret from memory or from the file it came from, and a
redactor in the middle is irrelevant. Nothing in this library is a defence against local
code execution and nothing here should be cited as one.

## Trust boundaries

Two boundaries, one per control. Each is a point where data of one trust level becomes
data of another, and the whole library is the enforcement sitting on those two lines.

| # | Boundary | What crosses | Untrusted side | Trusted side | Enforced by |
|---|---|---|---|---|---|
| 1 | Read to prompt | Screen text, file contents, tool output, fetched pages, transcripts | Anything the agent read | The prompt the model receives | `SecretRedactor.redact`, then `SecretRedactor.wrapAsUntrusted` |
| 2 | Model to network | A URL the model chose, composed, or copied out of untrusted text | The URL string | The socket your HTTP client opens | `URLGuard.evaluate` |

**Boundary 1 is one way and it is final.** Text that crosses it cannot be recalled. That is
why the redactor runs before the prompt is assembled rather than as a filter on the way
out.

**Boundary 2 is enforced on a string, not on a connection.** `evaluate` returns a verdict
about one URL at one moment. The caller is what turns that verdict into a refusal, and the
caller owns every hop after the first. This is the single most misread thing about the
library and it is limit 1 below.

### The third trust boundary, capability, which Grux does not sit on

Which tools the agent holds, what those tools may touch, and whether a dangerous action
needs a human. A redactor plus a URL guard cannot make an over-privileged agent safe.
Withholding a capability the agent never needed beats filtering the input that would have
abused it. This boundary is named here because leaving it out is how a reader concludes
that two string functions are a complete agent security story.

## What Grux defends

Every row is pinned by the named test. Run `swift test --filter <symbol>` to see it.

**`URLGuard`, string level evasion, which is the part people get wrong by hand.**

| Defence | Test symbol |
|---|---|
| Non-canonical IPv4 spellings (`0177.0.0.1`, `0x7f.0.0.1`, `127.1`, `2130706433`) | `testNonCanonicalIPv4SpellingsAreDenied` |
| IPv4 wearing an IPv6 costume (mapped, compatible, 6to4, NAT64, RFC 2765 translated) | `testIPv4MappedIPv6CannotReachPrivateTargets`, `testUnusualIPv6SpellingsOfAnEmbeddedIPv4AreDenied` |
| NAT64 local use, every RFC 6052 prefix slot rather than only `/96` | `testNAT64LocalUsePrefixDecodesEveryRFC6052Slot` |
| Percent-decoded host smuggling (`127.0.0.1%00.example.com`) | `testPercentDecodedHostCannotSmuggleALoopbackTarget` |
| Trailing dot and repeated trailing dot denylist bypass | `testTrailingDotCannotBypassDenylist`, `testRepeatedTrailingDotsCannotBypassTheDenylist` |
| Denylist entries written as people actually write them (pasted URL, host:port, wildcard) | `testDenylistEntriesSurviveTheWayPeopleActuallyWriteThem` |
| Cloud and container metadata by NAME, not only by address | `testCloudAndContainerMetadataHostnamesAreDenied` |
| A private address spelled into hostname labels (`10.0.0.1.nip.io`, `10-0-0-1.example`) | `testHostnamesEmbeddingAPrivateAddressAreDenied` |
| Wildcard DNS loopback aliases (`lvh.me`, `localtest.me`) | `testLoopbackAliasDomainsAreDenied` |
| The IANA IPv6 special purpose registry, including three anycast addresses that read as global unicast | `testIANASpecialPurposeIPv6RegistryRowsAreDenied` |
| Homograph and unicode spellings of loopback | `testEveryUnicodeSpellingOfALoopbackHostIsDenied` |
| Credential bearing URLs, with no allowlist override | `testAllowlistNeverOverridesCredentialCheck` |
| An attacker choosing their own audit label | `testAttackerChosenSchemeCannotSteerTheAuditTag` |

**`SecretRedactor`, credential shapes and the injection fence.**

| Defence | Test symbol |
|---|---|
| The whole PEM block, body included, indented or JSON escaped | `testPEMBodyIsRedactedNotJustTheHeader`, `testPEMInsideJSONLosesItsBody` |
| Provider prefixes, most specific tag wins | `testProviderKeysGetTheirOwnTag`, `testMostSpecificPatternWins` |
| Providers the generic entropy pass structurally cannot see | `testProvidersTheGenericPassCannotSee` |
| Labelled values across env, shell, YAML, JSON, query strings and headers | `testAssignedSecretsAreRedactedAcrossFormats` |
| Credentials inside URLs and behind `curl -u` | `testSpecificTagSurvivesInsideURLAndFlagCredentials` |
| A fenced body forging its own closer, in any case | `testUntrustedBodyCannotCloseItsOwnFence`, `testFenceNeutralisationIsCaseInsensitive` |
| A fenced body opening a nested block with an attacker chosen kind | `testUntrustedBodyCannotOpenItsOwnFence` |
| Fence ids unguessable and varying per call | `testFenceIDsAreUnguessableAndVary` |
| Idempotence, so re-redacted fragments keep their precise tags | `testRedactIsIdempotent` |
| The whole leak corpus, zero survivors, and the benign corpus, zero mangles | `testLeakCorpusHasZeroSurvivors`, `testBenignCorpusHasZeroMangles` |
| Superlinear blowup on attacker chosen input | `testNoInputShapeIsSuperlinear`, `testOneNonASCIICharacterDoesNotMakeRedactionQuadratic` |

## The three limits that decide whether this library fits

These are not caveats bolted on at the end. They follow directly from "pure functions that
perform no I/O", and each one is verifiable in the source.

### Limit 1. `URLGuard` does not follow redirects

`evaluate` judges one string and returns. It performs no request, so it never sees a
response, so it cannot see a `Location` header. A URL that is public in every respect is
free to answer `302 Location: http://127.0.0.1:8080/`, and nothing in this library will
know.

**Every hop after the first is the caller's job.** README.md carries the `URLSessionTaskDelegate`
shape that does it, and the important half of that example is `task.cancel()`: passing
`nil` to the completion handler refuses the redirect and then lets the task complete
normally with the redirect's own body and no error. A caller written as
`if let error { handle } else { trust }` reads a blocked SSRF attempt as a successful
fetch, which is worse than never checking, because it looks like the guard worked.

**Verify it:** the only `import` in `Sources/Grux/Security/URLGuard.swift` is `Foundation`,
and the file contains no `URLSession`, no `dataTask`, and no redirect delegate.

```
grep -rnE 'URLSession|dataTask|willPerformHTTPRedirection' Sources/Grux/Security/URLGuard.swift
```

### Limit 2. `URLGuard` does not resolve DNS, so it cannot stop rebinding

There is no resolver call anywhere in the guard. `inet_pton` at `URLGuard.swift:484` is a
presentation to bytes parse of a literal that is already an address; it does not consult
DNS, a hosts file, or the network.

The consequence is DNS rebinding, and it is not a subtle one. `totally-fine.com` is allowed
by this guard and is free to resolve to `10.0.0.5`. It is also free to answer differently
on the second lookup than it did on the first, so even a caller who resolves and checks
before connecting has a window between the check and the connection.

Closing this properly means resolving, checking the resolved address rather than the name,
pinning it, and connecting to the pinned address. That needs a real network stack and is
out of scope for a pure evaluator. **If you are fetching genuinely hostile URLs, put an
egress proxy or a firewall rule behind this, not just this.**

The same absence produces a smaller limit worth knowing: a dotted name with a private TLD
(`host.corp`, `sub.media-server`) is textually indistinguishable from a public domain
without a resolver or a public suffix list, so it is allowed. Put yours on the denylist.

**Verify it:**

```
grep -rnE 'getaddrinfo|gethostbyname|CFHost|DNSService|res_query' Sources/
```

The only hit is inside a comment at `URLGuard.swift:468`, which records how a claim about
`inet_aton` was measured. There is no resolver call in the shipped path.

### Limit 3. `SecretRedactor` is a matcher, not a parser

It recognises shapes. A credential in a format no pattern covers passes through by
construction, and no amount of tuning changes that, because the thing it would have to do
instead is understand the document.

**Single case hex is deliberately exempt, and this is the sharpest edge of that limit.**
The generic entropy rule ends at `SecretRedactor.swift:869`:

```swift
return upper && lower && digit && runLength >= 32
```

A lowercase hex run has `lower` and `digit` but never `upper`, so it is never redacted by
that rule. That is a decision, not an oversight: it is what keeps git SHAs, md5 and sha256
checksums, and content hashes intact in text the model needs to reason about. The price is
that a 32 or 64 character lowercase hex secret goes through untouched.

**Be precise about how wide that hole is, because the short version overstates it.** The
exemption applies to a **bare** run with no label in front of it. A labelled one is caught
by a different pass: `looksLikeACredentialValue` at `SecretRedactor.swift:473` accepts on
`hasDigit || (hasUpper && hasLower)`, and lowercase hex satisfies `hasDigit`. So
`0123456789abcdef0123456789abcdef01234567` survives, and
`DD_APP_KEY=0123456789abcdef0123456789abcdef01234567` does not.

Both halves of that are pinned by one test, which asserts the survival and the catch
side by side so neither can drift alone:

```
swift test --filter testSingleCaseHexAndUUIDsAreSparedBareAndCaughtWhenLabelled
```

Two further known defects sit in the same class and are disclosed rather than fixed: a
labelled credential inside a JSON array or YAML sequence survives, and one inside an XML or
plist element body survives. Both are pinned by `testKnownDefect*` expectations that turn
the suite red the moment somebody fixes them, so the disclosure cannot outlive the defect.
`docs/CORPUS.md` lists all three with their controls.

## Out of scope

Named so that a reader knows where to stop expecting help, and so that a reporter knows
what will be closed as working as intended. Reports about anything here are still welcome
if you think the documentation oversells the defence, which is the failure mode this list
exists to prevent.

| Out of scope | Why, and what actually covers it |
|---|---|
| Redirect chains | No I/O by design. Re-evaluate every hop in your client. Limit 1 above. |
| DNS rebinding, and time of check to time of use on an address | No resolver by design. Needs address pinning at connect time, or an egress proxy. Limit 2. |
| A credential in a format no pattern matches | A matcher cannot recognise an unknown shape. Limit 3. Report the shape and it becomes a pattern. |
| A compromised local host | If the attacker runs code on the machine they read the secret at its source. |
| Prompt injection as a solved problem | `wrapAsUntrusted` marks a boundary the model can act on. It is not a guarantee, and it is not a substitute for withholding tools. |
| Model behaviour after a correct fence | Whether the model honours the boundary is the model's property, not this library's. |
| Egress filtering, network policy, firewalling | A string evaluator cannot enforce what a socket does. |
| Secrets at rest, key management, rotation | Out of the data path entirely. |
| Transport security, certificates, pinning | Your HTTP client's job. |
| `allowlist` overriding the private network denial | Working as intended and load bearing. It is how you say "I mean it" about one host. Note that it allowlists every subdomain, including one that spells a private address, so a domain with wildcard DNS hands back the surface this guard removes. |
| Destroying some ordinary text | A real cost, measured and published, not a bug: 20 of 30 ordinary config lines whose field NAME merely contains a credential word are destroyed. A redactor people switch off protects nothing, so this IS in scope as a report even though it is not a vulnerability. |

## Checks this project cannot earn, and why

Stating these is stronger than a silently missing score, because each one is falsifiable.

**`Signed-Releases` is unearnable here, and that is a property of the ecosystem rather than
of this project.** The OpenSSF Scorecard `Signed-Releases` check looks for signed release
ARTIFACTS attached to a release, which is how npm, PyPI and Maven publish. Swift Package
Manager does not resolve artifacts at all: it resolves a git URL at a git tag and builds
from source, so there is no uploaded artifact to sign and no signature for the check to
find. Attaching a tarball purely to satisfy the check would create a second artifact that
nobody consumes, which is worse than the missing score because it invites someone to
consume it.

What actually protects a Swift consumer is tag immutability plus the resolver's fingerprint
store, and that one is measurable: SwiftPM records the revision a version resolved to under
`~/Library/org.swift.swiftpm/security/fingerprints/`, and moving a published tag makes every
later resolve fail with `Revision ... does not match previously recorded value`. It survives
purging the package caches and a brand new project. **Tags in this repository are therefore
immutable once published.** A defect gets a new tag, never a moved one.

Related and honest: **there is no fuzz target and fuzzing is not performed.** The adversarial
corpus in `docs/CORPUS.md` is what stands in for it, and the difference is stated there
rather than papered over.

## Residual risk, stated as a caller would meet it

- A public host that redirects to loopback. **Yours to close**, in the redirect delegate.
- A public name that resolves to a private address. **Yours to close**, with address level
  checking or an egress control.
- A secret shape nobody has written a pattern for. **Report it.** That is the fastest path
  to it becoming a pattern and a test.
- A bare, unlabelled, single case hex secret. **Known and documented above.** Label it, or
  keep it out of the agent's reach.
- An over-privileged agent. **Not this library's problem to solve**, and the most important
  one on the list.

## Reporting

Found something that gets past either control? `SECURITY.md` has the channels. Email
**security@gruxai.com** with `Grux security` in the subject. A failing test case is the
fastest possible path to a fix.

If you think one of the documented limits above is worse than this page implies, that is
still worth reporting. The line between a documented limit and a false sense of security is
exactly the thing this document is trying to get right.
