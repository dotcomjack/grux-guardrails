# Disclosure, August 2026: six published tags leak credentials

**2026-08-14.** Six tags of this library, `0.1.0` through `0.4.0`, contain defects in the two
controls the library exists to provide. Each one was found by an audit of code that had
already survived earlier audits. All six are fixed in `0.5.0`. **Use `0.6.1`.**

The tags are not being deleted, rewritten, or force pushed. They stay exactly where they
are, and this page plus six GitHub Security Advisories are the disclosure.

## Affected versions

| Version | Status | Exposure window | Worst defect | Severity |
|---|---|---|---|---|
| `0.1.0` | **Affected** | 2026-08-08 03:06 to 12:58 ET | Private key bodies passed to the model, and a forgeable injection fence | Critical, CVSS 9.3 |
| `0.2.0` | **Affected** | 2026-08-08 12:58 to 13:26 ET | AWS secret access key leaked in full, plus a quadratic pass on attacker chosen input | High, CVSS 8.6 |
| `0.2.1` | **Affected** | 2026-08-08 13:26 to 14:00 ET | AWS secret access key leaked, PEM tail leaked, guessable fence identifiers | High, CVSS 8.6 |
| `0.3.0` | **Affected** | 2026-08-08 14:00 to 14:05 ET | Path heuristic discarded 14% of AWS secret access keys; NAT64 route to loopback | High, CVSS 8.6 |
| `0.3.1` | **Affected** | 2026-08-08 14:05 to 19:21 ET | Every labelled secret shorter than 40 characters sent in plaintext, behind a test that pinned the leak as correct | High, CVSS 8.6 |
| `0.4.0` | **Affected** | 2026-08-08 19:21 to 2026-08-10 13:39 ET | Denylist fails open unless entries are bare hosts, plus loopback and NAT64 SSRF bypasses and six credential leak classes | Critical, CVSS 9.3 |
| `0.5.0` | Not affected | first clean tag, 2026-08-10 | none known | |
| `0.6.0` | Not affected | 2026-08-13 | `0.5.0` with the module renamed, nothing else | |
| `0.6.1` | **Use this one** | current | none known | |

The exposure window is the interval during which each tag was the newest available. A
consumer pinned to an affected tag is exposed until they move, regardless of that window.

**Known real-world exposure is zero, and that is measured rather than hoped.** This
repository has been private for the entire life of every tag above: created
2026-08-08, `"visibility": "private"`, **0 forks and 0 stars** as of 2026-08-14. No stranger
could resolve any of these tags, so there is no known affected consumer. This page is
published anyway, because the repository is going public and the moment it does, all six
become fetchable for the first time. A disclosure that waits for a victim is not a
disclosure.

## What you should do

**If you have never used this library, nothing. Start at `0.6.1`.**

If you have a `Package.swift` or a `Package.resolved` naming this package, check which tag
you resolved and move:

```
swift package show-dependencies | grep -i grux
grep -A3 -i grux Package.resolved
```

Then pin forward:

```swift
.package(url: "https://github.com/dotcomjack/grux.git", from: "0.6.1")
```

**The module was renamed, so this is not a drop-in bump from `0.5.0` or earlier.** It is
`GruxKit` up to and including `0.5.0`, and `Grux` from `0.6.0` onward. Change your import:

```swift
import Grux      // was: import GruxKit
```

`from: "0.6.1"` means the range `[0.6.1, 1.0.0)`, so it can only ever resolve to a tag that
has the `Grux` product. What breaks is a constraint that actually holds you at or below
`0.5.0`: `.exact("0.5.0")`, an `upToNextMinor` range, or a `from: "0.5.0"` written before
`0.6.0` existed. In any of those, `import Grux` fails with `product 'Grux' not found`.

**Then rotate anything the agent saw.** Moving the library forward does not un-send a
credential that already reached a model provider. If you ran an affected tag against real
input, treat every secret in that input as disclosed: rotate the key, do not merely stop
leaking it. That is the correct first step in any credential exposure and it is the only
one that actually helps.

**Specifically worth checking, by tag:**

- Any tag before `0.5.0`: private keys, if you passed PEM blocks through `redact`.
- `0.2.0`, `0.2.1`, `0.3.0`: AWS secret access keys.
- `0.3.1`: every `NAME=value` credential shorter than 40 characters, which is most of them.
- `0.4.0`: session cookies, `Bearer` tokens printed by `curl -v`, `PGPASSWORD`, and any
  denylist you believed was blocking a host.

**If you used `URLGuard` with a denylist on `0.4.0`, re-read the entries.** Anything not
written as a bare host matched nothing at all. See the root cause below.

## The single most transferable lesson

**On `0.4.0`, a denylist entry written as anything other than a bare host matched nothing.**
Against `denylist: ["evil.com"]`, all three of these were silently inert:

```
https://evil.com      a pasted URL, the single most likely thing a human writes
evil.com:443          a host and port copied out of a log line
*.evil.com            the natural spelling of a wildcard, which every other tool accepts
```

Each one looks completely correct in a config file. None of them blocked anything.

**A denylist fails OPEN when it fails to match.** That is the whole lesson and it
generalises far past this library: an allowlist that fails to match is loud, because
something legitimate stops working and somebody files a bug within the hour. A denylist that
fails to match is silent, because the only symptom is that an attack succeeds. Every entry
now goes through the same canonicaliser the host does, which strips a scheme, a userinfo, a
port, a path, a leading star and any number of trailing dots, and it is pinned by
`testDenylistEntriesSurviveTheWayPeopleActuallyWriteThem`.

The same tag had the mirror image of this bug: `evaluate` stripped one trailing dot while
the entry canonicaliser stripped all of them, so `http://evil.com../` walked past. That was
introduced by fixing the single trailing dot case on only one side of the comparison. Fixing
half of a symmetry is how the fix becomes the next bug.

## Root cause

There is not one root cause, there are three, and they are worth separating because only one
of them is about this library.

**1. A matcher was tuned on the cases somebody thought of.** Every credential leak in the
list above is the same shape: a spelling nobody wrote a case for. `access_token` was covered
and `accessToken`, `clientSecret`, `PGPASSWORD` and `_auth` were not, because the pattern
required the keyword to start the name or follow a separator. The suite was green throughout.
The fix was not a better regex, it was replacing the acceptance criterion: two published
corpora, one that must have zero survivors and one that must have zero mangles, held in the
same file so the trade cannot drift in one direction unnoticed. See `docs/CORPUS.md`.

**2. Two fixes each opened the next leak.** This is the pattern most worth naming.

- `0.3.0` removed `/` from the entropy character class to stop file paths being mangled. That
  blinded the redactor to standard base64, whose alphabet contains `/`, and the AWS secret
  access key leaked completely. Paths are now excluded structurally instead.
- `0.3.1` kept `=` out of the token run to stop `Authorization=Bearer_...` being swallowed
  whole. The label had been supplying the length, so every `NAME=value` secret under 40
  characters went out in plaintext. **A fix for a cosmetic complaint silently un-redacted a
  whole class of real credentials.**

Both were traded the wrong way: a cosmetic annoyance was allowed to buy a real leak. The
rule now is explicit, in the source, at the line where the trade is made: annoyance loses to
disclosure, every time.

**3. `0.3.1` shipped a test that pinned the leak as correct.** That is the worst item on
this page, and it is worse than any single leak, because the suite was green while asserting
the wrong thing. Known defects are now written as the assertion that SHOULD hold, wrapped in
`XCTExpectFailure`, one expectation per case rather than one around a table. Fixing a defect
turns the expectation into an unexpected pass and the suite goes red, which forces the fixer
to come and delete the disclosure deliberately. A partial fix cannot hide, because a single
recorded failure no longer satisfies a whole table.

## Why the bad tags are not being deleted

Deleting them buys nothing and costs the trust argument.

GitHub's own guidance on removing sensitive data is that rewritten history remains reachable
in any clone or fork, directly by SHA in cached views on GitHub, and through any pull request
that references it. So deletion does not remove the code from an attacker who already has it.
What it does remove is reproducibility for anyone pinned to a tag, and the evidence trail
that makes this page checkable.

There is a second reason specific to Swift. SwiftPM records the revision each version
resolved to in a fingerprint store, and a moved tag makes every later resolve fail with
`Revision ... does not match previously recorded value`. That is a supply chain defence
against an author silently repointing a published version, and it works: it survives purging
the package caches and starting a brand new project. **Tags here are immutable once
published.** A defect gets a new tag, never a moved one.

## Advisories

Six GitHub Security Advisories, one per affected tag, are drafted and are published when this
repository goes public. Publishing them puts the affected ranges into the GitHub Advisory
Database, which is what reaches a consumer who already resolved an old tag; prose on a page
reaches nobody who is not reading the page.

Each advisory carries a CVSS v3.1 vector with a stated method, and the CWEs that actually
match rather than a generic one. `AV:N` because a redaction failure discloses to a remote
third party. `S:C` because the leaked credential authorises a different security authority
than this library: an AWS account, a Postgres server, a GitHub org.

The patched version is `0.5.0` on all six, deliberately. Several defects were fixed in the
very next tag, but every intermediate tag carries a leak of its own, so `0.5.0` is the first
version a consumer can move to and be clear of all of them. **An advisory whose patched
version points at another vulnerable release is worse than no advisory.**

Staging status and the exact publish commands: `docs/ADVISORIES-STAGED.md`.

## Reporting

If you find something that gets past either control, `SECURITY.md` has the channels. Email
**security@gruxai.com** with `Grux security` in the subject. A failing test case is the
fastest possible path to a fix.

The current limits, including the three that are documented rather than fixed, are in
`docs/THREAT-MODEL.md`. If you think one of them is worse than that page implies, that is
worth reporting too.
