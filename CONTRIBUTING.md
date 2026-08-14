# Contributing to Grux

Grux is a security control. A bug here does not make a feature worse, it hands a
credential to a model or lets an agent dial an address it was supposed to refuse. So the
bar is not "does this look right". The bar is "can you show me the failure this prevents".

Everything below is a convention this repo already follows, not a wish list. If a rule
here looks strict, the CHANGELOG usually names the release where the loose version of it
shipped a leak.

## Before you open anything

**Found a bypass? Do not open an issue.** A secret that survives `SecretRedactor.redact`,
or a URL that `URLGuard.evaluate` allows and that reaches a private address, cloud
metadata or loopback, goes to a private channel first. Read [SECURITY.md](SECURITY.md).
There are two channels and either is fine: GitHub's private vulnerability reporting on
this repository, or email to `security@gruxai.com` with `Grux security` in the subject.
The email one always works, so use it whenever the button is not there.

**Check whether it is already known and documented.** Three things are known defects with
tests already pinning them, and a fourth is a matcher limitation by construction:

- A labelled credential inside a JSON array or a YAML sequence survives, because a
  bracket breaks the name-to-value adjacency the rules read.
- An XML or plist element **body** survives, though the attribute form is caught.
- Quoted prose under a credential-ish name is destroyed. 20 of 30 measured real-world
  config lines of that shape did not survive.
- `SecretRedactor` is a matcher, so a credential in a format no pattern covers passes
  through. That is a pattern request, not a vulnerability.

The first three live in `Tests/GruxTests/AdversarialRound2Tests.swift` as
`testKnownDefect*` tests. Read those before reporting one of them again, and read
[CHANGELOG.md](CHANGELOG.md) before reporting anything: it is written as a narrative and
it records the wrong first attempts as well as the fixes.

`URLGuard` does not follow redirects and does not resolve DNS. Redirect chains and DNS
rebinding are outside what it can see, by design, and both are described in the README.

## Build and test

```
swift build
swift test
```

Requires macOS 14 and Swift 5.9 tools or newer. There are zero third-party dependencies,
and `Package.resolved` is gitignored because there is nothing to resolve.

`swift build` succeeds on Linux. **`swift test` does not currently compile on Linux**, and
this is a known limitation rather than a mystery: three sites in
`AdversarialRound2Tests.swift` call `XCTExpectFailure`, which ships with Apple's XCTest and
not with swift-corelibs-xctest. If you work on Linux, build the library there and run the
suite on macOS.

CI runs `macos-14` and `macos-15`. `macos-13` is deliberately absent from the matrix: it
was added, it never scheduled (31 minutes queued while the other two finished in about 2),
and it held both runs so CI could never reach a conclusion at all. A leg that can never
report is not coverage, it just looks like coverage on the checks page.

## The bar for anything touching Sources/

### 1. Ship a test

Not "I tested it manually". A test in `Tests/GruxTests/`, in the file that owns the
family your change belongs to.

### 2. Prove the test fails first

This is the rule that matters most, and it is the one a reviewer will actually check. A
test that has never been red proves nothing at all. Park your fix, run the test, watch it
fail, then put the fix back:

```
git stash push Sources/
swift test --filter testYourNewCase    # must be RED
git stash pop
swift test --filter testYourNewCase    # must be GREEN
```

Paste the red output into the pull request. The failure message has to name the real
input, because a red run that says `XCTAssertTrue failed` is not evidence of anything.

The reason this is a hard rule: **0.3.1 shipped a leak that sat behind a test asserting
the leak was correct, with the suite green the whole time.** The CHANGELOG calls that the
worst kind of failure there is. A green suite is worth exactly as much as the last time
somebody made it go red on purpose.

### 3. Write it as a table

Every module here is table-driven, and that is deliberate: a table is what makes the next
person's addition cheap. One `let cases: [(note, input, expected)]` and a loop beats six
near-identical `func test` bodies. Organise by attack family, not by assertion, so a
coverage gap is visible in the source rather than only in a report.

### 4. If you touch the redactor, extend the corpus

`Tests/GruxTests/Corpus.swift` is the acceptance gate and it replaces "65 tests green":

- `Corpus.leaks` (50 cases) must reach **zero survivors**. A survivor means a credential
  reached the model. Hard failure.
- `Corpus.benign` (64 lines) must reach **zero mangles**. A mangle means ordinary text was
  destroyed, which is how a redactor gets switched off, and a switched-off redactor
  protects nothing.

Both corpora are adversarial about **spelling** rather than about exotic formats, because
spelling is where every real leak has come from: camelCase, glued words, abbreviations, an
intervening scheme word, a different delimiter. `POSTGRES_PASSWORD=` was covered, so
`DB_PASS=` on the next line looked covered too. It was not, and nothing in the suite could
tell.

A change that fixes a leak and adds only a hand-picked fixture is not finished. Add the
adversarial spellings around it.

### 5. Never pin a leak with an equality assertion

Writing `XCTAssertEqual(out, input)` around a known defect repeats the 0.3.1 mistake
exactly: it encodes the bug as the specification, and the suite goes green forever.

A documented defect is written as the assertion that **should** hold, wrapped in
`XCTExpectFailure`, with a message that starts `KNOWN DEFECT:` and names both the fix and
the fact that the expectation must be deleted when it lands. The suite stays green, the
defect is stated in the assertion instead of buried in a comment, and the moment somebody
fixes it the expectation goes unmet and the suite goes red, which forces the fixer to come
here and delete it deliberately.

**One expectation per case, never one wrapped around the loop.** With a single expectation
around the table, one recorded failure satisfies it, so a partial fix leaves the suite
green and ships believed complete.

If your change makes an existing `testKnownDefect*` pass, delete that expectation in the
same commit, and say so in the pull request. Do not leave it behind "just in case".

### 6. Publish the number, do not tune it

Where correctness is statistical, the measured value gets printed and the guard is set
just above it, so a real regression trips while sampling noise does not. The bare
40-character credential leak rate is measured at roughly 1.3% over 20,000 trials and
`testBareCredentialLeakRateIsPublished` asserts under 2.0%. Moving a threshold to make a
run pass is a change to the claim the library makes, so it needs its own line in the
CHANGELOG and its own justification. Silently widening a bound is the one review comment
that will not be negotiated.

### 7. Watch the clock

`testNoInputShapeIsSuperlinear` exists because 0.4.0 shipped a cubic pattern where 8KB of
ordinary CSS-class-shaped text took 40 seconds. A redactor an agent can be made to hang on
is a denial of service in the agent, so a new pattern gets a shape added to that test.

### 8. Docs are mechanically pinned, so update them in the same commit

`testEveryTagTheCodeCanEmitIsDocumentedInTheReadme` reads README.md and fails the build if
`URLGuardDecision.tag` can emit a tag the table there does not name, and it also fails if
the table names a tag no input can reach. A denial reason landing outside the tags people
alert on is a defect that has already happened twice. If you add a tag, edit the README
table in the same change or CI will stop you.

## House style

- **No em dashes and no en dashes.** Anywhere: Swift, Markdown, YAML, comments, commit
  messages. Use a comma, a colon, a full stop, parentheses or a pipe. The `house-style`
  CI job greps `*.swift`, `*.md` and `*.yml` recursively and fails the build on a hit.
- **Every credential in this repository is synthetic.** Never paste a real key, not even
  a revoked one, not even your own, not even to demonstrate a bug. Use the shapes already
  in `Corpus.swift`.
- **Zero dependencies is a feature, not an accident.** A pull request that adds one is a
  conversation to have in an issue first, not something to discover in review.
- **Comments say what was wrong, not what the code does.** The useful comment in this
  repo is the one recording the measurement, the wrong first attempt, or the reason a
  cheaper approach was rejected. `// loop over the cases` is noise; `// inet_aton reads a
  bare 0x as zero, confirmed with getaddrinfo(AI_NUMERICHOST)` is why the next person does
  not reintroduce the bug.
- **The public surface is small on purpose.** `SecretRedactor.redact`,
  `SecretRedactor.wrapAsUntrusted`, `SecretRedactor.newFenceID`, `URLGuard.evaluate`,
  `URLGuardConfig` and `URLGuardDecision`. Adding a public symbol is an API commitment on
  a pre-1.0 package, so justify it.

## Commit messages

Lowercase type prefix, then a sentence that states the **finding**, not the action. From
the actual log:

```
ci: drop macos-13, because a leg that never schedules is not coverage
docs: the false positive rate was disclosed as an excuse, not as a limitation
test(security): round 2 finds a real leak, and JSON arrays are where it lives
```

`fix: update redactor` tells a reader nothing. `fix(redactor): the empty leading segment
fired on any token starting with a slash` tells them everything.

## What gets rejected

- A behaviour change to `Sources/` with no test.
- A test that has not been shown to fail without the fix.
- A "fix" that widens a published threshold instead of changing behaviour.
- A leak pinned as correct with an equality assertion.
- A real credential in a fixture, a comment, or a commit message.
- A new dependency arriving as a surprise inside a feature PR.
- A pattern added with no benign counter-case, since every pattern that catches more also
  destroys more.
- Reformatting passes bundled with behaviour changes. Send those separately or not at all.

## The six leaking tags stay

Tags 0.1.0 through 0.4.0 all leak credentials, they are documented as leaking, and they
are not going to be deleted or rewritten. Deleting them buys nothing against an attacker
(clones, forks and cached commit views survive it), it breaks anyone pinned to an old tag,
and it destroys the disclosure record that is the reason to trust the current one. Please
do not open a pull request that rewrites tag history.

To be exact about what leaked, because the phrasing invites the wrong reading: the
**library** failed to redact **its users'** secrets. No credential belonging to the
maintainer has ever been committed to this repository, and every credential-shaped string
in `Tests/` is synthetic.

## There is no Sponsor button, deliberately

SECURITY.md says there is no bounty and that this is a solo project given away under MIT.
A funding button sitting next to that sentence would contradict it, so `.github/FUNDING.yml`
is intentionally absent. This is a recorded decision, not an oversight, and it does not
need re-proposing.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Enforcement
reports go to `jack@dotcomjack.com`.

## Licence

Contributions are accepted under the MIT licence in [LICENSE](LICENSE).
