<!--
Read CONTRIBUTING.md first. The short version: a behaviour change to Sources/ needs a
test, and that test needs to have been RED before your fix. Delete the sections that do
not apply, but do not delete the boxes that do.
-->

## What was wrong

<!--
State the finding, not the action. "the empty leading segment fired on any token starting
with a slash" tells a reviewer everything; "update redactor" tells them nothing. Same
convention as the commit log.
-->

## What this changes

<!-- Behaviour, not files. If it changes a published number or a documented limit, say so here. -->

## Kind of change

- [ ] Behaviour change in `Sources/` (the whole checklist below applies)
- [ ] Tests only
- [ ] Documentation only
- [ ] CI or repository metadata

---

## If this touches Sources/

### The test was red first

This is the one thing a review will not skip. A test that has never failed proves
nothing, and this library shipped a leak at 0.3.1 that sat behind a test asserting the
leak was correct, with the suite green throughout.

```
git stash push Sources/
swift test --filter testYourNewCase    # RED
git stash pop
swift test --filter testYourNewCase    # GREEN
```

- [ ] I ran the above and the red run genuinely failed for the right reason.

**Paste the red output here, including the failure message:**

```

```

### Checklist

- [ ] The new test is a **table**, not a stack of near-identical `func test` bodies.
- [ ] If this touches `SecretRedactor`, I added the adversarial **spellings** around the
      case, not just the one that was reported. camelCase, glued, abbreviated, a scheme
      word in between, a different delimiter. That is where every real leak here has come
      from.
- [ ] If this adds or changes a pattern, `Corpus.leaks` gained the positive cases **and**
      `Corpus.benign` gained the counter-cases. Every pattern that catches more also
      destroys more.
- [ ] `swift test` is green locally on macOS 14 or later, with `Corpus.leaks` at zero
      survivors and `Corpus.benign` at zero mangles.
- [ ] I did not pin a leak as correct with `XCTAssertEqual(out, input)`. A known defect is
      written as the assertion that should hold, wrapped in `XCTExpectFailure`, one
      expectation **per case** rather than one around the loop.
- [ ] I did not move a published threshold to make a run pass. If I did, it is called out
      above with its justification, because that is a change to the claim the library
      makes and not a test tweak.
- [ ] If this made an existing `testKnownDefect*` pass, I deleted that expectation in this
      PR and said so.
- [ ] If this adds a `URLGuardDecision` tag, I updated the tag table in README.md.
      `testEveryTagTheCodeCanEmitIsDocumentedInTheReadme` fails the build otherwise, in
      both directions.
- [ ] A new pattern comes with a shape added to `testNoInputShapeIsSuperlinear`. 0.4.0
      shipped a cubic pattern where 8KB of ordinary text took 40 seconds.
- [ ] `CHANGELOG.md` records this, including any wrong first attempt worth the next
      person's time.

---

## Always

- [ ] **Every credential-shaped string in this diff is synthetic.** No real key, not a
      revoked one, not my own, not a truncated one.
- [ ] **No em dashes and no en dashes** anywhere in the diff, code, comments, docs or
      commit messages. Checked with
      `grep -rnP '[\x{2013}\x{2014}]' --include='*.swift' --include='*.md' --include='*.yml' .`
      The `house-style` CI job runs exactly that and fails the build on a hit.
- [ ] **No new dependencies.** Zero third-party packages is a property of this library,
      not an accident. If this needs one, open an issue first.
- [ ] No formatting or renaming sweep bundled in with the behaviour change.
- [ ] No public symbol added without a reason stated above. The surface is
      `SecretRedactor.redact`, `SecretRedactor.wrapAsUntrusted`,
      `SecretRedactor.newFenceID`, `URLGuard.evaluate`, `URLGuardConfig` and
      `URLGuardDecision`, and it is small on purpose.
- [ ] This does not rewrite, delete or move any existing tag. The six leaking tags stay,
      and CONTRIBUTING.md explains why.

## Related

<!--
Issue or advisory this closes. If it came from a private security report, link the
advisory rather than restating the finding, and say whether the reporter wants credit.
-->
