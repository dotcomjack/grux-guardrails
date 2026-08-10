# Changelog

## Unreleased

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
