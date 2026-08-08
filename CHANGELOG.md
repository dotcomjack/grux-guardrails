# Changelog

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
  length. It now requires two independent signals. Measured leak rate for that credential
  is now 0%.
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
