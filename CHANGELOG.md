# Changelog

## 0.3.0

**Use this one.** Earlier tags leak credentials, see below.

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
