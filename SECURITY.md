# Security policy

This library is a security control, so a bug here is not a normal bug. If you have found
a way past `SecretRedactor` or `URLGuard`, please report it privately first.

## Reporting

Two channels. Either is fine, and the second one always works.

1. GitHub's private vulnerability reporting on this repository:
   **Security → Report a vulnerability**. That opens a channel only the maintainer can
   see. It appears once the repository is public and the setting is on.
2. Email **security@gruxai.com** with `Grux security` in the subject. This mailbox is
   live and monitored, so use it whenever the button above is not there.

Please include the input that triggers it and what you expected instead. A failing test
case is the fastest possible path to a fix.

## What to expect

- Acknowledgement within 3 days.
- An assessment within 14 days for anything I can reproduce, plus either a fix or an
  explanation of why it is working as intended.
- Credit in the release notes and the commit, unless you would rather not be named.

There is no bounty. This is a solo project given away under MIT.

## Disclosure

Coordinated disclosure. I will not publish the details of a report before there is a fix
or we agree there is nothing to fix, and I ask you for the same window. After a fix ships
I disclose it in full: what got through, which tags were affected, and what the fix
actually changed. That is not a promise made for this page. Six tags in this repository
are already published as leaking credentials, in the README, in the changelog, and in
`docs/DISCLOSURE-2026-08.md`, with no attempt to quietly drop them.

## What counts

**In scope.** A secret format that survives `redact`. Ordinary text that `redact`
destroys, since a redactor people switch off protects nothing. Any URL that
`URLGuard.evaluate` allows and that reaches a private address, cloud metadata, or the
loopback interface. Anything that crashes either entry point.

**Known and documented, so not a finding.** Each of these is deliberate, and each is
already written down with the reason, so a report about one will be closed as working as
intended. The full list with the trust boundaries is `docs/THREAT-MODEL.md`.

- `URLGuard` does not follow redirects. It judges one string, so a public URL is free to
  answer a 302 pointing at loopback and nothing here will see it. Every hop is the
  caller's.
- `URLGuard` does not resolve DNS, so it cannot see DNS rebinding, and it cannot tell a
  private TLD from a public domain.
- `SecretRedactor` is a matcher, not a parser, so a credential in a format no pattern
  covers passes through by construction.
- **A bare single-case hex secret is deliberately exempt**, which is what keeps git SHAs
  and checksums intact. A labelled one is still caught. Two further known defects, a
  labelled credential inside a JSON array or YAML sequence and one inside an XML or plist
  element body, are disclosed in `docs/CORPUS.md` and pinned by tests.

If you think one of those documented limits is worse than the documentation implies, that
is still worth reporting. The line between a documented limit and a false sense of security
is exactly the thing I would want to get right.

## Supported versions

Pre-1.0. Only the latest tag receives fixes.
