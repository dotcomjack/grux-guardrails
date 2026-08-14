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
are already published as leaking credentials, in the README and the changelog, with no
attempt to quietly drop them.

## What counts

**In scope.** A secret format that survives `redact`. Ordinary text that `redact`
destroys, since a redactor people switch off protects nothing. Any URL that
`URLGuard.evaluate` allows and that reaches a private address, cloud metadata, or the
loopback interface. Anything that crashes either entry point.

**Known and documented, so not a finding.** `URLGuard` does not follow redirects and does
not resolve DNS, so redirect chains and DNS rebinding are outside what it can see. Both
are described in the README, along with what to put behind it. `SecretRedactor` is a
matcher, so a credential in a format no pattern covers passes through by construction.

If you think one of those documented limits is worse than the README implies, that is
still worth reporting. The line between a documented limit and a false sense of security
is exactly the thing I would want to get right.

## Supported versions

Pre-1.0. Only the latest tag receives fixes.
