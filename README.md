<!-- dcj-tag:start -->
```
██████╗  ██████╗     ██╗
██╔══██╗██╔════╝     ██║
██║  ██║██║          ██║
██║  ██║██║     ██   ██║
██████╔╝╚██████╗╚█████╔╝
╚═════╝  ╚═════╝ ╚════╝
d o t c o m j a c k
```
<!-- dcj-tag:end -->

# GruxKit

Guardrails for desktop AI agents, in Swift. MIT licensed.

Everybody wants their own Jarvis. Most of the public attempts are demos: a loop that
pipes a microphone into a model and executes whatever comes back. They are impressive
for an afternoon and then you notice that the thing reading your screen is also
transcribing your password manager, and that it will fetch any URL a web page tells it
to.

This library is the unglamorous half of that problem, extracted from a Mac agent that
has been running against a real workload daily. It does not include the agent. It
includes the parts you would otherwise write badly at 2am and never test.

**Status: early.** Two modules today, both production code with real coverage. More
listed under Roadmap. It is versioned honestly, so what is here is here and nothing is
promised as shipped that is not.

## Install

```swift
.package(url: "https://github.com/dotcomjack/grux-kit.git", from: "0.5.0")
```

**Use 0.5.0. Every earlier tag leaks credentials, and each one looked fine when it was
cut.** That second half is the part worth reading: five tags have been published and all
five were later found to leak, including by audits of code that had already survived several
earlier ones. 0.5.0 is the most heavily audited state this library has been in and that is a
statement about effort, not a guarantee.

What the earlier tags actually do. 0.1.0 passes private key bodies straight through to the
model and has a forgeable injection fence. 0.2.x leaks the AWS secret access key. And
0.4.0, measured against a real build of it rather than inferred from its changelog, allows
the loopback and NAT64 SSRF bypasses and leaks indented PEM bodies, `PGPASSWORD=`, session
cookies, `Set-Cookie`, bare `Bearer` headers and `curl -u` passwords. Worst of that set,
and the one to check if you have ever pinned it: **a denylist entry written any way other
than a bare host matches nothing at all.** `https://evil.com`, `evil.com:443` and
`*.evil.com` are all silently inert against `denylist: ["evil.com"]`, so your own denylist
fails open and looks configured.

Earlier tags stay resolvable so existing checkouts do not break, and are documented in
[CHANGELOG.md](CHANGELOG.md) so nobody adopts one by accident.

Pre-1.0, so treat the minor version as breaking. Pin exactly if that matters to you.

```swift
.target(name: "YourAgent", dependencies: [.product(name: "GruxKit", package: "grux-kit")])
```

Requires macOS 13 and Swift 5.9. No third-party dependencies.

**Your own manifest needs `platforms: [.macOS(.v13)]` too.** That line is not optional and
leaving it out is a build failure, not a warning:

```
error: the library 'YourAgent' requires macos 10.13, but depends on the product 'GruxKit'
which requires macos 13.0
```

So the whole manifest, and this time it really is the whole file, opening pragma and import
included. Without those two lines a literal copy of the block fails with an error about
Swift tools version 3.1.0, which tells you nothing about what is actually wrong:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "YourAgent",
    platforms: [.macOS(.v13)],
    products: [.library(name: "YourAgent", targets: ["YourAgent"])],
    dependencies: [.package(url: "https://github.com/dotcomjack/grux-kit.git", from: "0.5.0")],
    targets: [
        .target(name: "YourAgent",
                dependencies: [.product(name: "GruxKit", package: "grux-kit")]),
    ]
)
```

Both claims here were checked by building them. A fresh `swift package init` plus the two
isolated snippets above and nothing else fails on the platform mismatch; adding the
`platforms` line builds clean. The block immediately above was pasted byte for byte into an
empty file and built on its own.

## SecretRedactor

An agent that can see your screen will eventually see a secret, and the moment that text
is interpolated into a prompt it leaves your machine.

```swift
let clean = SecretRedactor.redact(ocrText)
// "deploy with sk-ant-api03-…"  ->  "deploy with [REDACTED:ANTHROPIC_KEY]"
```

Twenty-four patterns plus a generic high-entropy pass. Two properties are
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

### What it does not do

It is a matcher, not a parser, so it cannot catch a secret that does not look like one.
A password, a session cookie with a short opaque value, an internal hostname, or a
credential in a format no pattern covers all pass straight through. New providers appear
constantly and this list will always trail them.

**Single-case hex strings are deliberately exempt, and that is a real gap, not just a
feature.** It is what keeps git SHAs, md5 and sha256 checksums intact, and those appear
constantly in the logs and diffs an agent reads. The cost is that a 32 or 64 character
lowercase-hex API secret, which several providers still issue, goes through untouched. It
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

### What it does not do

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
comments or docs, which is a house style the linter enforces.

## Licence

MIT. See [LICENSE](LICENSE).
