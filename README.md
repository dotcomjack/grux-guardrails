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
.package(url: "https://github.com/dotcomjack/grux-kit.git", from: "0.1.0")
```

Pre-1.0, so treat the minor version as breaking. Pin exactly if that matters to you.

```swift
.target(name: "YourAgent", dependencies: [.product(name: "GruxKit", package: "grux-kit")])
```

Requires macOS 13 and Swift 5.9. No third-party dependencies.

## SecretRedactor

An agent that can see your screen will eventually see a secret, and the moment that text
is interpolated into a prompt it leaves your machine.

```swift
let clean = SecretRedactor.redact(ocrText)
// "deploy with sk-ant-api03-…"  ->  "deploy with [REDACTED:ANTHROPIC_KEY]"
```

Twelve provider-specific patterns plus a generic high-entropy pass. Two properties are
load-bearing and both are pinned by tests:

**Most specific wins.** A Stripe live key is tagged `[REDACTED:STRIPE_LIVE_SECRET]`, not
the generic entropy tag. Precision is what makes the audit trail worth reading later.

**It is idempotent.** `redact(redact(x)) == redact(x)`. Prompts get assembled from
fragments that were each cleaned on the way in, so the function runs over its own output
constantly. Without an explicit guard, `[REDACTED:ANTHROPIC_KEY]` is itself a long mixed
class token and the entropy pass eats its own markers.

The generic pass requires 40+ characters spanning 4 character classes before it fires.
That threshold exists because **a redactor that mangles ordinary text is a redactor
people switch off**, and a switched-off redactor protects nothing. An md5 digest, a long
URL path, and fifty consecutive digits all pass through untouched, and there are tests
asserting exactly that.

There is also a fence for the injection half of the problem, which is a different problem
from the secrets half:

```swift
let block = SecretRedactor.wrapAsUntrusted("screen_ocr", pageText)
// <untrusted_data kind="screen_ocr"> … </untrusted_data>
```

Text the agent *read* and text you *typed* are indistinguishable once concatenated into a
prompt. The fence does not make injection impossible. It gives the model a boundary it
can act on, which is strictly better than concatenation and is not a substitute for not
handing the agent capabilities it did not need.

### What it does not do

It is a matcher, not a parser, so it cannot catch a secret that does not look like one.
A password, a session cookie with a short opaque value, an internal hostname, or a private
key pasted without its PEM header all pass straight through. It is the last line, not the
only one, and it is not a reason to feed an agent credentials it did not need.

## URLGuard

The threat is server-side request forgery with a language model as the confused deputy.
Your agent runs on your laptop, inside your network, and it will follow a link that came
from a web page, an email, or its own hallucination.

```swift
let decision = URLGuard.evaluate(url, config: config)
guard decision.isAllowed else {
    log("blocked", decision.tag)   // PRIVATE_NETWORK, CREDENTIAL_URL, BAD_SCHEME, …
    return
}
```

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
[::ffff:169.254.169.254] cloud metadata in an IPv6 costume
evil.com.               trailing-dot FQDN, resolves identically, different string
```

Every line above is a test case. The trailing dot one matters more than it looks: it has
to be normalized *before* list matching, not after, or one appended character walks past
your denylist.

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
func urlSession(_ s: URLSession, task: URLSessionTask,
                willPerformHTTPRedirection r: HTTPURLResponse,
                newRequest: URLRequest,
                completionHandler: @escaping (URLRequest?) -> Void) {
    let next = newRequest.url?.absoluteString ?? ""
    completionHandler(URLGuard.evaluate(next, config: config).isAllowed ? newRequest : nil)
}
```

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
