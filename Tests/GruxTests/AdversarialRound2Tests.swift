import XCTest
@testable import GruxGuardrails

/// Round two of the adversarial audit.
///
/// Round one drove 45 hostile URLs and 31 shape-correct credentials and came back with
/// one real result, a false positive. That number is the signal that matters: when a
/// corpus stops producing findings it has stopped being adversarial about the right
/// things, not become complete. So this file deliberately attacks the families round one
/// never touched, and it is organised by family rather than by assertion so the coverage
/// gap is visible in the source rather than only in a report.
///
/// Two kinds of test live here and the difference is load-bearing.
///
/// The ordinary ones assert that a family holds. Each is a table, because a table is what
/// makes the next person's addition cheap.
///
/// The ones named `testKnownDefect...` and `testKnownGap...` use `XCTExpectFailure`, and
/// that choice is the whole point rather than a convenience. This library shipped a leak
/// at 0.3.1 that sat behind a test asserting the leak was CORRECT, with the suite green
/// throughout, and the CHANGELOG calls that the worst kind of failure there is. Pinning a
/// leak with `XCTAssertEqual(out, input)` would repeat exactly that mistake, so a
/// documented defect is written as the assertion that SHOULD hold, wrapped in an expected
/// failure. The suite stays green, the defect is stated in the assertion rather than
/// buried in a comment, and the moment somebody fixes it the expectation stops being met
/// and the suite goes red, which forces the fixer to come here and delete it deliberately.
///
/// Every credential below is synthetic.
final class AdversarialRound2Tests: XCTestCase {

    // MARK: - Helpers

    private func assertDenied(_ raw: String, tag expected: String,
                              _ note: String, file: StaticString = #filePath, line: UInt = #line) {
        let decision = URLGuard.evaluate(raw)
        XCTAssertFalse(decision.isAllowed,
                       "ALLOWED but must be denied: \(note) [\(escaped(raw))]", file: file, line: line)
        XCTAssertEqual(decision.tag, expected,
                       "wrong audit tag for \(note) [\(escaped(raw))]", file: file, line: line)
    }

    /// Non-ASCII scalars are printed as code points, because a failure message carrying a
    /// raw fullwidth digit is unreadable in a terminal and indistinguishable from the
    /// ASCII digit it is impersonating, which is the entire attack.
    private func escaped(_ s: String) -> String {
        s.unicodeScalars.map {
            $0.isASCII && $0.value >= 0x20 ? String($0) : "U+" + String(format: "%04X", $0.value)
        }.joined()
    }

    // MARK: - URLGuard, family 1: IDN homographs and punycode round-tripping

    /// Every unicode spelling that a browser resolves to loopback.
    ///
    /// This family exists because the guard does no IDNA work of its own: it reads
    /// `URL.host` and trusts it. That is either completely safe or completely broken
    /// depending on a Foundation behaviour nothing in this package pins, so it is pinned
    /// here. Measured: `URL.host` applies UTS46 mapping, so fullwidth digits, the three
    /// alternate full stops, circled digits, roman numerals and a soft hyphen all
    /// normalise to ASCII BEFORE the guard ever sees them.
    ///
    /// The consequence is worth stating plainly, because it is the difference between a
    /// pass and a critical bypass. `http://127.0\u{FF0E}0\u{FF0E}1/` carries only ONE
    /// ASCII dot. If Foundation preserved the fullwidth stops, the host would be the
    /// two labels `127` and `0\u{FF0E}0\u{FF0E}1`, which is not a dotted quad, is not
    /// numeric-IP-like because the labels are not all digits, and is not single-label
    /// because there is a real dot in it. It would fall all the way through
    /// `privateNetworkReason` and be ALLOWED, while Chrome, Safari and Firefox all dial
    /// 127.0.0.1. Nothing in the guard would catch it. The only thing standing between
    /// this library and that bypass is a Foundation implementation detail, so it gets a
    /// test rather than an assumption.
    func testEveryUnicodeSpellingOfALoopbackHostIsDenied() {
        let cases: [(String, String)] = [
            ("http://\u{FF11}\u{FF12}\u{FF17}\u{FF0E}\u{FF10}\u{FF0E}\u{FF10}\u{FF0E}\u{FF11}/",
             "fullwidth digits and fullwidth full stops"),
            ("http://127\u{FF0E}0\u{FF0E}0\u{FF0E}1/", "ASCII digits, fullwidth full stops"),
            ("http://127\u{3002}0\u{3002}0\u{3002}1/", "ideographic full stops"),
            ("http://127\u{FF61}0\u{FF61}0\u{FF61}1/", "halfwidth ideographic full stops"),
            ("http://\u{2460}\u{2461}\u{2466}.0.0.1/", "circled digits one two seven"),
            ("http://\u{217C}ocalhost/", "small roman numeral fifty as the leading l"),
            ("http://\u{FF4C}\u{FF4F}\u{FF43}\u{FF41}\u{FF4C}\u{FF48}\u{FF4F}\u{FF53}\u{FF54}/",
             "fullwidth localhost"),
            ("http://local\u{00AD}host/", "soft hyphen inside localhost"),
            ("http://LOCALHOST/", "uppercase localhost"),
        ]
        for (raw, note) in cases {
            assertDenied(raw, tag: "PRIVATE_NETWORK", note)
        }
    }

    /// The mixed case, where only SOME of the separators are unicode. Kept separate from
    /// the table above because it is the shape that defeats a guard which merely rejects
    /// hosts containing non-ASCII: each of these is majority ASCII and would look
    /// unremarkable to a length or character-class check.
    func testAlternateDotCharactersCannotSplitAnIPv4Literal() {
        let cases: [(String, String)] = [
            ("http://127.0\u{FF0E}0\u{FF0E}1/", "one ASCII dot, two fullwidth"),
            ("http://127.0\u{3002}0\u{3002}1/", "one ASCII dot, two ideographic"),
            ("http://127.0\u{FF61}0\u{FF61}1/", "one ASCII dot, two halfwidth ideographic"),
            ("http://\u{2460}\u{2461}\u{2466}\u{FF0E}0\u{FF0E}0\u{FF0E}1/",
             "circled digits with fullwidth stops"),
            ("http://127.0.0.1\u{200B}.evil.com/", "zero width space inside an embedded literal"),
        ]
        for (raw, note) in cases {
            assertDenied(raw, tag: "PRIVATE_NETWORK", note)
        }
    }

    /// The other half of the homograph question, and the one a guard gets wrong by being
    /// too aggressive. A Cyrillic lookalike of an ordinary public domain is a PHISHING
    /// concern, not a network-reachability one, and `URLGuard` says so in the comment on
    /// `isStructurallyIllegalInHost`. It has to stay allowed, or the guard starts denying
    /// every internationalized domain on the internet.
    ///
    /// Both of these punycode to `xn--` hosts that resolve to whatever their owner points
    /// them at, which is public by default and is not this guard's problem.
    func testUnicodeAndPunycodeHostsThatAreMerelyPublicStayAllowed() {
        for raw in ["http://\u{0435}vil.com/", "http://xn--0-3sa.com/", "http://\u{4F8B}\u{3048}.jp/"] {
            XCTAssertTrue(URLGuard.evaluate(raw).isAllowed,
                          "denied a merely public internationalized host: \(escaped(raw))")
        }
    }

    // MARK: - URLGuard, family 2: percent encoding and overlong UTF-8

    func testPercentEncodingAndOverlongUTF8CannotSmuggleAHost() {
        let cases: [(String, String, String)] = [
            ("http://127%2e0%2e0%2e1/", "PRIVATE_NETWORK", "percent-encoded dots"),
            ("http://%31%32%37%2e%30%2e%30%2e%31/", "PRIVATE_NETWORK", "every character percent-encoded"),
            // Overlong UTF-8 for a full stop. A decoder that accepts it reads this host as
            // `127.0.0.1.evil.com`, and one that rejects it has to produce nothing at all.
            // Foundation does the second, which is the safe half of the fork, so the
            // denial arrives as a missing host rather than as a private-network hit.
            ("http://127.0.0.1%C0%AE.evil.com/", "URL_DENIED", "overlong UTF-8 encoded full stop"),
            ("http://127.0.0.1%00.example.com/", "HOST_SMUGGLING", "NUL truncation"),
        ]
        for (raw, tag, note) in cases {
            assertDenied(raw, tag: tag, note)
        }
    }

    // MARK: - URLGuard, family 3: authority shapes where parsers disagree

    /// The dangerous direction here is specific and worth naming, because the harmless
    /// direction looks identical at a glance.
    ///
    /// WHATWG, which is what a browser and most HTTP clients implement, treats a backslash
    /// as a path separator for special schemes, so `http://127.0.0.1\evil.com/` has the
    /// authority `127.0.0.1` and the path `/evil.com`. RFC 3986, which is what Foundation
    /// implements, does not, so the same string has one long authority. If Foundation
    /// resolved that authority to the PUBLIC `evil.com` while a browser dialled loopback,
    /// the guard would allow a URL that reaches the local network. That is the bypass this
    /// test is looking for.
    ///
    /// Measured: it does not happen, and it fails closed by three different routes.
    /// The bare backslash form is unparseable. Both `@` forms are caught by the credential
    /// check before any host classification runs, which is why two of these carry
    /// CREDENTIAL_URL rather than a network tag. Raw tabs and newlines, which browsers
    /// strip from a URL entirely, are also unparseable.
    func testAuthorityShapesWhereFoundationAndABrowserDisagreeFailClosed() {
        let cases: [(String, String, String)] = [
            ("http://127.0.0.1\\evil.com/", "URL_DENIED", "bare backslash authority split"),
            ("http://127.0.0.1\\@evil.com/", "CREDENTIAL_URL", "backslash before the at sign"),
            ("http://evil.com\\@127.0.0.1/", "CREDENTIAL_URL", "public decoy in the userinfo"),
            ("http://127.0.0.1\t.evil.com/", "URL_DENIED", "raw tab, which a browser strips"),
            ("http://127.0.0.1\n.evil.com/", "URL_DENIED", "raw newline, which a browser strips"),
            ("http://127.0.0.1\r.evil.com/", "URL_DENIED", "raw carriage return"),
        ]
        for (raw, tag, note) in cases {
            assertDenied(raw, tag: tag, note)
        }

        // The inverse, and it must stay ALLOWED. A fragment or a query cannot move the
        // authority, so the loopback address in these two is decoration. A guard that
        // denied them would be scanning for a substring rather than reading a host, and
        // that is the mistake `URLGuardDecision.tag` already had to be fixed for once.
        for raw in ["http://google.com#@127.0.0.1/", "http://google.com?@127.0.0.1/"] {
            XCTAssertTrue(URLGuard.evaluate(raw).isAllowed,
                          "denied a public host over a loopback address that is only decoration: \(raw)")
        }
    }

    // MARK: - URLGuard, family 4: scheme case and whitespace

    func testSchemeCaseAndWhitespaceVariantsAreNormalisedOrDenied() {
        let cases: [(String, String, String)] = [
            ("hTtPs://127.0.0.1/", "PRIVATE_NETWORK", "mixed case scheme"),
            ("HTTPS://LOCALHOST/", "PRIVATE_NETWORK", "everything uppercase"),
            ("\thttp://127.0.0.1/", "PRIVATE_NETWORK", "leading tab, trimmed"),
            ("  http://127.0.0.1/  ", "PRIVATE_NETWORK", "surrounding spaces, trimmed"),
            ("http://127.0.0.1", "PRIVATE_NETWORK", "no trailing slash"),
            ("http\u{0009}://127.0.0.1/", "URL_DENIED", "tab inside the scheme"),
            ("http:// 127.0.0.1/", "URL_DENIED", "space after the slashes"),
            ("http://127.0.0.1 /", "URL_DENIED", "space inside the authority"),
            ("http:127.0.0.1/", "URL_DENIED", "scheme with no slashes"),
            ("http:///127.0.0.1/", "URL_DENIED", "three slashes, empty authority"),
            ("//127.0.0.1/", "BAD_SCHEME", "protocol relative, no scheme at all"),
        ]
        for (raw, tag, note) in cases {
            assertDenied(raw, tag: tag, note)
        }
    }

    // MARK: - URLGuard, family 5: port confusion

    /// A port is the part of an authority most likely to be mistaken for something else,
    /// in both directions: `evil.com:80@127.0.0.1` looks like a host and a port and is
    /// actually a username and a password, and `[::1]:8080` looks like it has three colons
    /// too many. Neither may change which host is judged.
    func testPortConfusionCannotReachAPrivateHost() {
        let cases: [(String, String, String)] = [
            ("http://127.0.0.1:65536/", "PRIVATE_NETWORK", "port above the 16 bit range"),
            ("http://[::1]:8080/", "PRIVATE_NETWORK", "bracketed IPv6 with a port"),
            ("http://[::ffff:127.0.0.1]:8080/", "PRIVATE_NETWORK", "mapped IPv4 with a port"),
            ("http://evil.com:80@127.0.0.1/", "CREDENTIAL_URL", "host and port worn as userinfo"),
            ("http://127.0.0.1:80:80/", "URL_DENIED", "two ports"),
            ("http://127.0.0.1:+80/", "URL_DENIED", "signed port"),
            ("http://127.0.0.1:0x50/", "URL_DENIED", "hex port"),
        ]
        for (raw, tag, note) in cases {
            assertDenied(raw, tag: tag, note)
        }
    }

    // MARK: - URLGuard, family 6: unusual IPv6 spellings of an embedded IPv4

    func testUnusualIPv6SpellingsOfAnEmbeddedIPv4AreDenied() {
        let cases: [(String, String)] = [
            ("http://[0:0:0:0:0:ffff:7f00:0001]/", "fully expanded mapped form with leading zeros"),
            ("http://[::FFFF:127.0.0.1]/", "uppercase hex in the mapped prefix"),
            ("http://[::127.0.0.1]/", "IPv4 compatible"),
            ("http://[64:ff9b::127.0.0.1]/", "NAT64 well known prefix, dotted tail"),
            ("http://[64:ff9b:1::7f00:1]/", "NAT64 local use prefix, hex tail"),
            ("http://[2002:7f00:1::]/", "6to4 carrying loopback"),
            ("http://[2002:a9fe:a9fe::]/", "6to4 carrying the metadata address"),
            ("http://[fe80::1%25en0]/", "zone index, percent encoded"),
            ("http://[fe80::1%en0]/", "zone index, raw"),
        ]
        for (raw, note) in cases {
            assertDenied(raw, tag: "PRIVATE_NETWORK", note)
        }
    }

    /// FIXED IN 0.6.1. This was the only URL family in round 2 that was not denied.
    ///
    /// `::ffff:0:a.b.c.d` is the IPv4-translated address of RFC 2765 section 2.1, the
    /// `::ffff:0:0:0/96` prefix. It is the fourth member of the embedded-IPv4 family whose
    /// other three, IPv4-mapped, IPv4-compatible and NAT64, this guard decodes and judges
    /// by the address they carry. This one it does not: `first10Zero` is false because
    /// the `ffff` sits at bytes 8 and 9 rather than 10 and 11, so `mapped`, `compatible`
    /// and `nat64` are all false and the address falls through `ipv6RegistryReason` as
    /// ordinary global unicast.
    ///
    /// **Why this is filed as a gap and not as a leak.** Measured on this machine,
    /// `route -n get -inet6 ::ffff:0:7f00:1` answers `not in table`, while the same
    /// command for `::1` answers `interface: lo0`. There is no route, so an agent that
    /// follows one of these URLs today reaches nothing. RFC 6145 obsoleted RFC 2765 and
    /// dropped this format, and IANA does not carry it as a special-purpose prefix, which
    /// is presumably why it was never in the table.
    ///
    /// It is now decoded beside the other three. The reasoning that got it fixed:
    /// this guard denies `0x7f.0.0.1` purely because a
    /// resolver MIGHT read it as loopback, and it denies deprecated site-local fec0::/10
    /// with the note that deprecated is not the same as unroutable. By its own published
    /// standard, a deprecated translation format carrying a loopback target belongs in the
    /// table. The cost of adding it is a public IPv6 that happens to collide with a
    /// reserved prefix, which is the same trade the NAT64 rows already took.
    func testIPv4TranslatedIPv6PrefixIsDenied() {
        let payloads = [
            "http://[::ffff:0:127.0.0.1]/",
            "http://[::ffff:0:169.254.169.254]/",
            "http://[::ffff:0:10.0.0.1]/",
            "http://[::ffff:0:7f00:1]/",
            "http://[0:0:0:0:ffff:0:7f00:1]/",
            "http://[::ffff:0:0:127.0.0.1]/",
        ]
            for raw in payloads {
                XCTAssertFalse(URLGuard.evaluate(raw).isAllowed,
                               "IPv4-translated IPv6 carrying a private target was allowed: \(raw)")
            }
    }

    // MARK: - URLGuard, family 7: extremely long hosts

    /// Two questions at once, because a host is attacker-controlled in both length and
    /// content. Does a very long host still get classified correctly, and does the cost of
    /// classifying it stay linear. `embeddedPrivateIPv4Reason` walks every window of four
    /// consecutive labels, so a host with ten thousand labels does ten thousand joins, and
    /// a quadratic version of that loop would be a free denial of service against any
    /// agent that evaluates a URL it was handed.
    func testExtremelyLongHostsAreClassifiedCorrectlyAndStayLinear() {
        let small = "http://" + Array(repeating: "a", count: 1_000).joined(separator: ".") + ".com/"
        let large = "http://" + Array(repeating: "a", count: 10_000).joined(separator: ".") + ".com/"

        let t0 = Date()
        XCTAssertTrue(URLGuard.evaluate(small).isAllowed, "a long public host must stay allowed")
        let smallTime = max(Date().timeIntervalSince(t0), 0.0005)

        let t1 = Date()
        XCTAssertTrue(URLGuard.evaluate(large).isAllowed, "a long public host must stay allowed")
        let largeTime = Date().timeIntervalSince(t1)

        XCTAssertLessThan(largeTime, 2.0, "10,000 labels took \(largeTime)s, which is a denial of service")
        XCTAssertLessThan(largeTime / smallTime, 40.0,
                          "10x the labels cost \(largeTime / smallTime)x, which is superlinear")

        // Length must not dilute the classification. A private address buried 500 labels
        // deep is still a private address.
        let buried = "http://" + Array(repeating: "a", count: 500).joined(separator: ".") + ".127.0.0.1.example.com/"
        assertDenied(buried, tag: "PRIVATE_NETWORK", "loopback embedded 500 labels deep")

        let numeric = "http://" + Array(repeating: "127.0.0.1", count: 2_000).joined(separator: ".") + "/"
        assertDenied(numeric, tag: "PRIVATE_NETWORK", "2,000 repeated dotted quads")
    }

    // MARK: - SecretRedactor, family 8: serialised and multi-line credentials

    /// Credentials that have been through a serialiser on the way to the agent. Each of
    /// these is a real file an agent is routinely asked to read, and each puts the value
    /// somewhere the plain `NAME=value` shape does not.
    func testSerialisedAndMultiLineCredentialsAreCaught() {
        let cases: [(String, String, String)] = [
            ("JSON with an escaped unicode escape in the value",
             "{\"password\": \"\\u0073ecretPassw0rd123\"}", "\\u0073ecretPassw0rd123"),
            ("JSON with the value on the next line",
             "{\n  \"apiKey\":\n    \"abcdefghijklmnopqrstuvwxyz012345\"\n}",
             "abcdefghijklmnopqrstuvwxyz012345"),
            ("minified JSON, no whitespace at all",
             "{\"a\":1,\"clientSecret\":\"abcdefghijklmnopqrstuvwxyz012345\",\"b\":2}",
             "abcdefghijklmnopqrstuvwxyz012345"),
            ("TOML",
             "[registry]\ntoken = \"abcdefghijklmnopqrstuvwxyz012345\"",
             "abcdefghijklmnopqrstuvwxyz012345"),
            ("INI, the shape of ~/.aws/credentials",
             "[default]\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
             "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            ("CRLF line endings, which is what a Windows env file carries",
             "API_TOKEN=abcdefghijklmnopqrstuvwxyz012345\r\nNEXT=1",
             "abcdefghijklmnopqrstuvwxyz012345"),
            ("a PEM whose line breaks are CRLF rather than LF",
             "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAxYz1234567890abcdefGHIJ\r\n-----END RSA PRIVATE KEY-----",
             "MIIEowIBAAKCAQEAxYz1234567890abcdefGHIJ"),
            ("an XML attribute, which is the half of XML that is covered",
             "<server password=\"s3cretPassw0rdForProd\" />", "s3cretPassw0rdForProd"),
        ]
        for (note, text, secret) in cases {
            XCTAssertFalse(SecretRedactor.redact(text).contains(secret),
                           "leaked: \(note)\n   in : \(text)\n   out: \(SecretRedactor.redact(text))")
        }
    }

    /// KNOWN DEFECT. A credential inside a JSON array or a YAML sequence survives.
    ///
    /// `redactLabelledValues` finds the NAME, steps over quotes and whitespace, accepts a
    /// separator, and then reads the VALUE. What it does not do is step over a container
    /// opener. After `"tokens":` the next character is `[`, which is not a quote and is
    /// not a value terminator either, so the value it reads is the single character `[`,
    /// which fails the eight-character floor in `looksLikeACredentialValue` and the whole
    /// run is skipped. Every element of the array then walks out untouched.
    ///
    /// This is not the documented matcher limit. The README's caveat is that the redactor
    /// "cannot catch a secret that does not look like one", and the label here is right
    /// there in the text. The scanner's own doc comment claims it "covers env files, shell
    /// exports, YAML, JSON and query strings in one pattern". A JSON array is JSON.
    ///
    /// The blast radius is exactly the class of value the labelled scanner exists to save.
    /// Measured: a provider-prefixed token inside an array is still caught by `patterns`,
    /// and a 40-character mixed-case token is still caught by the entropy pass. What leaks
    /// is everything that only the LABEL could have saved, which is the short, the
    /// single-case and the lowercase-hex, and that is most real passwords and most real
    /// API keys. The control assertion below pins that asymmetry: the identical secret in
    /// `POSTGRES_PASSWORD=` form is in the leak corpus and is caught.
    func testKnownDefectCredentialsInsideAJSONArrayOrYAMLSequenceSurvive() {
        let cases: [(String, String, String)] = [
            ("JSON array of passwords",
             "{\"passwords\": [\"s3cretPassw0rdForProd\"]}", "s3cretPassw0rdForProd"),
            ("JSON array of lowercase hex API keys",
             "{\"apiKeys\": [\"0123456789abcdef0123456789abcdef\"]}", "0123456789abcdef0123456789abcdef"),
            ("multi element array over several lines",
             "\"tokens\": [\n  \"abcdefghijklmnopqrstuvwxyz012345\",\n  \"zyxwvutsrqponmlkjihgfedcba543210\"\n]",
             "zyxwvutsrqponmlkjihgfedcba543210"),
            ("single quoted array element",
             "tokens: ['abcdefghijklmnopqrstuvwxyz012345']", "abcdefghijklmnopqrstuvwxyz012345"),
            ("YAML sequence, the dash form",
             "passwords:\n  - s3cretPassw0rdForProd", "s3cretPassw0rdForProd"),
        ]
        // ONE EXPECTATION PER CASE, deliberately, not one wrapped around the table.
        // With a single expectation around the loop, ONE recorded failure satisfies it,
        // so a PARTIAL fix leaves the suite green and ships believed complete. Per case,
        // the moment any one of them starts passing, its own expectation goes unmet and
        // the suite goes red, which is what this file claims to guarantee.
        for (note, text, secret) in cases {
            XCTExpectFailure("KNOWN DEFECT: redactLabelledValues does not step over a container opener, so every element of a JSON array or YAML sequence leaks. Fixing it means skipping `[` and a YAML `- ` after the separator, and then deleting this expectation. [case: \(note)]") {
                    XCTAssertFalse(SecretRedactor.redact(text).contains(secret),
                                   "leaked: \(note)\n   in : \(text)\n   out: \(SecretRedactor.redact(text))")
            }
        }

        // Controls, deliberately outside the expectation so they stay strict. These are
        // what make the defect a defect rather than a general weakness: the SAME secret is
        // caught in the SAME file format the moment it is not inside brackets, and the
        // other two passes still reach into the array for the values they can see.
        XCTAssertFalse(SecretRedactor.redact("POSTGRES_PASSWORD=s3cretPassw0rdForProd")
                           .contains("s3cretPassw0rdForProd"),
                       "the control leaked, so this test is measuring the wrong thing")
        XCTAssertFalse(SecretRedactor.redact("{\"tokens\": [\"ghp_ABCDEFGHIJ0123456789abcdefghij0123\"]}")
                           .contains("ghp_ABCDEFGHIJ0123456789abcdefghij0123"),
                       "a provider prefix inside an array must still be caught by patterns")
        XCTAssertFalse(SecretRedactor.redact("{\"tokens\": [\"aB3dE5gH7jK9lM1nO3pQ5rS7tU9vW1xY3zA5bC7d\"]}")
                           .contains("aB3dE5gH7jK9lM1nO3pQ5rS7tU9vW1xY3zA5bC7d"),
                       "a high entropy value inside an array must still be caught by the entropy pass")
    }

    /// KNOWN DEFECT. A credential in the BODY of an XML or plist element survives, while
    /// the same credential in an ATTRIBUTE of the same element is caught.
    ///
    /// That asymmetry is what makes this dangerous rather than merely absent. A reviewer
    /// checking whether XML is handled finds `password="..."` redacted and stops, and the
    /// element form is the one that Maven's `settings.xml` actually uses. The scanner
    /// requires `=`, `:`, `(` or whitespace after the name, and after `<password>` the
    /// next character is `>`, which is none of them.
    ///
    /// The plist case is worth calling out separately because this is a macOS library. A
    /// plist does not even put the name and the value in the same element: the name is in
    /// a `<key>` and the value is in the `<string>` that follows it, so a scanner that
    /// reads a name and then a value cannot reach it without understanding the format.
    func testKnownDefectCredentialsInsideAnXMLOrPlistElementBodySurvive() {
        let cases: [(String, String, String)] = [
            ("Maven settings.xml",
             "<server>\n  <id>central</id>\n  <password>s3cretPassw0rdForProd</password>\n</server>",
             "s3cretPassw0rdForProd"),
            ("a bare XML element",
             "<apiKey>abcdefghijklmnopqrstuvwxyz012345</apiKey>", "abcdefghijklmnopqrstuvwxyz012345"),
            ("an Apple plist key and string pair",
             "<key>APIToken</key>\n<string>abcdefghijklmnopqrstuvwxyz012345</string>",
             "abcdefghijklmnopqrstuvwxyz012345"),
        ]
        // ONE EXPECTATION PER CASE, deliberately, not one wrapped around the table.
        // With a single expectation around the loop, ONE recorded failure satisfies it,
        // so a PARTIAL fix leaves the suite green and ships believed complete. Per case,
        // the moment any one of them starts passing, its own expectation goes unmet and
        // the suite goes red, which is what this file claims to guarantee.
        for (note, text, secret) in cases {
            XCTExpectFailure("KNOWN DEFECT: an XML or plist element BODY is not reachable by redactLabelledValues, though the attribute form is. Fixing it means accepting `>` as a separator, and for plist recognising the key and string pairing. Then delete this expectation. [case: \(note)]") {
                    XCTAssertFalse(SecretRedactor.redact(text).contains(secret),
                                   "leaked: \(note)\n   in : \(text)\n   out: \(SecretRedactor.redact(text))")
            }
        }
    }

    /// KNOWN DEFECT. Two provider prefixes that neither pass can see.
    ///
    /// This is precisely the case the pattern table already exists for. Its own comment
    /// says HuggingFace and Shopify tokens got prefix patterns "because the generic pass
    /// structurally cannot reach them. It requires mixed case AND digits, and a
    /// HuggingFace token carries no digit while a Shopify token is single case."
    ///
    /// `dckr_pat_` and `lin_api_` are the same shape and are not in the table. A Docker
    /// Hub personal access token whose body is lowercase and digits clears the 40
    /// character entropy floor as one run, because `_` is in the token class, and then
    /// fails `looksLikeASecret` on the missing uppercase. A shorter one never reaches the
    /// floor at all. Either way it leaves in the clear.
    ///
    /// The control below is the part that makes this a defect rather than a wish: the
    /// labelled form IS caught, so the library already agrees these values are
    /// credentials. It just cannot see them when they arrive bare, which is how a token
    /// appears in a `docker login` transcript or a CI log.
    func testDockerHubAndLinearTokensAreRedacted() {
        let bare = [
            "dckr_pat_a1b2c3d4e5f6g7h8i9j0kl1mn2o3p4q5",
            "dckr_pat_abcdefghijklmnopqrstuvwxyzabcdef1234",
            "lin_api_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        ]
        for token in bare {
            XCTAssertFalse(SecretRedactor.redact(token).contains(token),
                           "bare provider token leaked: \(token)")
        }

        // Controls. The labelled form is caught, so the disagreement is only about the
        // bare token, and the two providers the table DOES carry for this exact reason
        // still work.
        for token in bare {
            XCTAssertFalse(SecretRedactor.redact("DOCKER_TOKEN=\(token)").contains(token),
                           "the labelled control leaked, so this test is measuring the wrong thing")
        }
        XCTAssertFalse(SecretRedactor.redact("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")
                           .contains("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"),
                       "the HuggingFace prefix pattern regressed")
    }

    /// KNOWN DEFECT, and this one is a false positive rather than a leak.
    ///
    /// `credentialWords` are matched as plain substrings with no word boundary, which is
    /// deliberate and is what reaches `accessToken` and `PGPASSWORD`. The price is that
    /// `keywords`, `author`, `passenger`, `keyPath`, `tokenizer` and `session` all contain
    /// one too. The library already knows this: `isWhitespaceSeparable` exists precisely
    /// because "a keyword anywhere inside any token made the NEXT token disappear", and
    /// the four round-seven fixtures in the benign corpus, keyboard, passenger, authorial
    /// and keystone, are there to hold that brake in place.
    ///
    /// The defect is that the brake is wired to ONE separator. A name that has to prove
    /// itself before whitespace is trusted completely before a colon, and a colon is how
    /// JSON, YAML and every front matter block in the world writes a field. So the exact
    /// four words the benign corpus protects are destroyed the moment the separator
    /// changes, and no test could see it because every fixture written to exercise the
    /// brake happens to use whitespace.
    ///
    /// Measured over 30 authored real-world config lines: 20 destroyed, 66.7%. The two
    /// that hurt most are not the exotic ones. `auth_url` and `token_url` are the standard
    /// OpenID Connect discovery field names, and their values are public URLs.
    func testKnownDefectQuotedProseUnderACredentialishNameIsDestroyed() {
        let ordinary = [
            "\"keywords\": \"machine-learning, artificial-intelligence\"",
            "\"author\": \"Alice Smith and Bob Jones\"",
            "\"passenger\": \"John Smith Party Of Four\"",
            "\"keyboard\": \"Mechanical Cherry MX Brown\"",
            "\"keystone\": \"Species Conservation Programme\"",
            "\"keyPath\": \"user.profile.displayName\"",
            "\"tokenizer\": \"sentencepiece-bpe-32k-vocabulary\"",
            "\"sessionStorage\": \"window.sessionStorage.getItem\"",
            "session: \"Morning Keynote and Panel Discussion\"",
            "  secretName: my-tls-certificate-bundle",
            "keyboard_layout: \"United States International\"",
            "authorised_by: \"Regional Operations Manager\"",
            "passport_country: \"United Kingdom Of Britain\"",
            "  auth_url: \"https://accounts.example.com/authorize\"",
            "  token_url: \"https://accounts.example.com/token\"",
            "\"passwordPolicy\": \"minimum twelve characters\"",
        ]
        // ONE EXPECTATION PER CASE, deliberately, not one wrapped around the table.
        // With a single expectation around the loop, ONE recorded failure satisfies it,
        // so a PARTIAL fix leaves the suite green and ships believed complete. Per case,
        // the moment any one of them starts passing, its own expectation goes unmet and
        // the suite goes red, which is what this file claims to guarantee.
        for text in ordinary {
            XCTExpectFailure("KNOWN DEFECT: isWhitespaceSeparable brakes the whitespace separator only, so a buried credential word is fully trusted before a colon. 20 of 30 measured real-world config lines are destroyed. Fixing it means applying the same name brake, or the locator brake, to the colon path, and then deleting this expectation. [case: \(text)]") {
                    XCTAssertEqual(SecretRedactor.redact(text), text,
                                   "ordinary configuration was destroyed:\n   in : \(text)\n   out: \(SecretRedactor.redact(text))")
            }
        }

        // Controls. The whitespace path still holds, which is what localises the defect to
        // the separator rather than to the word list, and a real labelled secret under the
        // very same names is still caught, which is what makes this a tuning problem
        // rather than an argument for deleting the scanner.
        for text in ["the keyboard Serial9912345 was replaced", "a keystone Species4471 went extinct"] {
            XCTAssertEqual(SecretRedactor.redact(text), text,
                           "the whitespace brake regressed, so this test is measuring the wrong thing")
        }
        XCTAssertFalse(SecretRedactor.redact("\"secret\": \"abcdefghijklmnopqrstuvwxyz012345\"")
                           .contains("abcdefghijklmnopqrstuvwxyz012345"),
                       "a real labelled secret must still be caught")
    }

    // MARK: - SecretRedactor, family 9: base64 of a credential

    /// Encoding a secret is not hiding it, as long as the result is long enough for the
    /// entropy pass to see. Base64 output is mixed case with digits by construction, which
    /// is the exact signal `looksLikeASecret` keys on, so a wrapped credential of any real
    /// size is caught and so is a double wrapped one.
    ///
    /// The one that survives is worth stating rather than hiding: base64 of a 20 character
    /// AWS access key ID is 28 characters, which is under the 40 character entropy floor.
    /// It is also not a secret. `AKIA...` is the public half of the AWS pair, the same
    /// class of value as the Twilio account SID that round one recorded as a bad test, and
    /// the half that grants access is `aws_secret_access_key`, which IS caught wrapped,
    /// bare and inside an INI file.
    func testBase64OfACredentialIsCaughtOnceItIsLongEnough() {
        let wrappedSecret = Data("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".utf8)
            .base64EncodedString()
        XCTAssertFalse(SecretRedactor.redact(wrappedSecret).contains(wrappedSecret),
                       "base64 of an AWS secret access key line leaked: \(wrappedSecret)")

        let wrappedAnthropic = Data("sk-ant-api03-ABCDEF0123456789abcdef".utf8).base64EncodedString()
        XCTAssertFalse(SecretRedactor.redact(wrappedAnthropic).contains(wrappedAnthropic),
                       "base64 of an Anthropic key leaked: \(wrappedAnthropic)")

        let doubled = Data(wrappedAnthropic.utf8).base64EncodedString()
        XCTAssertFalse(SecretRedactor.redact(doubled).contains(doubled),
                       "double base64 of an Anthropic key leaked")

        // The documented survivor, pinned so that a future widening of the entropy floor
        // is a deliberate decision rather than a surprise.
        let wrappedIdentifier = Data("AKIAIOSFODNN7EXAMPLE".utf8).base64EncodedString()
        XCTAssertEqual(wrappedIdentifier.count, 28,
                       "fixture drifted, the point of it is that it is under the 40 character floor")
    }

    // MARK: - SecretRedactor, family 10: the matcher limit, stated rather than implied

    /// A credential broken across two lines survives its second half, and that is the
    /// README's caveat rather than a defect: "It is a matcher, not a parser, so it cannot
    /// catch a secret that does not look like one." Half a token does not look like one.
    ///
    /// This is pinned because the FIRST half is redacted, which is the shape most likely
    /// to be mistaken for coverage when somebody eyeballs the output. Seeing
    /// `[REDACTED:ANTHROPIC_KEY]` at the end of a line reads as a win, and the rest of the
    /// key is sitting on the line below.
    func testTheMatcherLimitOnCredentialsSplitAcrossLines() {
        let wrapped = "The key is sk-ant-api03-ABCDEF012\n3456789abcdefghij"
        let out = SecretRedactor.redact(wrapped)
        XCTAssertTrue(out.contains("[REDACTED:ANTHROPIC_KEY]"), "the first half must still be caught")
        XCTAssertTrue(out.contains("3456789abcdefghij"),
                      "if the tail is now caught, a parser was added and this limit note is stale")
    }

    /// Single case hex and UUIDs are deliberately spared, and this pins WHY so that a
    /// future round does not read them as misses.
    ///
    /// A 40 character lowercase hex run is a git SHA. A 32 character one is an md5 sum. A
    /// UUID is an object identifier that appears in every log line an agent reads.
    /// Redacting them bare would destroy far more than it protects, so the library
    /// requires mixed case AND digits, and it relies on the LABEL to catch the ones that
    /// really are credentials. Both halves are asserted here.
    func testSingleCaseHexAndUUIDsAreSparedBareAndCaughtWhenLabelled() {
        let bare = [
            "0123456789abcdef0123456789abcdef01234567",   // Datadog app key, and a git SHA
            "0123456789abcdef0123456789abcdef01234",      // Cloudflare global API key shape
            "8f2b1c4d-3e5a-4b6c-9d8e-1f2a3b4c5d6e",       // a UUID, which is also a Railway token
        ]
        for value in bare {
            XCTAssertEqual(SecretRedactor.redact(value), value,
                           "a bare single case identifier was redacted, which destroys git SHAs: \(value)")
            for name in ["DD_APP_KEY", "CF_API_KEY", "RAILWAY_TOKEN"] {
                XCTAssertFalse(SecretRedactor.redact("\(name)=\(value)").contains(value),
                               "the label did not save \(name)=\(value)")
            }
        }
    }
}
