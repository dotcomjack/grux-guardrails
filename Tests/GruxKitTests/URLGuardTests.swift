// █ dcj · dotcomjack.com · MIT
import XCTest
@testable import GruxKit

/// Table-driven coverage for the URL policy. Drives the pure
/// `URLGuard.evaluate(_:config:)` with explicit configs, so there is no disk and no
/// global state anywhere in this file.
final class URLGuardTests: XCTestCase {

    private let defaults = URLGuardConfig()

    private func isAllowed(_ url: String, config: URLGuardConfig? = nil) -> Bool {
        URLGuard.evaluate(url, config: config ?? defaults).isAllowed
    }

    // MARK: - Default policy table

    func testDefaultPolicyTable() {
        let table: [(url: String, allowed: Bool)] = [
            // Ordinary public web: allowed
            ("https://example.com/page", true),
            ("https://www.anthropic.com", true),
            ("http://news.ycombinator.com/item?id=1", true),
            // Schemes other than http/https: denied
            ("file:///etc/passwd", false),
            ("javascript:alert(1)", false),
            ("data:text/html,hello", false),
            ("chrome://settings", false),
            // Credential-bearing: denied
            ("http://user:pass@example.com/", false),
            ("https://admin@example.com/", false),
            // Loopback and localhost: denied
            ("http://localhost:3000", false),
            ("http://127.0.0.1:8080/", false),
            ("http://[::1]/", false),
            // Private IPv4 ranges: denied
            ("http://10.0.0.1/", false),
            ("http://192.168.1.5/admin", false),
            ("http://172.16.0.1/", false),
            ("http://172.20.3.4/", false),
            ("http://172.31.255.255/", false),
            ("http://169.254.10.10/", false),
            ("http://100.100.1.1/", false),     // carrier-grade NAT, also tailnet range
            ("http://0.0.0.0/", false),
            // 172.x outside the /12 is public: allowed
            ("http://172.32.0.1/", true),
            ("http://172.15.0.1/", true),
            // mDNS and bare intranet hostnames: denied
            ("http://something.local/", false),
            ("http://intranet/", false),
            ("http://router/", false),
            // Junk: denied
            ("", false),
            ("not a url at all", false)
        ]
        for row in table {
            let decision = URLGuard.evaluate(row.url, config: defaults)
            XCTAssertEqual(decision.isAllowed, row.allowed,
                           "URL '\(row.url)' expected allowed=\(row.allowed), got \(decision)")
        }
    }

    /// The shipped default trusts nothing on the local network. Somebody else's laptop
    /// should not inherit a hole named after our hardware.
    func testNoLANHostsAreTrustedByDefault() {
        XCTAssertTrue(defaults.trustedLANHosts.isEmpty)
        XCTAssertFalse(isAllowed("http://media-server:8096/"))
    }

    /// `trustedLANHosts` is exact-match, `allowlist` matches subdomains too. Both are
    /// demonstrated against a `.local` host, which the default policy denies, so the
    /// difference between the two lists is actually visible.
    func testTrustedLANHostsAreExactMatchButAllowlistIsNot() {
        let exact = URLGuardConfig(trustedLANHosts: ["box.local"])
        XCTAssertTrue(isAllowed("http://box.local:8096/library", config: exact))
        XCTAssertFalse(isAllowed("http://sub.box.local/", config: exact))

        let suffix = URLGuardConfig(allowlist: ["box.local"])
        XCTAssertTrue(isAllowed("http://box.local:8096/library", config: suffix))
        XCTAssertTrue(isAllowed("http://sub.box.local/", config: suffix))
    }

    /// A documented limitation, pinned so it cannot change silently.
    ///
    /// The guard denies bare single-label hostnames ("router", "intranet") because those
    /// can only resolve through a local search domain. It cannot deny a dotted name with
    /// a made-up TLD ("sub.media-server", "host.corp"), because that is textually
    /// indistinguishable from an ordinary public domain without a resolver or a
    /// public-suffix list, and this evaluator is deliberately pure and offline.
    ///
    /// If your network hands out dotted internal names, put them on the denylist. Do not
    /// assume the default posture covers them.
    func testDottedInternalNamesAreNotCaughtByDefault() {
        XCTAssertTrue(isAllowed("http://sub.media-server/"))
        XCTAssertTrue(isAllowed("http://host.corp/"))
        // The denylist is the supported answer.
        let config = URLGuardConfig(denylist: ["media-server", "corp"])
        XCTAssertFalse(isAllowed("http://sub.media-server/", config: config))
        XCTAssertFalse(isAllowed("http://host.corp/", config: config))
    }

    // MARK: - Denylist

    func testDenylistBlocksHostAndSubdomains() {
        let config = URLGuardConfig(denylist: ["evil.com"])
        XCTAssertFalse(isAllowed("https://evil.com/x", config: config))
        XCTAssertFalse(isAllowed("https://sub.evil.com/", config: config))
        // Suffix matching is segment-aware: notevil.com is a different host.
        XCTAssertTrue(isAllowed("https://notevil.com/", config: config))
    }

    func testTrailingDotCannotBypassDenylist() {
        // "evil.com." resolves identically to "evil.com", so the dot must be normalized
        // BEFORE denylist matching, not just in the private-network checks that run last.
        let config = URLGuardConfig(denylist: ["evil.com"])
        XCTAssertFalse(isAllowed("https://evil.com./x", config: config))
        XCTAssertFalse(isAllowed("https://sub.evil.com./", config: config))
    }

    func testTrailingDotStillMatchesAllowlist() {
        let config = URLGuardConfig(allowlist: ["mything.local"])
        XCTAssertTrue(isAllowed("http://mything.local./status", config: config))
    }

    func testDenylistBeatsAllowlist() {
        let config = URLGuardConfig(allowlist: ["both.com"], denylist: ["both.com"])
        XCTAssertFalse(isAllowed("https://both.com/", config: config))
    }

    func testDenylistCanBlockTrustedLANHost() {
        let config = URLGuardConfig(denylist: ["media-server"], trustedLANHosts: ["media-server"])
        XCTAssertFalse(isAllowed("http://media-server:8096/", config: config))
    }

    // MARK: - Allowlist

    func testAllowlistOverridesPrivateNetworkDenials() {
        let config = URLGuardConfig(allowlist: ["mything.local", "192.168.1.50"])
        XCTAssertTrue(isAllowed("http://mything.local/status", config: config))
        XCTAssertTrue(isAllowed("http://192.168.1.50:8080/", config: config))
        // Other private hosts stay denied.
        XCTAssertFalse(isAllowed("http://other.local/", config: config))
        XCTAssertFalse(isAllowed("http://192.168.1.51/", config: config))
    }

    func testAllowlistNeverOverridesCredentialCheck() {
        let config = URLGuardConfig(allowlist: ["example.com"])
        XCTAssertFalse(isAllowed("https://user:secret@example.com/", config: config))
    }

    func testAllowlistMatchesSubdomains() {
        let config = URLGuardConfig(allowlist: ["corp.example"])
        XCTAssertTrue(isAllowed("https://api.corp.example/", config: config))
    }

    // MARK: - IPv6 smuggling and non-canonical IPv4 spellings

    func testIPv4MappedIPv6CannotReachPrivateTargets() {
        // IPv4-mapped IPv6 loopback and private, in both dotted and hex spellings.
        XCTAssertFalse(isAllowed("http://[::ffff:127.0.0.1]/"))
        XCTAssertFalse(isAllowed("http://[::ffff:7f00:1]/"))
        XCTAssertFalse(isAllowed("http://[::ffff:10.0.0.1]/"))
        XCTAssertFalse(isAllowed("http://[::ffff:192.168.1.5]/"))
        XCTAssertFalse(isAllowed("http://[::ffff:169.254.169.254]/")) // cloud metadata
        XCTAssertFalse(isAllowed("http://[64:ff9b::7f00:1]/"))        // NAT64 loopback
        // Embedded PUBLIC IPv4 stays allowed.
        XCTAssertTrue(isAllowed("http://[::ffff:8.8.8.8]/"))
    }

    func testIPv6Classification() {
        XCTAssertTrue(isAllowed("http://[2606:4700::6810:84e5]/")) // public
        XCTAssertFalse(isAllowed("http://[fe80::1]/"))             // link-local
        XCTAssertFalse(isAllowed("http://[fd00::1]/"))             // unique-local
        XCTAssertFalse(isAllowed("http://[ff02::1]/"))             // multicast
        XCTAssertFalse(isAllowed("http://[::]/"))                  // unspecified
    }

    func testNonCanonicalIPv4SpellingsAreDenied() {
        XCTAssertFalse(isAllowed("http://0177.0.0.1/"))  // octal octet, resolves to 127
        XCTAssertFalse(isAllowed("http://0x7f.0.0.1/"))  // hex octet
        XCTAssertFalse(isAllowed("http://127.1/"))       // two-part shorthand
        XCTAssertFalse(isAllowed("http://2130706433/"))  // bare 32-bit integer
        XCTAssertFalse(isAllowed("http://127.0.0.1./"))  // trailing-dot FQDN spelling
        XCTAssertFalse(isAllowed("http://localhost./"))
        // Canonical public IPv4 is unaffected.
        XCTAssertTrue(isAllowed("http://8.8.8.8/"))
    }

    // MARK: - Percent-decoded host smuggling

    /// Regression, found by adversarial probing before the first public release.
    ///
    /// `URL.host` percent-decodes, so these arrive as hosts containing a literal NUL
    /// byte or a literal slash. Both used to parse as ordinary multi-label names and
    /// were ALLOWED, while any resolver that truncates at NUL reads them as plain
    /// loopback. Structural validation of the decoded host is what closes it.
    func testPercentDecodedHostCannotSmuggleALoopbackTarget() {
        XCTAssertFalse(isAllowed("http://127.0.0.1%00.example.com/"))
        XCTAssertFalse(isAllowed("http://127.0.0.1%2f.example.com/"))
        XCTAssertFalse(isAllowed("http://127.0.0.1%09.example.com/"))
        XCTAssertFalse(isAllowed("http://169.254.169.254%00.example.com/"))
        // This assertion used to read `"URL_DENIED"`, with a comment reasoning that the
        // denial is structural rather than a private-network hit. That reasoning is
        // correct and the conclusion was still wrong: it pinned the most attack-shaped
        // signal the guard emits into the same audit bucket as "empty URL", and
        // README.md line 142 tells you to alert on the tag. Someone deliberately
        // smuggling a loopback target past the parser deserves its own label, not the
        // one that means nothing happened.
        XCTAssertEqual(URLGuard.evaluate("http://127.0.0.1%00.example.com/").tag, "HOST_SMUGGLING")
    }

    /// Percent-decoding that produces a perfectly ordinary host is fine, and must stay
    /// fine, because over-denying here would break real URLs. `evil%2ecom` decodes to
    /// `evil.com` and is then matched by the denylist on its decoded form, which is the
    /// behaviour we want.
    func testHarmlessPercentDecodingStillWorks() {
        XCTAssertTrue(isAllowed("http://evil%2ecom/"))
        XCTAssertFalse(isAllowed("http://evil%2ecom/", config: URLGuardConfig(denylist: ["evil.com"])))
    }

    /// Non-ASCII hosts are NOT structurally illegal. A unicode homograph is a phishing
    /// problem, not a network-reachability one, and denying it here would be a false
    /// positive in a guard that is only supposed to answer "can this reach my LAN".
    func testUnicodeHostsAreNotRejectedByStructuralValidation() {
        XCTAssertTrue(isAllowed("http://ex\u{0430}mple.com/"))   // cyrillic a
        XCTAssertTrue(isAllowed("http://xn--80ak6aa92e.com/"))   // punycode
    }

    // MARK: - List canonicalisation

    /// Regression, and the nastiest class of bug a denylist can have: it fails OPEN.
    /// Entries used to be trimmed with `.whitespaces`, which excludes newlines, and were
    /// never stripped of a trailing dot. So a perfectly reasonable-looking entry matched
    /// nothing at all and the call site had no way to tell.
    func testDenylistEntriesAreCanonicalisedLikeHosts() {
        let spellings = ["evil.com.", " evil.com ", "evil.com\n", "EVIL.COM", ".evil.com", "\tevil.com\t"]
        for entry in spellings {
            let config = URLGuardConfig(denylist: [entry])
            XCTAssertFalse(isAllowed("https://evil.com/", config: config),
                           "denylist entry \(entry.debugDescription) failed OPEN")
            XCTAssertFalse(isAllowed("https://sub.evil.com/", config: config),
                           "subdomain slipped past entry \(entry.debugDescription)")
        }
    }

    func testTrustedLANHostsAreCanonicalisedToo() {
        for entry in ["Box.local", " box.local ", "box.local.", "BOX.LOCAL"] {
            let config = URLGuardConfig(trustedLANHosts: [entry])
            XCTAssertTrue(isAllowed("http://box.local/", config: config),
                          "trusted entry \(entry.debugDescription) silently did nothing")
        }
    }

    func testAllowlistEntriesAreCanonicalised() {
        let config = URLGuardConfig(allowlist: ["Corp.Example.\n"])
        XCTAssertTrue(isAllowed("https://api.corp.example/", config: config))
    }

    /// Regression. `URL.host` is already punycoded, so an internationalized denylist
    /// entry was compared raw against "xn--r8jz45g.jp" and matched nothing. The entry
    /// failed OPEN while looking perfectly correct at the call site, which is the same
    /// bug class the canonicalisation fix was written to eliminate.
    func testInternationalizedDenylistEntriesMatch() {
        let config = URLGuardConfig(denylist: ["例え.jp"])
        XCTAssertFalse(isAllowed("https://例え.jp/", config: config))
        XCTAssertFalse(isAllowed("https://xn--r8jz45g.jp/", config: config))
        XCTAssertFalse(isAllowed("https://sub.例え.jp/", config: config))
    }

    /// Regression. canonicalEntry("") and canonicalEntry(".") both reduce to "", so
    /// without a guard a blank line in a config file becomes a trusted-host entry.
    func testBlankTrustedLANEntriesMatchNothing() {
        // The last five are new ways to reduce to empty, added when canonicalEntry
        // learned to strip schemes, ports, paths and wildcards. Every new stripping rule
        // is a new way for an entry to collapse to "", and an entry that collapses to ""
        // would match an empty host, so the guard has to be re-tested each time rather
        // than assumed to still hold.
        for junk in ["", ".", "  ", "\n", "...", "*", "*.", "https://", "://", "/path"] {
            let config = URLGuardConfig(trustedLANHosts: [junk])
            XCTAssertFalse(isAllowed("http://127.0.0.1/", config: config))
            XCTAssertFalse(isAllowed("http://router/", config: config))
        }
    }

    /// Regression. The IPv4 table grew but `tag` did not, so the newest SSRF denials
    /// reported as generic URL_DENIED. An alert keyed on PRIVATE_NETWORK, which is what
    /// the README tells you to log, silently stopped seeing them.
    func testEveryPrivateNetworkDenialCarriesThePrivateNetworkTag() {
        let shouldBePrivate = [
            "http://192.0.0.192/", "http://255.255.255.255/", "http://224.0.0.1/",
            "http://0.1.2.3/", "http://198.18.0.1/", "http://192.0.2.1/",
            "http://203.0.113.1/", "http://240.0.0.1/", "http://[fec0::1]/",
            "http://[2002:7f00:1::]/", "http://192.168.1.1/", "http://localhost/",
        ]
        for u in shouldBePrivate {
            XCTAssertEqual(URLGuard.evaluate(u).tag, "PRIVATE_NETWORK", "wrong tag for \(u)")
        }
    }

    // MARK: - The rest of the special-purpose registry

    /// Everything outside the covered ranges is treated as public internet, so anything
    /// missing here is reachable. 192.0.0.192 is Oracle Cloud's metadata endpoint, the
    /// same class of target as 169.254.169.254, and it was allowed while that one was
    /// correctly denied.
    func testSpecialPurposeIPv4RangesAreDenied() {
        let denied = [
            "http://192.0.0.192/",        // Oracle Cloud metadata
            "http://192.0.2.1/",          // TEST-NET-1
            "http://198.18.0.1/",         // benchmark
            "http://198.51.100.1/",       // TEST-NET-2
            "http://203.0.113.1/",        // TEST-NET-3
            "http://224.0.0.1/",          // multicast
            "http://239.255.255.250/",    // SSDP multicast
            "http://240.0.0.1/",          // reserved
            "http://255.255.255.255/",    // broadcast
            "http://0.1.2.3/",            // this-network
        ]
        for u in denied {
            XCTAssertFalse(isAllowed(u), "should be denied: \(u)")
        }
        // Neighbouring public addresses stay allowed, so the ranges are not overbroad.
        for u in ["http://192.0.1.1/", "http://198.20.0.1/", "http://223.255.255.1/", "http://204.0.113.1/"] {
            XCTAssertTrue(isAllowed(u), "should stay allowed: \(u)")
        }
    }

    /// 6to4 is the fourth member of the embedded-IPv4 family and was the one missing, so
    /// 2002:7f00:1:: reached loopback while ::ffff:127.0.0.1 was denied.
    func test6to4AndSiteLocalIPv6AreDenied() {
        XCTAssertFalse(isAllowed("http://[2002:7f00:1::]/"))        // 6to4 -> 127.0.0.1
        XCTAssertFalse(isAllowed("http://[2002:c0a8:105::]/"))      // 6to4 -> 192.168.1.5
        XCTAssertFalse(isAllowed("http://[2002:a9fe:a9fe::]/"))     // 6to4 -> 169.254.169.254
        XCTAssertFalse(isAllowed("http://[fec0::1]/"))              // site-local
        // 6to4 wrapping a public IPv4 is still fine.
        XCTAssertTrue(isAllowed("http://[2002:0808:0808::]/"))      // 6to4 -> 8.8.8.8
    }

    // MARK: - Case handling

    func testHostMatchingIsCaseInsensitive() {
        let config = URLGuardConfig(denylist: ["evil.com"])
        XCTAssertFalse(isAllowed("https://EVIL.com/", config: config))
        XCTAssertFalse(isAllowed("HTTPS://sub.Evil.COM/", config: config))
    }

    // MARK: - Denial tags

    func testDenialsCarryACoarseTag() {
        XCTAssertEqual(URLGuard.evaluate("file:///etc/passwd").tag, "BAD_SCHEME")
        XCTAssertEqual(URLGuard.evaluate("http://user:pass@example.com/").tag, "CREDENTIAL_URL")
        XCTAssertEqual(URLGuard.evaluate("http://192.168.1.5/").tag, "PRIVATE_NETWORK")
        XCTAssertEqual(
            URLGuard.evaluate("https://evil.com/", config: URLGuardConfig(denylist: ["evil.com"])).tag,
            "USER_DENYLIST")
        XCTAssertNil(URLGuard.evaluate("https://example.com/").tag)
    }
}

extension URLGuardTests {
    /// RFC 8215 local-use NAT64 prefix. Only the RFC 6052 well-known prefix was decoded,
    /// so 64:ff9b:1::7f00:1 reached loopback on any host running a local NAT64.
    func testNAT64LocalUsePrefixIsDecoded() {
        XCTAssertFalse(URLGuard.evaluate("http://[64:ff9b:1::7f00:1]/").isAllowed)
        XCTAssertFalse(URLGuard.evaluate("http://[64:ff9b:1::a9fe:a9fe]/").isAllowed)
        XCTAssertFalse(URLGuard.evaluate("http://[64:ff9b::7f00:1]/").isAllowed)
        // Wrapping a public IPv4 stays allowed through either prefix.
        XCTAssertTrue(URLGuard.evaluate("http://[64:ff9b:1::0808:0808]/").isAllowed)
    }
}

extension URLGuardTests {
    /// The IP rules already denied 169.254.169.254, but the NAME is the form that
    /// actually appears in prompts, docs and SDK samples. Blocking only the numeric
    /// spelling blocks the one nobody types.
    func testCloudAndContainerMetadataHostnamesAreDenied() {
        for h in ["http://metadata.google.internal/computeMetadata/v1/",
                  "http://metadata.goog/", "http://metadata/",
                  "http://host.docker.internal:8080/", "http://gateway.docker.internal/",
                  "http://instance-data/", "http://kubernetes.default.svc/api/"] {
            XCTAssertFalse(URLGuard.evaluate(h).isAllowed, "reachable: \(h)")
            XCTAssertEqual(URLGuard.evaluate(h).tag, "PRIVATE_NETWORK", "wrong tag: \(h)")
        }
        // A real public host that merely contains one of those words stays allowed.
        XCTAssertTrue(URLGuard.evaluate("https://metadata.example.com/").isAllowed)
        XCTAssertTrue(URLGuard.evaluate("https://internal.example.com/").isAllowed)
    }

    /// The reason-to-tag mapping, pinned as a table.
    ///
    /// `tag` is derived by searching the reason string for needles, which is a
    /// hand-maintained list, and it has now silently fallen behind TWICE. First when the
    /// IPv4 table grew and the new reasons reported as generic URL_DENIED. Then again
    /// with `illegal character in host`, which is the null-byte smuggling denial and the
    /// most attack-shaped signal the guard produces: it sat in the same bucket as
    /// "empty URL" while README.md line 142 tells you to alert on the tag.
    ///
    /// A needle list cannot defend itself. This table can, so every new denial reason has
    /// to be added here, and landing in URL_DENIED by accident now fails the build.
    func testEveryDenialReasonLandsOnTheIntendedTag() {
        let table: [(url: String, tag: String)] = [
            ("http://user:pass@example.com/", "CREDENTIAL_URL"),
            ("file:///etc/passwd",            "BAD_SCHEME"),
            ("javascript:alert(1)",           "BAD_SCHEME"),
            ("http://127.0.0.1%00.example.com/", "HOST_SMUGGLING"),
            ("http://127.0.0.1",              "PRIVATE_NETWORK"),
            ("http://10.0.0.5",               "PRIVATE_NETWORK"),
            ("http://192.168.1.1",            "PRIVATE_NETWORK"),
            ("http://169.254.169.254/",       "PRIVATE_NETWORK"),
            ("http://192.0.0.192/",           "PRIVATE_NETWORK"),
            ("http://100.64.0.1/",            "PRIVATE_NETWORK"),
            ("http://224.0.0.1/",             "PRIVATE_NETWORK"),
            ("http://255.255.255.255/",       "PRIVATE_NETWORK"),
            ("http://0.0.0.0/",               "PRIVATE_NETWORK"),
            ("http://0177.0.0.1",             "PRIVATE_NETWORK"),
            ("http://router/",                "PRIVATE_NETWORK"),
            ("http://nas.local/",             "PRIVATE_NETWORK"),
            ("http://metadata.google.internal/", "PRIVATE_NETWORK"),
            ("http://[::1]/",                 "PRIVATE_NETWORK"),
            ("http://[fd00::1]/",             "PRIVATE_NETWORK"),
            ("http://[fe80::1]/",             "PRIVATE_NETWORK"),
            ("http://[2002:7f00:1::]/",       "PRIVATE_NETWORK"),
            ("http://[64:ff9b::7f00:1]/",     "PRIVATE_NETWORK"),
            ("http://[64:ff9b:1::7f00:1]/",   "PRIVATE_NETWORK"),
        ]
        for (url, expected) in table {
            let d = URLGuard.evaluate(url)
            XCTAssertFalse(d.isAllowed, "should be denied: \(url)")
            XCTAssertEqual(d.tag, expected, "wrong tag for \(url): \(String(describing: d))")
        }
        // The generic bucket is for genuinely uninteresting denials, and only those.
        for url in ["", "http:///path"] {
            XCTAssertEqual(URLGuard.evaluate(url).tag, "URL_DENIED", "unexpected tag for \(String(reflecting: url))")
        }
    }

    /// A denylist fails OPEN when it fails to match, so every plausible way a person
    /// writes a host has to reduce to the same entry. Each of these blocked NOTHING while
    /// looking correct in a config file.
    func testDenylistEntriesSurviveTheWayPeopleActuallyWriteThem() {
        for entry in ["evil.com", "EVIL.COM", "evil.com.", " evil.com \n", ".evil.com",
                      "https://evil.com", "http://evil.com/path", "evil.com:443",
                      "evil.com/path", "*.evil.com", "*evil.com", "https://evil.com:443/x?y=1"] {
            let cfg = URLGuardConfig(denylist: [entry])
            XCTAssertFalse(URLGuard.evaluate("http://evil.com/", config: cfg).isAllowed,
                           "denylist entry blocked nothing: \(String(reflecting: entry))")
            XCTAssertFalse(URLGuard.evaluate("http://sub.evil.com/", config: cfg).isAllowed,
                           "subdomain reachable via entry: \(String(reflecting: entry))")
        }
        // And none of that may start blocking a host that merely looks similar.
        let cfg = URLGuardConfig(denylist: ["*.evil.com"])
        XCTAssertTrue(URLGuard.evaluate("http://notevil.com/", config: cfg).isAllowed)
        XCTAssertTrue(URLGuard.evaluate("http://evil.com.attacker.net/", config: cfg).isAllowed)
    }

    /// The README documents the tag vocabulary and tells the reader to alert on it, so
    /// the code must not be able to emit a tag the README does not name. Reads the real
    /// file rather than a copy, because a copy drifts and a mirror test that mirrors
    /// nothing is decoration. Same shape as the pattern-count test in the redactor suite,
    /// which caught a real drift the moment a provider pattern was added.
    func testEveryTagTheCodeCanEmitIsDocumentedInTheReadme() throws {
        let readme = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("README.md"),
            encoding: .utf8)
        // Every tag the switch in URLGuardDecision.tag can return.
        let emitted = ["PRIVATE_NETWORK", "HOST_SMUGGLING", "CREDENTIAL_URL",
                       "USER_DENYLIST", "BAD_SCHEME", "URL_DENIED"]
        for tag in emitted {
            XCTAssertTrue(readme.contains("`\(tag)`"),
                          "README does not document the \(tag) tag, so nobody will alert on it")
        }
        // And each one is actually reachable, so the table documents no ghosts.
        let reachable = Set([
            "http://127.0.0.1", "http://127.0.0.1%00.example.com/",
            "http://user:pass@example.com/", "file:///etc/passwd", "", "http://x.evil.com/",
        ].map { URLGuard.evaluate($0, config: URLGuardConfig(denylist: ["evil.com"])).tag ?? "nil" })
        XCTAssertEqual(reachable, Set(emitted), "tag table and reachable tags disagree")
    }

    /// A bare `0x` label with no digits after it. The hex check required more than two
    /// characters, so `0x` was neither decimal nor hex, the whole host was judged
    /// non-numeric and fell through to ALLOWED. `inet_aton` reads a bare `0x` as zero,
    /// which was confirmed with getaddrinfo(AI_NUMERICHOST): the OS parses `127.0.0x.1`
    /// as an IP literal, so this reached loopback.
    func testBareHexLabelIsNotAnEscapeHatch() {
        for h in ["http://127.0.0x.1/", "http://0x.0x.0x.0x/", "http://0x.1/",
                  "http://127.0x0.0x0.1/"] {
            XCTAssertFalse(URLGuard.evaluate(h).isAllowed, "reachable: \(h)")
        }
        // A real domain whose label merely begins with those characters is not an IP.
        XCTAssertTrue(URLGuard.evaluate("https://0xdeadbeef.example.com/").isAllowed)
        XCTAssertTrue(URLGuard.evaluate("https://0x.io/").isAllowed)
    }

    /// Wildcard resolvers answer `<anything>.10.0.0.1.nip.io` with 10.0.0.1, which turns
    /// any private address into an ordinary public-looking domain. The metadata table
    /// already carried `169.254.169.254.nip.io`, so the technique was known and exactly
    /// one instance of it was blocked while the general shape was not.
    func testHostnamesEmbeddingAPrivateAddressAreDenied() {
        for h in ["http://127.0.0.1.nip.io/", "http://10.0.0.1.sslip.io/",
                  "http://192.168.1.1.xip.io/", "http://169.254.169.254.sslip.io/",
                  "http://foo.127.0.0.1.nip.io/", "http://10-0-0-1.nip.io/",
                  "http://127-0-0-1.nip.io/", "http://127.0.0.1.example.com/"] {
            XCTAssertFalse(URLGuard.evaluate(h).isAllowed, "reachable: \(h)")
            XCTAssertEqual(URLGuard.evaluate(h).tag, "PRIVATE_NETWORK", "wrong tag: \(h)")
        }
        // A PUBLIC address in the labels is not a private-network hit, and ordinary
        // hostnames that merely contain numbers must not be swept up. Over-denying here
        // would be paid on every version-numbered and dated subdomain in existence.
        for h in ["https://8.8.8.8.nip.io/", "https://1.2.3.4.example.com/",
                  "https://v1.2.3.4.example.com/", "https://2026.08.09.example.com/",
                  "https://a1-b2-c3-d4.example.com/", "https://192.0.example.com/"] {
            XCTAssertTrue(URLGuard.evaluate(h).isAllowed, "wrongly denied: \(h)")
        }
    }

    /// RFC 6052 puts the embedded IPv4 in a different place for every prefix length. Only
    /// the /96 position was read, so a public decoy in the tail hid the real target where
    /// the standard actually puts it for a /48.
    func testNAT64LocalUsePrefixDecodesTheRFC6052SlotForIts48() {
        XCTAssertFalse(URLGuard.evaluate("http://[64:ff9b:1:7f00:0:1:808:808]/").isAllowed,
                       "loopback at the /48 slot reached, with a public decoy in the tail")
        XCTAssertFalse(URLGuard.evaluate("http://[64:ff9b:1:0a00:0:1:808:808]/").isAllowed)
        // The /96 form with an empty /48 slot is not a /48 embedding of 0.0.0.0, and a
        // public address wrapped in the local-use prefix must stay allowed.
        XCTAssertTrue(URLGuard.evaluate("http://[64:ff9b:1::0808:0808]/").isAllowed)
    }

    /// The attacker picked the audit label. `evaluate` interpolates the scheme into its
    /// own denial reason, and `tag` scanned that reason for substrings, so a URL with the
    /// scheme `denylist:` reported as USER_DENYLIST and `credential:` as CREDENTIAL_URL.
    /// Anyone counting denial classes was reading numbers hostile input could move.
    func testAttackerChosenSchemeCannotSteerTheAuditTag() {
        for scheme in ["denylist", "credential", "loopback", "metadata", "private",
                       "multicast", "intranet", "unparseable"] {
            XCTAssertEqual(URLGuard.evaluate("\(scheme)://x/").tag, "BAD_SCHEME",
                           "scheme \(scheme) steered the tag")
        }
    }

    /// `unparseable URL` contains `unparseable`, a needle added for the IPv6 literal case,
    /// so an ordinary malformed URL reported as PRIVATE_NETWORK and inflated the count of
    /// the one tag the README tells you to alert on.
    func testMalformedURLsAreNotReportedAsPrivateNetworkHits() {
        for u in ["http://[not-an-ipv6/", "ht tp://x", "http://%%%/"] {
            XCTAssertEqual(URLGuard.evaluate(u).tag, "URL_DENIED", "wrong tag for \(u)")
        }
    }

    /// `evaluate` stripped ONE trailing dot while `canonicalEntry` stripped all of them,
    /// and the two never compared equal, so a second dot walked past the denylist. Same
    /// class as the single trailing dot the strip was written to fix, reintroduced by
    /// fixing only one side of the comparison.
    func testRepeatedTrailingDotsCannotBypassTheDenylist() {
        let cfg = URLGuardConfig(denylist: ["evil.com"])
        for u in ["http://evil.com/", "http://evil.com./", "http://evil.com../",
                  "http://evil.com.../", "http://sub.evil.com../"] {
            XCTAssertFalse(URLGuard.evaluate(u, config: cfg).isAllowed, "bypassed: \(u)")
        }
    }

    /// An unbracketed IPv6 entry has many colons and no port. Stripping at the last one
    /// would truncate the address into a different, possibly public, one.
    func testIPv6DenylistEntriesAreNotTruncatedByThePortStripper() {
        let cfg = URLGuardConfig(trustedLANHosts: ["fd00::1"])
        XCTAssertTrue(URLGuard.evaluate("http://[fd00::1]/", config: cfg).isAllowed,
                      "a bare IPv6 trusted-host entry stopped matching")
    }
}
