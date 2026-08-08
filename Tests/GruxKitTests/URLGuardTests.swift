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
        // The denial is structural, so it is reported as such rather than as a
        // private-network hit.
        XCTAssertEqual(URLGuard.evaluate("http://127.0.0.1%00.example.com/").tag, "URL_DENIED")
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
