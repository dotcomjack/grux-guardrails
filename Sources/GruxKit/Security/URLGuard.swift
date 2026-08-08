import Foundation

/// Allow and deny policy for every URL the agent is asked to open or fetch.
///
/// The threat is server-side request forgery with a language model as the confused
/// deputy. Your agent runs on your laptop, inside your network, and it will follow a
/// link that appeared in a web page, an email, or its own hallucination. `http://169.254.169.254/`
/// is the cloud metadata endpoint. `http://router/` is your router's admin panel.
/// Neither looks alarming in a prompt.
///
/// Default posture:
/// - `http` and `https` only. `file:`, `javascript:`, `data:` and `chrome:` are denied.
/// - Credential-bearing URLs (`user:pass@host`) are always denied, with no override.
/// - Loopback, private ranges, link-local, carrier-grade NAT, `.local` mDNS and bare
///   single-label intranet hostnames are denied.
/// - The caller's allowlist and denylist match a host and all of its subdomains.
///   Denylist beats allowlist.
///
/// Decision order: parse and scheme, then credentials, then denylist, then trusted LAN
/// hosts, then allowlist, then the private-network checks, then allow.
///
/// The interesting work is in the last step, because "is this address private" has more
/// wrong answers than right ones. `0177.0.0.1`, `0x7f.0.0.1`, `127.1` and `2130706433`
/// are all loopback to the system resolver and none of them survive a naive dotted-quad
/// parse. `::ffff:169.254.169.254` is the metadata endpoint wearing an IPv6 costume.
/// A single trailing dot (`evil.com.`) resolves identically to the bare name but is a
/// different string, so it must be normalized before any list comparison, not after.
/// Every one of those is a test case.
///
/// `evaluate(_:config:)` is pure and synchronous, which is what makes the policy
/// table-testable. Wire your own auditing around it.
public enum URLGuardDecision: Equatable, Sendable {
    case allowed
    case denied(reason: String)

    public var isAllowed: Bool {
        if case .allowed = self { return true }
        return false
    }

    /// Coarse category for the denial, suitable for an audit log or a metric label.
    public var tag: String? {
        guard case .denied(let reason) = self else { return nil }
        if reason.contains("credential") { return "CREDENTIAL_URL" }
        if reason.contains("denylist") { return "USER_DENYLIST" }
        if reason.contains("scheme") { return "BAD_SCHEME" }
        // Every reason produced by privateNetworkReason has to land here. When the IPv4
        // table grew, these strings were not updated, so Oracle Cloud metadata and the
        // broadcast address reported as generic URL_DENIED. An alert keyed on
        // PRIVATE_NETWORK, which is what the README tells you to log, silently stopped
        // seeing the newest SSRF denials.
        for needle in ["loopback", "private", "link-local", ".local", "intranet", "NAT",
                       "unspecified", "ambiguous", "multicast", "unparseable", "site-local",
                       "this-network", "protocol assignment", "documentation", "benchmark",
                       "reserved", "broadcast", "6to4", "IPv6"] {
            if reason.contains(needle) { return "PRIVATE_NETWORK" }
        }
        return "URL_DENIED"
    }
}

public struct URLGuardConfig: Equatable, Sendable {
    /// Hosts (and their subdomains) that bypass the private-network checks.
    public var allowlist: [String]
    /// Hosts (and their subdomains) that are always denied. Beats everything below
    /// the credential check.
    public var denylist: [String]
    /// Exact-match hosts on your own network that should stay reachable, for example a
    /// local model server or a media box.
    ///
    /// Empty by default, deliberately. A shipped default here would be a hole in
    /// somebody else's network, not a convenience, so name your own.
    public var trustedLANHosts: [String]

    public init(allowlist: [String] = [], denylist: [String] = [], trustedLANHosts: [String] = []) {
        self.allowlist = allowlist
        self.denylist = denylist
        self.trustedLANHosts = trustedLANHosts
    }
}

public enum URLGuard {

    /// Pure policy evaluation. No I/O, no global state: this is what the test suite
    /// drives with a table.
    public static func evaluate(_ raw: String, config: URLGuardConfig = URLGuardConfig()) -> URLGuardDecision {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .denied(reason: "empty URL") }
        guard let url = URL(string: trimmed) else { return .denied(reason: "unparseable URL") }

        guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            return .denied(reason: "scheme '\(url.scheme ?? "none")' not allowed (http/https only)")
        }

        // Credential-bearing URLs are always denied, and an allowlist entry does NOT
        // override this. A user:pass@ in a URL the model composed is either a phishing
        // shape or a secret about to be written into browser history.
        if let user = url.user, !user.isEmpty {
            return .denied(reason: "credential-bearing URL")
        }
        if let pass = url.password, !pass.isEmpty {
            return .denied(reason: "credential-bearing URL")
        }

        guard let rawHost = url.host, !rawHost.isEmpty else {
            return .denied(reason: "missing host")
        }
        // A single trailing dot is a valid FQDN spelling ("evil.com.", "127.0.0.1.")
        // that resolves identically. Normalize it away BEFORE any host comparison, or
        // one appended dot walks straight past the denylist and the matching below.
        var host = rawHost.lowercased()
        if host.hasSuffix(".") { host = String(host.dropLast()) }

        // Structural validation, and it has to happen here rather than later.
        //
        // `URL.host` percent-DECODES, so "127.0.0.1%00.example.com" arrives as a host
        // containing a literal NUL byte and "127.0.0.1%2f.example.com" arrives with a
        // literal slash. Both parse as ordinary multi-label names, both sail past every
        // check below, and both are read as plain "127.0.0.1" by any resolver that
        // truncates at NUL or at the path separator. That is the classic null-byte SSRF.
        //
        // No legitimate hostname contains these characters, so fail closed rather than
        // trying to guess which downstream client will truncate where. Letters outside
        // ASCII are deliberately still permitted, because a raw unicode host is a
        // phishing concern rather than a network-reachability one and denying it here
        // would be a false positive.
        if host.unicodeScalars.contains(where: { isStructurallyIllegalInHost($0) }) {
            return .denied(reason: "illegal character in host")
        }

        // Denylist wins over everything past the credential check.
        if matches(host: host, list: config.denylist) {
            return .denied(reason: "host on user denylist")
        }

        // Trusted LAN hosts, then the allowlist, skip the private-network checks below.
        // Canonicalised like every other list, because a raw `contains` meant that the
        // one knob the README tells you that you MUST fill in yourself silently did
        // nothing if you happened to type a capital letter.
        // The `!isEmpty` guard matters: canonicalEntry("") and canonicalEntry(".") both
        // reduce to "", and without this a blank line in a config file would become a
        // trusted-host entry that matches an empty host.
        if config.trustedLANHosts.contains(where: { let e = canonicalEntry($0); return !e.isEmpty && e == host }) {
            return .allowed
        }
        if matches(host: host, list: config.allowlist) { return .allowed }

        if let reason = privateNetworkReason(host: host) {
            return .denied(reason: reason)
        }

        return .allowed
    }

    /// Characters that can never appear in a real hostname and therefore indicate
    /// smuggling: control codes including NUL, whitespace, and the delimiters that
    /// separate a host from the rest of a URL.
    ///
    /// `%` and `:` stay legal because a zone-indexed IPv6 literal ("fe80::1%en0")
    /// carries both after decoding, and that path is classified properly further down.
    private static func isStructurallyIllegalInHost(_ s: Unicode.Scalar) -> Bool {
        if s.value < 0x21 || s.value == 0x7F { return true }   // controls, NUL, space, DEL
        switch s {
        case "/", "\\", "@", "?", "#", "[", "]", "<", ">", "\"", "{", "}", "|", "^", "`":
            return true
        default:
            return false
        }
    }

    // MARK: - Host matching

    /// Entry "example.com" matches "example.com" and "sub.example.com", but not
    /// "notexample.com". The leading dot in the suffix check is what makes it
    /// segment-aware rather than a substring test.
    private static func matches(host: String, list: [String]) -> Bool {
        for entry in list {
            let e = canonicalEntry(entry)
            guard !e.isEmpty else { continue }
            if host == e { return true }
            if host.hasSuffix("." + e) { return true }
        }
        return false
    }

    /// Entries have to be canonicalised exactly the way hosts are, and a denylist makes
    /// that non-negotiable: it fails OPEN when it fails to match.
    ///
    /// The old version trimmed `.whitespaces`, which does not include newlines, and
    /// never stripped a trailing dot. So a denylist of `["evil.com."]`, or an entry read
    /// from a config file with its line ending attached, silently matched nothing at all
    /// while looking completely correct at the call site.
    private static func canonicalEntry(_ entry: String) -> String {
        var e = entry.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        while e.hasSuffix(".") { e = String(e.dropLast()) }
        while e.hasPrefix(".") { e = String(e.dropFirst()) }
        guard !e.isEmpty else { return "" }
        // Internationalized entries have to be punycoded, because `URL.host` already is.
        // A denylist of ["例え.jp"] was compared against the host "xn--r8jz45g.jp" and
        // matched nothing, so the entry failed OPEN while looking perfectly correct at
        // the call site. Round-tripping through URL performs the same IDNA conversion
        // that produced the host in the first place.
        if !e.allSatisfy({ $0.isASCII }) {
            if let punycoded = URL(string: "http://\(e)")?.host?.lowercased() {
                return punycoded
            }
        }
        return e
    }

    // MARK: - Private network detection

    private static func privateNetworkReason(host: String) -> String? {
        // The trailing-dot spelling is already normalized in evaluate(), before the
        // list matching. Strip again here so any future direct caller stays safe.
        // Idempotent.
        var host = host
        if host.hasSuffix(".") { host = String(host.dropLast()) }

        if host == "localhost" || host.hasSuffix(".localhost") { return "loopback (localhost)" }
        if host == "0.0.0.0" { return "unspecified address" }

        // IPv4 literal, strict dotted-quad decimal only.
        if let octets = ipv4Octets(host) {
            return privateIPv4Reason(octets)
        }

        // Numeric hosts that did NOT parse as strict dotted-quad decimal (octal
        // "0177.0.0.1", hex "0x7f.0.0.1", shorthand "127.1", bare integer
        // "2130706433") are resolver-dependent IP spellings. The system resolver may
        // read them as loopback or private even though they dodge the canonical parse.
        // Fail closed.
        if isNumericIPLikeHost(host) {
            return "ambiguous numeric IP literal"
        }

        // IPv6 literal. URL.host strips the brackets. Parse via inet_pton so that
        // IPv4-mapped and IPv4-compatible forms ("::ffff:127.0.0.1", hex
        // "::ffff:7f00:1") cannot smuggle a private IPv4 target past a string check.
        if host.contains(":") {
            return ipv6Reason(host)
        }

        // mDNS and Bonjour hosts are LAN by definition.
        if host.hasSuffix(".local") { return "mDNS .local host (LAN)" }

        // Bare single-label hostnames ("intranet", "router") resolve via local search
        // domains, so treat them as private.
        if !host.contains(".") { return "single-label intranet hostname" }

        return nil
    }

    /// The IANA special-purpose registry, not just RFC 1918. Everything outside this is
    /// treated as public internet, so anything missing here is reachable.
    private static func privateIPv4Reason(_ octets: (Int, Int, Int, Int)) -> String? {
        let (a, b, c, d) = octets
        if a == 0 && b == 0 && c == 0 && d == 0 { return "unspecified address" }
        if a == 0 { return "this-network IP (0.0.0.0/8)" }
        if a == 127 { return "loopback IP" }
        if a == 10 { return "private IP (10.0.0.0/8)" }
        if a == 172 && (16...31).contains(b) { return "private IP (172.16.0.0/12)" }
        if a == 192 && b == 168 { return "private IP (192.168.0.0/16)" }
        if a == 169 && b == 254 { return "link-local IP (169.254.0.0/16)" }
        if a == 100 && (64...127).contains(b) { return "carrier-grade NAT IP (100.64.0.0/10)" }
        // 192.0.0.0/24 is IETF protocol assignments, and 192.0.0.192 is Oracle Cloud's
        // metadata endpoint. Same class of target as 169.254.169.254, and it was
        // reachable while that one was blocked.
        if a == 192 && b == 0 && c == 0 { return "IETF protocol assignment (192.0.0.0/24)" }
        if a == 192 && b == 0 && c == 2 { return "documentation range (192.0.2.0/24)" }
        if a == 198 && (18...19).contains(b) { return "benchmark range (198.18.0.0/15)" }
        if a == 198 && b == 51 && c == 100 { return "documentation range (198.51.100.0/24)" }
        if a == 203 && b == 0 && c == 113 { return "documentation range (203.0.113.0/24)" }
        if (224...239).contains(a) { return "multicast IP (224.0.0.0/4)" }
        // Covers 255.255.255.255 broadcast as well as the reserved 240/4 block.
        if a >= 240 { return "reserved or broadcast IP (240.0.0.0/4)" }
        return nil // public IPv4
    }

    /// Strict dotted-quad decimal only: exactly four ASCII-digit labels with no leading
    /// zeros, each 0...255. Anything looser (octal, hex, shorthand) falls through to
    /// isNumericIPLikeHost and is denied as ambiguous.
    private static func ipv4Octets(_ host: String) -> (Int, Int, Int, Int)? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [Int] = []
        for p in parts {
            guard !p.isEmpty, p.count <= 3,
                  p.allSatisfy({ $0.isASCII && $0.isNumber }),
                  !(p.count > 1 && p.first == "0"),
                  let v = Int(p), (0...255).contains(v) else { return nil }
            octets.append(v)
        }
        return (octets[0], octets[1], octets[2], octets[3])
    }

    /// True when every dot-separated label is a number in some radix (decimal or 0x
    /// hex). Such a host can only be an IP literal, because real domains always end in
    /// a non-numeric TLD.
    private static func isNumericIPLikeHost(_ host: String) -> Bool {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        for label in labels {
            guard !label.isEmpty else { return false }
            let isDecimal = label.allSatisfy { $0.isASCII && $0.isNumber }
            let lower = label.lowercased()
            let isHex = lower.hasPrefix("0x") && lower.count > 2
                && lower.dropFirst(2).allSatisfy { $0.isASCII && $0.isHexDigit }
            if !(isDecimal || isHex) { return false }
        }
        return true
    }

    /// Byte-level IPv6 classification. Unparseable literals fail closed, and
    /// mapped, compatible and NAT64 forms are judged by their embedded IPv4 target.
    private static func ipv6Reason(_ host: String) -> String? {
        // Zone-indexed literals (fe80::1%en0) are interface-scoped. Parse the address
        // part, since a zone cannot make a private address public.
        let bare = String(host.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)[0])
        var addr = in6_addr()
        guard inet_pton(AF_INET6, bare, &addr) == 1 else {
            return "unparseable IPv6 literal"
        }
        var bytes = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: &addr) { raw in
            for i in 0..<16 { bytes[i] = raw[i] }
        }

        if bytes.allSatisfy({ $0 == 0 }) { return "unspecified IPv6" }
        if bytes[0..<15].allSatisfy({ $0 == 0 }) && bytes[15] == 1 { return "loopback IPv6" }
        if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 { return "link-local IPv6" }
        // Deprecated site-local, fec0::/10. Deprecated is not the same as unroutable:
        // stacks still resolve and connect to it.
        if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0 { return "site-local IPv6 (deprecated)" }
        if (bytes[0] & 0xfe) == 0xfc { return "unique-local IPv6" }
        if bytes[0] == 0xff { return "multicast IPv6" }

        // 6to4, 2002::/16, tunnels to the IPv4 address sitting in bytes 2 through 5.
        // It is the fourth member of the embedded-IPv4 family and was the one missing,
        // so 2002:7f00:1:: reached loopback while ::ffff:127.0.0.1 was correctly denied.
        if bytes[0] == 0x20 && bytes[1] == 0x02 {
            let v4 = (Int(bytes[2]), Int(bytes[3]), Int(bytes[4]), Int(bytes[5]))
            if let reason = privateIPv4Reason(v4) { return "\(reason) (embedded in 6to4)" }
            return nil
        }

        // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and the NAT64
        // well-known prefix (64:ff9b::/96) all target an IPv4 host, so apply the IPv4
        // policy to the embedded address.
        let first10Zero = bytes[0..<10].allSatisfy { $0 == 0 }
        let mapped = first10Zero && bytes[10] == 0xff && bytes[11] == 0xff
        let compatible = first10Zero && bytes[10] == 0 && bytes[11] == 0
        // RFC 6052 well-known prefix 64:ff9b::/96, and RFC 8215 local-use 64:ff9b:1::/48.
        // Only the first was handled, so 64:ff9b:1::7f00:1 reached loopback on any host
        // running a local NAT64. Both are translation prefixes and both end in the
        // target IPv4, so both get judged by it.
        let nat64WellKnown = bytes[0] == 0x00 && bytes[1] == 0x64
            && bytes[2] == 0xff && bytes[3] == 0x9b
            && bytes[4..<12].allSatisfy { $0 == 0 }
        let nat64LocalUse = bytes[0] == 0x00 && bytes[1] == 0x64
            && bytes[2] == 0xff && bytes[3] == 0x9b
            && bytes[4] == 0x00 && bytes[5] == 0x01
        let nat64 = nat64WellKnown || nat64LocalUse
        if mapped || compatible || nat64 {
            let v4 = (Int(bytes[12]), Int(bytes[13]), Int(bytes[14]), Int(bytes[15]))
            if let reason = privateIPv4Reason(v4) {
                return "\(reason) (embedded in IPv6)"
            }
            return nil // embedded public IPv4
        }

        return nil // public IPv6
    }
}
