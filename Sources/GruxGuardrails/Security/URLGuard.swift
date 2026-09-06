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

        // The fixed reasons match EXACTLY, and the scheme reason matches on its prefix,
        // because that reason interpolates the attacker's own scheme string into itself.
        // Substring scanning meant the attacker picked the audit label: `denylist://x`
        // produced "scheme 'denylist' not allowed" and reported as USER_DENYLIST, and
        // `credential://x` reported as CREDENTIAL_URL. Anyone counting denial classes was
        // reading numbers a hostile input could move.
        if reason.hasPrefix("scheme ") { return "BAD_SCHEME" }
        if reason == "credential-bearing URL" { return "CREDENTIAL_URL" }
        if reason == "host on user denylist" { return "USER_DENYLIST" }
        // An illegal character in the host is the most attack-shaped signal this guard
        // produces: `http://127.0.0.1%00.example.com/` is somebody deliberately smuggling
        // a loopback target past the parser, betting the resolver truncates at the NUL.
        // It used to land in the generic URL_DENIED bucket alongside "empty URL" and
        // "missing host", which are ordinary noise, so the one denial that means an
        // attack is in progress was indistinguishable from a typo.
        if reason == "illegal character in host" { return "HOST_SMUGGLING" }
        // Matched before the needle scan below, because "unparseable URL" contains
        // "unparseable", a needle added for "unparseable IPv6 literal", so a plain
        // malformed URL was reporting as PRIVATE_NETWORK.
        if reason == "empty URL" || reason == "unparseable URL" || reason == "missing host" {
            return "URL_DENIED"
        }
        // Everything above matches exactly or on a prefix. Everything below is a needle
        // scan over the reasons privateNetworkReason returns, and that list has now
        // silently fallen behind twice: once when the IPv4 table grew, and once for
        // `illegal character in host`, which was raised in evaluate() and so was never in
        // the earlier fix's scope at all. A hand-maintained needle list cannot defend
        // itself, which is why testEveryDenialReasonLandsOnTheIntendedTag pins the table.
        //
        // Every reason produced by privateNetworkReason has to land here. When the IPv4
        // table grew, these strings were not updated, so Oracle Cloud metadata and the
        // broadcast address reported as generic URL_DENIED. An alert keyed on
        // PRIVATE_NETWORK, which is what the README tells you to log, silently stopped
        // seeing the newest SSRF denials.
        for needle in ["loopback", "private", "link-local", ".local", "intranet", "NAT",
                       "unspecified", "ambiguous", "multicast", "unparseable", "site-local",
                       "this-network", "protocol assignment", "documentation", "benchmark",
                       "reserved", "broadcast", "6to4", "IPv6", "metadata"] {
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
        // `while`, not `if`. This stripped exactly ONE trailing dot while canonicalEntry
        // stripped all of them, and that asymmetry was a denylist bypass: `evil.com..`
        // reduced to `evil.com.` here, the entry reduced to `evil.com`, and the two never
        // compared equal. Same class of bug as the single trailing dot this line was
        // originally written to fix, reintroduced by fixing only one side of it.
        while host.hasSuffix(".") { host = String(host.dropLast()) }

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

    /// Named metadata endpoints across the major clouds and container runtimes. Each of
    /// these resolves to an address the IP rules already deny, so this list exists purely
    /// because the name is what actually appears in prompts, docs and code.
    private static let metadataHostnames: Set<String> = [
        "metadata",                       // GCP short form, resolves via search domain
        "metadata.google.internal",       // GCP
        "metadata.goog",                  // GCP alternate
        "instance-data",                  // AWS legacy
        "instance-data.ec2.internal",     // AWS
        "host.docker.internal",           // Docker Desktop, reaches the host
        "gateway.docker.internal",        // Docker Desktop
        "kubernetes.default.svc",         // in-cluster Kubernetes API
        "kubernetes.default",
        "metadata.platformequinix.com",
        "169.254.169.254.nip.io",         // wildcard DNS that resolves to the metadata IP
    ]

    /// Domains that resolve to loopback WITHOUT carrying the address in the name.
    ///
    /// These are the other half of the wildcard-DNS problem and they need a different
    /// answer. `127.0.0.1.nip.io` is caught by reading the address out of the labels,
    /// which beats the whole family at once. `lvh.me` and `localtest.me` have no address
    /// to read: they are ordinary-looking domains whose A record is 127.0.0.1, so naming
    /// them is the only option available.
    ///
    /// Matched as suffixes, because every subdomain resolves the same way, which is the
    /// entire reason developers use them. This list is best effort by construction, and
    /// the general defence against the ones nobody has enumerated is the same as for DNS
    /// rebinding: this guard does not resolve, so it cannot see where a name points.
    /// Stated in README.md rather than implied.
    private static let loopbackAliasDomains: [String] = [
        "localtest.me", "lvh.me", "localho.st", "vcap.me", "readme.localhost",
    ]

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

        // Everything below this line exists because a denylist that fails to match fails
        // OPEN, so every plausible way a human writes a host has to reduce to the same
        // string. Case, whitespace and dots were already handled. These four were not,
        // and each one silently blocked nothing while looking exactly right in a config:
        //
        //   "https://evil.com"  a pasted URL, the single most likely mistake
        //   "evil.com:443"      a host:port copied from a log line
        //   "evil.com/path"     a pasted link
        //   "*.evil.com"        the natural spelling of a wildcard, and the one every
        //                       other tool accepts. Entries already match subdomains, so
        //                       the star is redundant rather than wrong, which is exactly
        //                       why dropping it is safe and leaving it was dangerous.
        if let r = e.range(of: "://") { e = String(e[r.upperBound...]) }
        if let at = e.lastIndex(of: "@") { e = String(e[e.index(after: at)...]) }
        if let cut = e.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
            e = String(e[..<cut])
        }
        if e.hasPrefix("[") {
            // Bracketed IPv6 literal, with or without a port.
            if let close = e.firstIndex(of: "]") {
                e = String(e[e.index(after: e.startIndex)..<close])
            }
        } else if e.filter({ $0 == ":" }).count == 1, let colon = e.lastIndex(of: ":") {
            // Exactly one colon means host:port. More than one means a bare IPv6
            // literal, where stripping at the last colon would silently truncate the
            // address into a different, possibly public, one.
            e = String(e[..<colon])
        }
        while e.hasPrefix("*") { e = String(e.dropFirst()) }

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

        // Named cloud and container metadata endpoints. These resolve to the link-local
        // and private addresses already denied above, so denying the IP felt like enough.
        // It is not: the agent is far likelier to encounter the NAME, because that is the
        // form every cloud tutorial, SDK and Stack Overflow answer uses. A guard that
        // blocks 169.254.169.254 while allowing metadata.google.internal is blocking the
        // spelling nobody types.
        for suffix in [".internal", ".googleapis.internal", ".goog"] where host.hasSuffix(suffix) {
            return "cloud or container metadata hostname"
        }
        if metadataHostnames.contains(host) { return "cloud or container metadata hostname" }

        // Wildcard-resolver hostnames that carry their target IP in the NAME.
        //
        // nip.io, sslip.io and their kin answer `<anything>.10.0.0.1.nip.io` with
        // 10.0.0.1, which turns any private address into an ordinary-looking public
        // domain and walks past every check above. The metadata table already carried
        // `169.254.169.254.nip.io`, so the technique was known and one instance of it was
        // blocked while the general shape, including plain `127.0.0.1.nip.io`, was not.
        // Blocking a list of these services is a losing game, because a new one costs a
        // domain, so the embedded ADDRESS is what gets judged instead of the service.
        //
        // Deliberately over-broad: `127.0.0.1.example.com` is denied too, on a domain
        // that has nothing to do with nip.io. A hostname spelling out a loopback or RFC
        // 1918 address in its own labels is doing that on purpose, and the cost of being
        // wrong is one allowlist entry against an SSRF that otherwise just works.
        if let reason = embeddedPrivateIPv4Reason(host) { return reason }
        for domain in loopbackAliasDomains where host == domain || host.hasSuffix("." + domain) {
            return "loopback (wildcard DNS alias)"
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

    /// A private IPv4 written into the LABELS of an otherwise ordinary hostname, in
    /// either the dotted form `10.0.0.1.nip.io` or the dashed form `10-0-0-1.nip.io`.
    /// Both are what the wildcard-DNS services answer with, and the dashed one is the
    /// spelling that survives being used as a TLS subdomain.
    private static func embeddedPrivateIPv4Reason(_ host: String) -> String? {
        let labels = host.split(separator: ".").map(String.init)
        // Every window of four consecutive labels, because the address is not always at
        // the front: `foo.127.0.0.1.nip.io` resolves just as well. The count guard is
        // scoped to THIS loop and not the whole function, which it was at first: a
        // three-label host like `10-0-0-1.nip.io` returned early and the dashed check
        // below never ran at all, so the fix shipped covering half the shapes it named.
        if labels.count > 4 {
            for i in 0...(labels.count - 4) {
                let quad = labels[i..<(i + 4)].joined(separator: ".")
                if let octets = ipv4Octets(quad), let reason = privateIPv4Reason(octets) {
                    return "\(reason) (embedded in hostname)"
                }
            }
        }
        for label in labels {
            let parts = label.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 4 else { continue }
            if let octets = ipv4Octets(parts.joined(separator: ".")),
               let reason = privateIPv4Reason(octets) {
                return "\(reason) (embedded in hostname)"
            }
        }
        return nil
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
            // `count > 2` was `count > 2` on the whole label, so a BARE `0x` with no
            // digits after it counted as neither decimal nor hex, the whole host was
            // judged non-numeric, and `http://127.0.0x.1/` was ALLOWED. `inet_aton`
            // reads a bare `0x` as zero, so that host is 127.0.0.1 to the system
            // resolver: measured with getaddrinfo(AI_NUMERICHOST), which parses it as an
            // IP literal. `0x.0x.0x.0x` was allowed the same way and is 0.0.0.0.
            let isHex = lower.hasPrefix("0x")
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
        // RFC 2765 section 2.1 IPv4-translated, the ::ffff:0:0:0/96 prefix, and the fourth
        // member of this family. It was missed because the `ffff` sits at bytes 8 and 9
        // rather than 10 and 11, so `first10Zero` is false and all three tests above fail,
        // leaving `::ffff:0:127.0.0.1` to fall through as ordinary global unicast.
        //
        // It is not routable on macOS today: `route -n get -inet6 ::ffff:0:7f00:1` answers
        // `not in table`, and RFC 6145 obsoleted this format. It is judged anyway for the
        // same reason `0x7f.0.0.1` is denied on the chance a resolver reads it as loopback,
        // and for the same reason deprecated site-local fec0::/10 is denied: a deprecated
        // translation format carrying a loopback target is exactly what this table is for.
        // The cost is a public IPv6 that collides with a reserved prefix, which is the
        // trade the NAT64 rows already accepted.
        //
        // Pinning the `ffff` to one byte pair catches ONE spelling and misses the rest,
        // which is how the first attempt at this failed. `::ffff:127.0.0.1` puts it in
        // group 5, `::ffff:0:127.0.0.1` in group 4, `::ffff:0:0:127.0.0.1` in group 3,
        // because how many explicit zero groups the author writes moves it. Judge the
        // family by SHAPE instead: the leading twelve bytes are all zero except at most
        // one aligned 16-bit group equal to ffff. That covers every spelling including
        // the two already handled, and a real global unicast address cannot match it,
        // because its leading groups carry something that is neither zero nor ffff.
        let leadingGroups = stride(from: 0, to: 12, by: 2).map {
            (Int(bytes[$0]) << 8) | Int(bytes[$0 + 1])
        }
        let nonZeroLeading = leadingGroups.filter { $0 != 0 }
        let translated = nonZeroLeading.isEmpty
            || (nonZeroLeading.count == 1 && nonZeroLeading[0] == 0xffff)
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
        if mapped || compatible || nat64 || translated {
            let v4 = (Int(bytes[12]), Int(bytes[13]), Int(bytes[14]), Int(bytes[15]))
            if let reason = privateIPv4Reason(v4) {
                return "\(reason) (embedded in IPv6)"
            }
            // RFC 8215's local-use range is a /48, and RFC 6052 puts the embedded IPv4 in
            // a DIFFERENT place for every prefix length: at /96 it is the trailing four
            // bytes, at /48 it is bytes 6 and 7 then 9 and 10, skipping the u-octet at
            // byte 8. Only the /96 position was ever read, so an attacker parks a public
            // decoy in the tail and the real target where the standard actually puts it:
            // `64:ff9b:1:7f00:0:1:808:808` was ALLOWED while carrying 127.0.0.0.
            //
            // Both positions are now checked and either one denies, because a translator
            // configured with a /48 and one configured with a /96 inside it are both
            // legal and nothing in the address says which is in use. Failing closed on
            // the union costs a public IPv6 that happens to collide, which is a far
            // cheaper mistake than the one this replaces.
            if nat64LocalUse {
                // RFC 6052 section 2.2 puts the embedded IPv4 in a different place for
                // every Network-Specific Prefix length, always skipping byte 8, the
                // u-octet. RFC 8215 reserves this whole /48 for local use, so an operator
                // may deploy ANY of these lengths inside it and nothing in the address
                // says which one is in force.
                //
                // Checking one length is therefore not a fix, it is a guess, and the first
                // version of this checked only /48 and was defeated by
                // `64:ff9b:1:808:a:0:100:0`, which parks a public 8.8.10.0 in the /48 slot
                // and 1.0.0.0 in the /96 slot while carrying 10.0.0.1 where a /64 NSP puts
                // it. Every slot is checked now and any private hit denies.
                //
                // Being aggressive here is free: every address in this range is BY
                // DEFINITION a translation of some IPv4, so there is no legitimate public
                // IPv6 host to over-deny. A slot whose first octet is zero is skipped,
                // because 0.0.0.0/8 is what an unused slot reads as rather than a target
                // anybody is trying to reach, and without that skip the empty slots of a
                // perfectly ordinary /96 translation deny it.
                let slots: [(String, (Int, Int, Int, Int))] = [
                    ("/32", (Int(bytes[4]), Int(bytes[5]), Int(bytes[6]), Int(bytes[7]))),
                    ("/40", (Int(bytes[5]), Int(bytes[6]), Int(bytes[7]), Int(bytes[9]))),
                    ("/48", (Int(bytes[6]), Int(bytes[7]), Int(bytes[9]), Int(bytes[10]))),
                    ("/56", (Int(bytes[7]), Int(bytes[9]), Int(bytes[10]), Int(bytes[11]))),
                    ("/64", (Int(bytes[9]), Int(bytes[10]), Int(bytes[11]), Int(bytes[12]))),
                ]
                for (length, v4) in slots where v4.0 != 0 {
                    if let reason = privateIPv4Reason(v4) {
                        return "\(reason) (embedded in NAT64 \(length))"
                    }
                }
            }
            return nil // embedded public IPv4
        }

        if let reason = ipv6RegistryReason(bytes) { return reason }

        return nil // public IPv6
    }

    /// The rest of the IANA IPv6 Special-Purpose Address Registry.
    ///
    /// The IPv4 table has been registry-complete for several rounds and this one was not:
    /// 8 of the 25 rows were classified and 17 were allowed. That asymmetry was never a
    /// decision, it was an absence, and absence is exactly what an audit is supposed to
    /// turn into a decision. Every row below was driven through the real `evaluate` before
    /// and after, so "was allowed" is measured rather than assumed.
    ///
    /// Three of the seventeen were genuine holes rather than tidy-ups, and they share a
    /// shape: RFC 7723, RFC 8155 and RFC 9665 assign three anycast addresses at
    /// `2001:1::1`, `::2` and `::3`. Anycast means packets are absorbed by the nearest
    /// responder, which for all three is infrastructure on the local network. They read as
    /// ordinary global unicast, they were allowed, and they are a direct path to a device
    /// the caller was never supposed to reach.
    ///
    /// **The `2001::/23` trap is the reason this is a row-by-row table and not a prefix.**
    /// The obvious implementation is to deny the whole IETF Protocol Assignments block,
    /// which covers everything from `2001::` to `2001:1ff::` and would close the three
    /// anycast holes, Teredo, ORCHIDv2 and DETs in one line. It would also deny
    /// `2001:3::/32`, which is AMT, and `2001:4:112::/48`, which is AS112-v6. Both of
    /// those are globally reachable services carrying real traffic. Denying them would be
    /// exactly the mistake the round-seven NAT64 fix made in the other direction, so the
    /// carve-outs are checked FIRST and return nil explicitly rather than being left to
    /// fall out of the ordering.
    private static func ipv6RegistryReason(_ b: [UInt8]) -> String? {
        func prefix16(_ a: UInt8, _ c: UInt8) -> Bool { b[0] == a && b[1] == c }

        // Globally reachable, carrying real traffic, MUST stay allowed. Checked before
        // anything below so no later rule can swallow them.
        // 2001:3::/32 AMT, RFC 7450.
        if prefix16(0x20, 0x01) && b[2] == 0x00 && b[3] == 0x03 { return nil }
        // 2001:4:112::/48 AS112-v6, RFC 7535.
        if prefix16(0x20, 0x01) && b[2] == 0x00 && b[3] == 0x04
            && b[4] == 0x01 && b[5] == 0x12 { return nil }
        // 2620:4f:8000::/48 Direct Delegation AS112 Service, RFC 7534.
        if prefix16(0x26, 0x20) && b[2] == 0x00 && b[3] == 0x4f
            && b[4] == 0x80 && b[5] == 0x00 { return nil }

        // Teredo, 2001::/32, RFC 4380. The last registry prefix with embedded-IPv4
        // semantics that was not being decoded. A Teredo address carries the tunnel
        // SERVER's IPv4 in bytes 4 through 7 in the clear, and the CLIENT's IPv4 in bytes
        // 12 through 15 obfuscated by a bitwise NOT. Both are real destinations, so both
        // are judged by the IPv4 policy, same as 6to4 and NAT64 above.
        if prefix16(0x20, 0x01) && b[2] == 0x00 && b[3] == 0x00 {
            let server = (Int(b[4]), Int(b[5]), Int(b[6]), Int(b[7]))
            if let reason = privateIPv4Reason(server) {
                return "\(reason) (Teredo server, embedded in 2001::/32)"
            }
            let client = (Int(~b[12]), Int(~b[13]), Int(~b[14]), Int(~b[15]))
            if let reason = privateIPv4Reason(client) {
                return "\(reason) (Teredo client, embedded in 2001::/32)"
            }
            return "Teredo tunnel IPv6 (2001::/32)"
        }

        // The three anycast addresses. Each is absorbed by the nearest responder, which is
        // local infrastructure, so each is a route to the LAN wearing a global address.
        if prefix16(0x20, 0x01) && b[2] == 0x00 && b[3] == 0x01
            && b[4..<15].allSatisfy({ $0 == 0 }) {
            switch b[15] {
            case 1: return "PCP anycast IPv6 (2001:1::1), reaches the local NAT or firewall"
            case 2: return "TURN anycast IPv6 (2001:1::2), reaches an operator relay"
            case 3: return "DNS-SD SRP anycast IPv6 (2001:1::3), reaches the local-link registrar"
            default: break
            }
        }

        // 100::/64 discard-only, RFC 6666. 100:0:0:1::/64 dummy prefix, RFC 9780, which
        // the registry marks Destination=False, meaning it is a placeholder and never a
        // destination at all. Neither can carry a useful response, so a request to either
        // is a mistake or a probe.
        if prefix16(0x01, 0x00) && b[2..<8].allSatisfy({ $0 == 0 }) {
            return "discard-only IPv6 (100::/64)"
        }
        if prefix16(0x01, 0x00) && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0
            && b[6] == 0 && b[7] == 0x01 {
            return "dummy IPv6 prefix (100:0:0:1::/64), never a destination"
        }

        // ORCHIDv2 2001:20::/28 (RFC 7343) and DETs 2001:30::/28 (RFC 9374). Both are
        // cryptographic identifiers that merely look like addresses. The registry calls
        // ORCHIDv2 globally reachable, which is about the identifier namespace and not
        // about anything answering, so denying costs nothing real.
        if prefix16(0x20, 0x01) && b[2] == 0x00 && (b[3] & 0xf0) == 0x20 {
            return "ORCHIDv2 IPv6 identifier (2001:20::/28), not a routable host"
        }
        if prefix16(0x20, 0x01) && b[2] == 0x00 && (b[3] & 0xf0) == 0x30 {
            return "DET IPv6 identifier (2001:30::/28), not a routable host"
        }
        // Deprecated ORCHID, 2001:10::/28. Deprecated is not unroutable, same reasoning as
        // site-local above.
        if prefix16(0x20, 0x01) && b[2] == 0x00 && (b[3] & 0xf0) == 0x10 {
            return "deprecated ORCHID IPv6 (2001:10::/28)"
        }

        // Benchmarking 2001:2::/48, RFC 5180. Documentation 2001:db8::/32 (RFC 3849) and
        // 3fff::/20 (RFC 9637). None should ever be dialled by an agent, and a request to
        // one is a sign the caller is following an address out of a document.
        if prefix16(0x20, 0x01) && b[2] == 0x00 && b[3] == 0x02
            && b[4] == 0x00 && b[5] == 0x00 {
            return "benchmarking IPv6 (2001:2::/48)"
        }
        if prefix16(0x20, 0x01) && b[2] == 0x0d && b[3] == 0xb8 {
            return "documentation IPv6 (2001:db8::/32)"
        }
        if b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0x00 {
            return "documentation IPv6 (3fff::/20)"
        }

        // SRv6 SIDs, 5f00::/16, RFC 9602. The registry marks it not globally reachable.
        // These are routing instructions scoped to one SR domain, and a SID that leaks out
        // of its domain is a way to steer a packet inside somebody's fabric.
        if prefix16(0x5f, 0x00) {
            return "SRv6 SID (5f00::/16), an IPv6 routing instruction scoped to one domain"
        }

        // 2001::/23 IETF Protocol Assignments, the catch-all UNDER the specific rows
        // above, so the AMT and AS112-v6 carve-outs have already returned. This is the
        // exact IPv6 counterpart of IPv4 192.0.0.0/24, which the IPv4 table denies, so
        // leaving it open was an inconsistency rather than a considered position.
        if prefix16(0x20, 0x01) && (b[2] & 0xfe) == 0x00 {
            return "IETF protocol assignment (2001::/23)"
        }

        return nil
    }
}
