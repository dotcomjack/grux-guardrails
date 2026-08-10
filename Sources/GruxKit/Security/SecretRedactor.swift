// █ dcj · dotcomjack.com · MIT
import Foundation

/// Canonical redactor for anything untrusted that is about to enter a model prompt:
/// OCR of the screen, ambient microphone transcripts, file contents, tool output,
/// fetched web pages.
///
/// An agent that can see your screen and read your files will eventually read a
/// secret, and the moment that text is interpolated into a prompt it leaves your
/// machine. This runs in between. Secret-shaped tokens are replaced in place with
/// `[REDACTED:KIND]`, so the model still sees the shape of the document and can
/// reason about it without ever receiving the value.
///
/// Two properties are load-bearing, and both are pinned by tests:
///
/// 1. **Most-specific-first.** A Stripe live key becomes `[REDACTED:STRIPE_LIVE_SECRET]`,
///    not the generic high-entropy tag. Tag precision is what makes the audit log
///    useful after the fact, and a generic tag on a live payment key reads as noise.
/// 2. **Idempotence.** `redact(redact(x)) == redact(x)`. Redacted text gets re-redacted
///    constantly in practice, because prompts are assembled from fragments that were
///    each cleaned on the way in. It holds because `[`, `]` and `:` are outside every
///    pattern's character class, so a marker is only ever seen as the short runs
///    `REDACTED` and `HIGH_ENTROPY`, both far under the length floor. The `hasPrefix`
///    check in `replaceHighEntropy` is defence in depth for anyone who later widens the
///    class, not the thing currently doing the work.
///
/// This is deliberately a matcher, not a parser. It cannot catch a secret that does
/// not look like one, and it is the last line rather than the only one. Do not use it
/// to justify feeding the agent credentials it did not need.
public enum SecretRedactor {

    /// Every prefix pattern carries this left boundary. Without it the matcher happily
    /// starts mid-word: "task-management-system" contains "sk-management-system", which
    /// satisfied the OpenAI pattern and turned ordinary prose into
    /// "ta[REDACTED:OPENAI_KEY]". Excluding `-` and `_` as well as alphanumerics is the
    /// part that matters, because the prefixes themselves contain those characters.
    private static let L = #"(?<![A-Za-z0-9_\-])"#

    /// Ordered, most-specific prefixes first, JWT before generic entropy, generic last.
    private static let patterns: [(tag: String, regex: NSRegularExpression)] = {
        let raw: [(String, String)] = [
            // PEM has to consume the whole armoured block, not just the header line.
            // Matching the header alone tagged it [REDACTED:PEM] and then handed the
            // model every byte of the key body, which inverts the point of the library.
            //
            // This walks the base64 body line by line and then takes the END line if it
            // is there, rather than doing a lazy `[\s\S]*?` scan to the first END. That
            // distinction is a denial-of-service fix, not a style preference: the lazy
            // form is O(n^2) on input carrying many BEGIN markers and no END, because
            // every marker rescans the rest of the document. A 1.2MB hostile page took
            // 72 seconds. This form does the same work in under 10 milliseconds, because
            // a body line that is not base64 stops the match immediately.
            // The `[ \t]*` AFTER each line break is load-bearing and was missing. A PEM
            // indented inside YAML, JSON, a markdown block or a code sample matched its
            // header and stopped there, and the body then depended entirely on the
            // entropy pass to rescue it. Measured: an indented block whose body line is
            // single-case base64 carries no digit and no mixed case, so entropy cannot
            // see it either, and the key body reached the model VERBATIM while the
            // header sat above it reading `[REDACTED:PEM]`. The unindented form of the
            // same block is consumed whole, which is what made it look fine.
            //
            // This is the third instance of one defect. The comment on the JSON variant
            // below describes it happening with escaped newlines, and the fix there was
            // the same shape. Whitespace around a line break is not decoration when the
            // pattern is line-anchored.
            ("PEM", #"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"#
                  + #"(?:[ \t]*[\r\n]+[ \t]*[A-Za-z0-9+/=]{4,})*"#
                  + #"(?:[ \t]*[\r\n]+[ \t]*-----END [A-Z0-9 ]*PRIVATE KEY-----)?"#),
            // The same block after JSON encoding, where every newline is the two
            // characters backslash-n rather than an actual line break.
            //
            // This is not a hypothetical shape. It is exactly how a GCP service account
            // key file stores its private key, and reading a credentials JSON is a
            // completely ordinary thing for an agent to be asked to do. Measured against
            // a real 2048-bit key: the line-based pattern above matched only the header,
            // and 4 of the 25 body lines then reached the model verbatim, because the
            // entropy pass only rescues the ones that happen to carry mixed case and a
            // digit. A base64 line that happens to be single case walked straight out.
            ("PEM", #"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"#
                  + #"(?:\\r?\\n[ \t]*[A-Za-z0-9+/=]{4,})*"#
                  + #"(?:\\r?\\n[ \t]*-----END [A-Z0-9 ]*PRIVATE KEY-----)?"#),
            ("ANTHROPIC_KEY", L + #"sk-ant-[A-Za-z0-9_\-]{10,}"#),
            // Generic OpenAI-style secret key (sk-... and sk-proj-...). Runs after the
            // more specific sk-ant- so Anthropic keys keep their own tag. The 16-char
            // floor catches real keys, which are far longer, while leaving short "sk-"
            // prose alone.
            ("OPENAI_KEY", L + #"sk-(?:proj-)?[A-Za-z0-9_\-]{16,}"#),
            // AKIA is the long-lived access key ID, ASIA the temporary session one.
            ("AWS_KEY", L + #"A(?:KIA|SIA)[0-9A-Z]{16}"#),
            ("GOOGLE_API_KEY", L + #"AIza[0-9A-Za-z_\-]{35}"#),
            ("GOOGLE_OAUTH_SECRET", L + #"GOCSPX-[A-Za-z0-9_\-]{20,}"#),
            // ghp_ ghs_ gho_ ghu_ ghr_ all exist and all authenticate.
            ("GITHUB_TOKEN", L + #"gh[posur]_[A-Za-z0-9]{30,}"#),
            ("GITHUB_FINE_GRAINED", L + #"github_pat_[A-Za-z0-9_]{20,}"#),
            ("SLACK_TOKEN", L + #"xox[baprse]-[A-Za-z0-9\-]{20,}"#),
            ("STRIPE_WEBHOOK_SECRET", L + #"whsec_[A-Za-z0-9]{20,}"#),
            ("STRIPE_LIVE_SECRET", L + #"sk_live_[A-Za-z0-9]{20,}"#),
            ("STRIPE_LIVE_PUBLIC", L + #"pk_live_[A-Za-z0-9]{20,}"#),
            ("STRIPE_LIVE_RESTRICTED", L + #"rk_live_[A-Za-z0-9]{20,}"#),
            // Test keys are not harmless: they identify the account and leak in support
            // threads, and people paste the wrong one constantly.
            ("STRIPE_TEST_KEY", L + #"[sprk]k_test_[A-Za-z0-9]{20,}"#),
            ("ELEVENLABS_KEY", L + #"sk_[a-f0-9]{48,}"#),
            // These exist because the generic pass structurally cannot reach them. It
            // requires mixed case AND digits, and a HuggingFace token carries no digit
            // while a Shopify token is single case. Loosening the generic rule far enough
            // to catch either would start eating ordinary identifiers, so the honest
            // answer is a prefix pattern per provider rather than a blunter heuristic.
            ("HUGGINGFACE_TOKEN", L + #"hf_[A-Za-z0-9]{30,}"#),
            ("SHOPIFY_TOKEN", L + #"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"#),
            ("GITLAB_TOKEN", L + #"glpat-[A-Za-z0-9_\-]{20,}"#),
            ("NPM_TOKEN", L + #"npm_[A-Za-z0-9]{36}"#),
            ("DIGITALOCEAN_TOKEN", L + #"dop_v1_[a-f0-9]{64}"#),
            ("SENDGRID_KEY", L + #"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"#),
            ("SUPABASE_TOKEN", L + #"sbp_[a-f0-9]{20,}"#),
            ("JWT", L + #"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"#)
        ]
        return raw.compactMap { pair in
            (try? NSRegularExpression(pattern: pair.1, options: [])).map { (pair.0, $0) }
        }
    }()

    /// Generic high-entropy run, executed LAST so the specific patterns get first crack.
    ///
    /// `/` IS in this class, and getting that wrong cost a real secret.
    ///
    /// It was removed once, to stop `/var/folders/mn/2xk8h9.../T/build.log` matching as
    /// one token and being replaced whole. That fixed the paths and blinded the redactor
    /// to standard base64, whose alphabet includes `/`. The AWS secret access key, which
    /// is the half of the AWS pair that actually grants access, leaked completely.
    ///
    /// So `/` is back, and paths are excluded structurally instead, by `looksLikeASecret`
    /// rejecting any token with a segment shorter than 4 characters. A path is short
    /// segments joined by separators, and an absolute path starts with `/`, which is an
    /// empty leading segment. A base64 blob is one long run, or long runs.
    /// `=` is only legal as TRAILING base64 padding, never inside the run. Treating it as
    /// an ordinary token character made `Authorization=Bearer_...` a single 40+ token, so
    /// the whole thing including the field name was replaced. This file's promise is that
    /// the model still sees the shape of the document, and swallowing the label destroys
    /// exactly that: the reader can no longer tell which field was redacted.
    /// The floor is 32, not 40, and that number is load-bearing in a way that took a
    /// regression to learn. Keeping `=` out of the token run was correct, but it also
    /// removed the label from the run, and the label had been supplying the length. So
    /// `HF_TOKEN=hf_...` was redacted at 0.3.0 and leaked at 0.3.1: the fix for a
    /// cosmetic complaint silently un-redacted a whole class of real credentials.
    /// Every `NAME=value` secret shorter than 40 characters went out in plaintext.
    private static let entropyRegex: NSRegularExpression? = {
        try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9])[A-Za-z0-9+/_\-]{40,}={0,2}(?![A-Za-z0-9])"#,
            options: []
        )
    }()

    /// Assigned secrets: the value of anything whose NAME says it is a credential.
    ///
    /// This exists because length alone cannot separate a secret from an identifier in
    /// the 32 to 39 character band. Dropping the generic floor to 32 caught
    /// `HF_TOKEN=hf_...` and also ate `kCVPixelFormatType_32BGRA_FullRange` and
    /// `feature/JIRA-1234-add-new-thing-here`. Raising it back to 40 protected those and
    /// leaked every `NAME=value` secret shorter than 40. Both attempts were tuning the
    /// wrong dial.
    ///
    /// The label is the signal. `HF_TOKEN`, `TWILIO_AUTH` and `AWS_SECRET_ACCESS_KEY`
    /// announce themselves, and nothing named that way holds a value worth printing. So
    /// this matches the name, keeps it, and redacts only what follows, which is also what
    /// preserves the shape of the document. It covers env files, shell exports, YAML,
    /// JSON and query strings in one pattern because they all share the `name` then
    /// separator then `value` shape.
    /// The name part is anchored on the keyword rather than opened with a wildcard, and
    /// that is a performance fix, not a style choice. A leading `[A-Za-z0-9_\-]*` before
    /// the alternation makes the engine try a variable-length prefix at every offset in
    /// the document: 0.711s on 760KB of ordinary prose against 0.076s for this form, on
    /// text containing no secrets at all. Nine times the cost of the pass it sits next
    /// to, paid on every call, to scan text that will never match.
    /// Words that mark a name as holding a credential. Matched as plain SUBSTRINGS, case
    /// insensitively, with no word boundary. That is the whole point: the previous regex
    /// required the keyword to start the name or follow a separator, so `access_token` was
    /// caught and `accessToken`, `clientSecret`, `PGPASSWORD` and `_auth` were not.
    private static let credentialWords = [
        "secret", "token", "password", "passwd", "pass", "pwd",
        "apikey", "api_key", "api-key", "auth", "credential", "private",
        // A session identifier IS a credential: it is what a stolen cookie replays.
        // `session` also reaches JSESSIONID and PHPSESSID, and `cookie` takes the whole
        // header value, which is the shape these actually arrive in.
        "session", "cookie", "csrf",
        // Bare "key" is deliberately included, because SESSION_KEY and SIGNING_KEY are
        // credentials and nothing narrower reaches them. It also matches PARTITION_KEY and
        // PRIMARY_KEY, whose values are column names, so the value brake below carries the
        // decision rather than this list.
        "key",
    ]

    /// Auth schemes that sit between the separator and the value in an HTTP header. RFC
    /// 7235 puts a scheme token there, and requiring the value to start immediately after
    /// the separator meant every `Authorization: Bearer ...` header leaked in full.
    private static let authSchemes = ["bearer", "basic", "digest", "token", "apikey", "key"]

    /// Replace every secret-shaped token in `input` with `[REDACTED:KIND]`.
    /// Safe to call repeatedly on its own output.
    public static func redact(_ input: String) -> String {
        var out = input
        for (tag, regex) in patterns {
            out = replaceAll(in: out, regex: regex, with: "[REDACTED:\(tag)]")
        }
        // After the provider prefixes, so a recognised key keeps its own precise tag, and
        // before the entropy pass, so a labelled value is caught even when it is too
        // short or too single-case for the generic rule to see it.
        out = redactURLCredentials(in: out)
        out = redactBasicAuthFlags(in: out)
        out = redactLabelledValues(in: out)
        // After the labelled pass, deliberately. A header that carries its own name keeps
        // the more precise ASSIGNED_SECRET tag; this only picks up the naked case, a line
        // that opens with the scheme and nothing else, which is how `curl -v` and most
        // request logs print it. Lowercase hex is the common shape there and the entropy
        // pass cannot see it, because that rule needs mixed case.
        out = redactSchemeLedTokens(in: out)
        out = replaceHighEntropy(in: out)
        return out
    }

    /// `curl -u user:password`, which is the same credential as `https://user:pass@host`
    /// wearing a flag instead of a scheme. Six characters minimum on the password half so
    /// that `docker run -u 1000:1000` stays a uid:gid pair and not a redaction.
    private static let basicAuthFlagRegex: NSRegularExpression? = {
        try? NSRegularExpression(
            pattern: #"(^|\s)(--user|-u)(\s+[^\s:]{1,64}:)([^\s]{6,})"#,
            options: [])
    }()

    private static func redactBasicAuthFlags(in input: String) -> String {
        guard let regex = basicAuthFlagRegex else { return input }
        return replacePreservingMarkers(in: input, regex: regex, valueGroup: 4,
                                        replacement: "[REDACTED:BASIC_CREDENTIAL]")
    }

    private static let schemeLedRegex: NSRegularExpression? = {
        try? NSRegularExpression(
            pattern: #"(?i)\b(bearer|basic|digest)(\s+)([A-Za-z0-9+/=_.\-]{20,})"#,
            options: [])
    }()

    private static func redactSchemeLedTokens(in input: String) -> String {
        guard let regex = schemeLedRegex else { return input }
        let range = NSRange(input.startIndex..<input.endIndex, in: input)
        return regex.stringByReplacingMatches(
            in: input, options: [], range: range,
            withTemplate: "$1$2[REDACTED:AUTH_SCHEME_TOKEN]")
    }

    /// Mean length of the `/`-separated segments of a token.
    private static func meanSegmentLength(of s: String) -> Double {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty else { return 0 }
        let total = parts.reduce(0) { $0 + $1.count }
        return Double(total) / Double(parts.count)
    }

    // MARK: - Labelled values

    /// Redact the value of anything whose NAME says it holds a credential.
    ///
    /// This is a scanner, not a regex, and that is a deliberate rewrite. The regex version
    /// required three things to be true at once: the name had to clear a word boundary,
    /// AND the value had to be drawn from a narrow character class, AND the value had to
    /// begin immediately after the separator. Each of those three was its own leak, and
    /// five audit rounds found them one at a time. Scanning separates finding the NAME
    /// from taking the VALUE, so a new spelling of either cannot silently disable the
    /// other. It is also linear by construction, which removes the backtracking that made
    /// 8KB of ordinary CSS-class text cost forty seconds.
    private static func redactLabelledValues(in input: String) -> String {
        let s = Array(input)
        let lower = Array(input.lowercased())
        var out = ""
        out.reserveCapacity(s.count)
        var i = 0

        while i < s.count {
            guard let wordEnd = credentialWordEnd(lower, at: i) else {
                out.append(s[i]); i += 1; continue
            }
            // The keyword is inside a name. Take the whole name token around it, then look
            // for a separator. If either fails this is ordinary prose, so emit and move on.
            var nameEnd = wordEnd
            while nameEnd < s.count, isNameChar(s[nameEnd]) { nameEnd += 1 }

            // Every start position inside one name run shares this run's nameEnd, and
            // therefore its separator and its value, so a failure here fails identically
            // for all of them. Skipping the whole run is what keeps this linear. Advancing
            // one character instead made 48KB of `keykeykey` cost eleven seconds and 80KB
            // of `auth.auth.` cost twenty, on text an attacker chooses. The committed
            // superlinearity test does exercise this shape and missed it purely because
            // 8KB is small enough to stay under the threshold.
            func skipRun() {
                out.append(contentsOf: s[i..<nameEnd])
                i = nameEnd
            }

            // The name token as written, including anything before the keyword, because
            // `hunter2Passw0rd` and `password` are the same keyword in very different
            // company and only the whole token can tell them apart.
            var tokenStart = i
            while tokenStart > 0, isNameChar(s[tokenStart - 1]) { tokenStart -= 1 }
            let nameToken = String(s[tokenStart..<nameEnd])

            var j = nameEnd
            while j < s.count, s[j] == "\"" || s[j] == "'" { j += 1 }
            let beforeSpace = j
            while j < s.count, s[j] == " " || s[j] == "\t" { j += 1 }
            var separatorWasWhitespaceOnly = false
            if j < s.count, s[j] == "=" || s[j] == ":" {
                j += 1
                // Ruby and JavaScript write `apiKey => "..."`, and the arrow head is not
                // whitespace, so without this the value was read as a bare `>`.
                if j < s.count, s[j] == ">" { j += 1 }
                while j < s.count, s[j] == " " || s[j] == "\t" { j += 1 }
                j = skipToBlockScalarValue(s, from: j)
            } else if j < s.count, s[j] == "(" {
                // A call, `setApiKey("...")`. The quote is required: without it every
                // `decryptWithKey(masterKeyMaterial)` in ordinary code becomes a redaction.
                var k = j + 1
                while k < s.count, s[k] == " " || s[k] == "\t" { k += 1 }
                guard k < s.count, s[k] == "\"" || s[k] == "'" else { skipRun(); continue }
                j = k
            } else if j > beforeSpace {
                // Whitespace alone is a separator too. netrc writes `password hunter2`,
                // and so does every CLI flag (`--password hunter2`). It is also the
                // weakest signal in the scanner and it was the single largest source of
                // destroyed text, because a keyword anywhere inside any token made the
                // NEXT token disappear: `curl -u bot:hunter2Passw0rd https://api.acme.io`
                // ate the URL, and `see the auth README.md` ate the filename. So it now
                // carries two brakes the other separators do not need.
                separatorWasWhitespaceOnly = true
            } else {
                skipRun(); continue
            }

            if separatorWasWhitespaceOnly, !isWhitespaceSeparable(nameToken) { skipRun(); continue }

            // An optional auth-scheme word, then more whitespace.
            if let afterScheme = skipAuthScheme(lower, from: j) { j = afterScheme }
            var quote: Character? = nil
            if j < s.count, s[j] == "\"" || s[j] == "'" { quote = s[j]; j += 1 }

            // Take the value to its natural delimiter for the surrounding format.
            let valueStart = j
            while j < s.count, !isValueTerminator(s[j], quote: quote) { j += 1 }
            let value = String(s[valueStart..<j])

            // Never re-redact an existing marker. The provider patterns run BEFORE this
            // scanner, so `token ghp_...` is already `token [REDACTED:GITHUB_TOKEN]` by
            // the time we get here, and without this guard the scanner treats that marker
            // as the value and replaces it with a less precise tag. That destroys both
            // load-bearing properties at once: the specific tag, and idempotence.
            guard !value.hasPrefix("[REDACTED:"), looksLikeACredentialValue(value) else {
                skipRun(); continue
            }
            if separatorWasWhitespaceOnly, looksLikeALocator(value) { skipRun(); continue }
            out.append(contentsOf: s[i..<valueStart])
            out.append("[REDACTED:ASSIGNED_SECRET]")
            i = j
        }
        return out
    }

    /// Names that may be followed by nothing but whitespace and still mean "the next
    /// token is a credential". Deliberately much narrower than `credentialWords`, and
    /// deliberately an EXACT match on the whole name rather than a substring: `key`,
    /// `auth` and `private` are all common enough in prose that whitespace-separating on
    /// them destroys ordinary text, while `password X` is a real file format.
    private static let whitespaceSeparableNames: Set<String> = [
        "password", "passwd", "pwd", "pass", "token", "secret",
        "apikey", "api_key", "api-key", "credential", "credentials",
    ]

    private static func isWhitespaceSeparable(_ nameToken: String) -> Bool {
        var t = Substring(nameToken.lowercased())
        while t.first == "-" { t = t.dropFirst() }   // `--password`
        return whitespaceSeparableNames.contains(String(t))
    }

    /// YAML puts the value on the next line, either plainly or behind a block scalar
    /// indicator: `password:` then an indented line, or `clientSecret: >-` then one. A
    /// Kubernetes manifest is exactly this shape and it leaked whole.
    ///
    /// Exactly ONE line break is crossed, never a blank line. That is what stops it from
    /// walking out of a sentence and into the next paragraph: markdown's `set your
    /// password:` followed by a blank line and a heading stays untouched, because the
    /// second break is not consumed and an empty value fails the brake.
    private static func skipToBlockScalarValue(_ s: [Character], from j: Int) -> Int {
        var k = j
        if k < s.count, s[k] == "|" || s[k] == ">" {
            k += 1
            while k < s.count, s[k] == "-" || s[k] == "+" || s[k].isNumber { k += 1 }
            while k < s.count, s[k] == " " || s[k] == "\t" { k += 1 }
        }
        guard k < s.count, s[k] == "\n" || s[k] == "\r" else { return j }
        if s[k] == "\r", k + 1 < s.count, s[k + 1] == "\n" { k += 1 }
        k += 1
        while k < s.count, s[k] == " " || s[k] == "\t" { k += 1 }
        return k
    }

    /// A URL, a path or a filename. Credentials are none of these, and all three sit next
    /// to credential words constantly in prose and in shell transcripts.
    private static func looksLikeALocator(_ v: String) -> Bool {
        if v.contains("://") || v.contains("/") || v.hasPrefix("~") || v.hasPrefix(".") { return true }
        guard let dot = v.lastIndex(of: "."), dot != v.startIndex else { return false }
        let ext = v[v.index(after: dot)...]
        return (1...4).contains(ext.count) && ext.allSatisfy { $0.isLetter }
    }

    /// Index just past a credential word starting at `at`, or nil. Plain substring match.
    private static func credentialWordEnd(_ lower: [Character], at i: Int) -> Int? {
        for word in credentialWords {
            let w = Array(word)
            guard i + w.count <= lower.count else { continue }
            var k = 0
            while k < w.count, lower[i + k] == w[k] { k += 1 }
            if k == w.count { return i + w.count }
        }
        return nil
    }

    private static func skipAuthScheme(_ lower: [Character], from j: Int) -> Int? {
        for scheme in authSchemes {
            let w = Array(scheme)
            guard j + w.count < lower.count else { continue }
            var k = 0
            while k < w.count, lower[j + k] == w[k] { k += 1 }
            guard k == w.count else { continue }
            var after = j + w.count
            guard after < lower.count, lower[after] == " " || lower[after] == "\t" else { continue }
            while after < lower.count, lower[after] == " " || lower[after] == "\t" { after += 1 }
            return after
        }
        return nil
    }

    private static func isNameChar(_ c: Character) -> Bool {
        c.isLetter || c.isNumber || c == "_" || c == "-" || c == "."
    }

    /// Where a value ends. Inside quotes only the closing quote ends it; otherwise the
    /// delimiters of env files, YAML, JSON, query strings and shell all end it.
    private static func isValueTerminator(_ c: Character, quote: Character?) -> Bool {
        if let q = quote { return c == q || c == "\n" || c == "\r" }
        return c == " " || c == "\t" || c == "\n" || c == "\r"
            || c == "&" || c == "," || c == ";" || c == "}" || c == "]"
            || c == "\"" || c == "'"
    }

    /// The false-positive brake, and the only thing standing between substring matching
    /// and eating every config file an agent reads. `tokenizer=wordpiece` and
    /// `authors=alice,bob` both contain credential words in the NAME, so the VALUE has to
    /// carry the decision. A real credential is long and is not a plain lowercase word.
    private static func looksLikeACredentialValue(_ v: String) -> Bool {
        guard v.count >= 8 else { return false }
        var hasDigit = false, hasUpper = false, hasLower = false, hasSymbol = false
        for c in v {
            if c.isNumber { hasDigit = true }
            else if c.isUppercase { hasUpper = true }
            else if c.isLowercase { hasLower = true }
            else { hasSymbol = true }
        }
        // A lowercase dictionary word is not a secret, however long. A digit or mixed case
        // is doing something a word does not.
        if hasDigit || (hasUpper && hasLower) { return true }
        // Punctuation alone is the weakest signal, because snake_case and dotted
        // identifiers carry it and credentials almost never rely on it: every entry in the
        // leak corpus qualifies on a digit or on mixed case instead. At a 12-character
        // threshold this single line produced most of the surviving false positives,
        // eating `"key": "projects_json"` out of every blueprint and `key.anthropic` out
        // of every config enum. Twenty is measured, not guessed: it takes the project's
        // own 8,590 lines from 0.547% destroyed to 0.396% with the leak corpus unmoved.
        return hasSymbol && v.count >= 20
    }

    // MARK: - Credentials inside URLs

    /// `postgres://user:password@host` and every scheme like it.
    ///
    /// URLGuard has always denied this shape unconditionally, so for five rounds the two
    /// halves of this package disagreed about whether `user:pass@` is a credential. It is.
    private static let urlCredentialRegex: NSRegularExpression? = {
        try? NSRegularExpression(
            pattern: #"([A-Za-z][A-Za-z0-9+.\-]{1,31}://[^\s/:@]{1,256}:)([^\s/@]{1,256})(@)"#,
            options: []
        )
    }()

    private static func redactURLCredentials(in input: String) -> String {
        guard let regex = urlCredentialRegex else { return input }
        return replacePreservingMarkers(in: input, regex: regex, valueGroup: 2,
                                        replacement: "[REDACTED:URL_CREDENTIAL]")
    }

    /// Replace one capture group of every match, EXCEPT where that group already holds a
    /// redaction marker.
    ///
    /// Without this, the passes that run later silently downgrade the tag the earlier ones
    /// worked out. `patterns` runs first precisely so a recognised provider key keeps its
    /// own precise tag, and then `postgres://user:sk_live_...@db` came out as
    /// `[REDACTED:URL_CREDENTIAL]`, because by the time the URL pass ran, the value it was
    /// looking at WAS `[REDACTED:STRIPE_LIVE_SECRET]` and it overwrote it. Same for
    /// `curl -u alice:sk_live_...`.
    ///
    /// That made "most specific wins" false in exactly the two places a credential is most
    /// likely to be sitting, and the claim is stated as load-bearing both in this file's
    /// doc comment and in README.md. Nothing leaked either way, so the only casualty was
    /// the audit trail, which is the thing the tag exists for.
    private static func replacePreservingMarkers(
        in input: String, regex: NSRegularExpression, valueGroup: Int, replacement: String
    ) -> String {
        let ns = input as NSString
        let matches = regex.matches(
            in: input, options: [], range: NSRange(location: 0, length: ns.length))
        guard !matches.isEmpty else { return input }
        let out = NSMutableString(capacity: ns.length)
        var cursor = 0
        var replacedAny = false
        for match in matches {
            let valueRange = match.range(at: valueGroup)
            guard valueRange.location != NSNotFound else { continue }
            if ns.substring(with: valueRange).hasPrefix("[REDACTED:") { continue }
            out.append(ns.substring(
                with: NSRange(location: cursor, length: valueRange.location - cursor)))
            out.append(replacement)
            cursor = valueRange.location + valueRange.length
            replacedAny = true
        }
        guard replacedAny else { return input }
        out.append(ns.substring(from: cursor))
        return out as String
    }

    /// Redact, then fence the result so the model can tell untrusted DATA apart from
    /// your instructions.
    ///
    /// This is the prompt-injection half of the problem and it is separate from the
    /// secret half. Screen text and web pages contain sentences addressed to the model.
    /// Without a fence, "ignore your previous instructions" that the agent merely *read*
    /// is indistinguishable from the same sentence that you *typed*.
    ///
    /// **The fence carries a random per-call id, and that is load-bearing.** A fixed
    /// `</untrusted_data>` closer is forgeable by the very input it is meant to contain:
    /// any web page that prints that literal string escapes the block and everything
    /// after it reads as your instructions. That is a one-line bypass of the whole
    /// defence, written by the attacker, in the exact input class this function exists
    /// to handle. With an unguessable id in both tags, a forged closer does not match.
    ///
    /// Tell the model, in your system prompt, that only the closer bearing the matching
    /// id ends the block.
    ///
    /// Pipe ANY screen, ambient, file or network text through this before it reaches a
    /// prompt. The fence is still not a guarantee. It is a boundary the model can act
    /// on, and it is not a substitute for withholding capabilities the agent did not
    /// need in the first place.
    public static func wrapAsUntrusted(_ kind: String, _ body: String) -> String {
        wrapAsUntrusted(kind, body, id: Self.newFenceID())
    }

    /// Deterministic variant, for tests and for callers that need to reference the same
    /// fence id in their system prompt. Prefer the random one everywhere else.
    ///
    /// **Do not pass a human-readable label here.** An id that is not already strong hex
    /// is hashed with FNV-1a, which is unkeyed, so `id: "screen_ocr"` emits
    /// `f942782c85ee7d92` on every machine that has ever run this code and anyone can
    /// recompute it offline in six lines. That hands back the forgery the id exists to
    /// prevent. The hashing is still the right behaviour, because the alternative it
    /// replaced silently truncated the label to a six-character stub, which was worse:
    /// this at least yields a full-width id. But the warning belonged out here, on the
    /// function a caller actually reads, rather than on the private helper.
    ///
    /// If you need a stable id, generate ONE strong random id, `newFenceID()`, and paste
    /// the literal into your system prompt. A 16-hex-character id is used verbatim.
    public static func wrapAsUntrusted(_ kind: String, _ body: String, id: String) -> String {
        let safeKind = kind.filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        // Do NOT silently strip non-hex characters. Doing that turned a caller's ordinary
        // label, say "screen-capture", into id="ceecae": six characters, trivially
        // guessable, which hands back the exact forgery this id exists to prevent, with
        // no error and no warning. An id that is not already strong hex is hashed into
        // one, so every caller gets a usable fence whatever they pass.
        let hex = id.filter { $0.isHexDigit }
        let safeID = (hex.count >= 12 && hex.count == id.count) ? hex : derivedID(from: id)
        // Belt and braces. The id alone already makes a forged closer useless, since the
        // attacker cannot guess it, but neutralising the literal keeps the transcript
        // readable and removes any doubt about what closed the block.
        //
        // Both tags, and case insensitively. This handled `</untrusted_data` only, exactly
        // spelled, which left two gaps in a defence whose entire job is to be unambiguous:
        //
        //   `</UNTRUSTED_DATA id="...">` passed through untouched, and a model reading a
        //   transcript does not owe you case sensitivity when every markup language it has
        //   ever seen is case-insensitive about tags.
        //
        //   The OPENING literal passed through too. That one does not escape the block,
        //   the real closer still carries the real id and still ends it, so the original
        //   framing of this as an escape is wrong. What it does is let the body open a
        //   second, nested block with an attacker-chosen `kind`, so a page can print
        //   `<untrusted_data kind="operator_policy">` and invite the model to read what
        //   follows as a more trusted class of content. The fence exists to make the
        //   trust boundary unambiguous, and an attacker who can draw a boundary of their
        //   own inside it has taken exactly that away.
        //
        // Neither is a substring of the other, so the order of these two does not matter.
        let neutralised = redact(body)
            .replacingOccurrences(of: "</untrusted_data", with: "<\u{200B}/untrusted_data",
                                  options: .caseInsensitive)
            .replacingOccurrences(of: "<untrusted_data", with: "<\u{200B}untrusted_data",
                                  options: .caseInsensitive)
        return "<untrusted_data kind=\"\(safeKind)\" id=\"\(safeID)\">\n"
            + neutralised
            + "\n</untrusted_data id=\"\(safeID)\">"
    }

    /// 64 bits of unguessable fence id, rendered as hex.
    public static func newFenceID() -> String {
        String(format: "%016lx", UInt64.random(in: UInt64.min...UInt64.max))
    }

    /// Deterministic 64-bit id for a caller-supplied label. FNV-1a, which is not a
    /// cryptographic hash and is not pretending to be: a caller who passes a fixed label
    /// has chosen a predictable fence and the doc comment says so. It exists so that a
    /// non-hex label produces a full-width id instead of a six-character stub.
    private static func derivedID(from s: String) -> String {
        var h: UInt64 = 0xcbf29ce484222325
        for b in Array(s.utf8) {
            h ^= UInt64(b)
            h = h &* 0x100000001b3
        }
        return String(format: "%016lx", h)
    }

    // MARK: - Internals

    private static func replaceAll(in input: String, regex: NSRegularExpression, with replacement: String) -> String {
        let range = NSRange(input.startIndex..<input.endIndex, in: input)
        return regex.stringByReplacingMatches(
            in: input, options: [], range: range,
            withTemplate: NSRegularExpression.escapedTemplate(for: replacement))
    }

    private static func replaceHighEntropy(in input: String) -> String {
        guard let regex = entropyRegex else { return input }
        let nsInput = input as NSString
        let range = NSRange(location: 0, length: nsInput.length)
        let matches = regex.matches(in: input, options: [], range: range)
        guard !matches.isEmpty else { return input }

        // Single forward pass over NSString, which indexes UTF-16 in constant time.
        //
        // The previous version walked matches in reverse calling
        // `Range(match.range, in: result)` and mutating a Swift String. That conversion
        // is O(n) the moment the string is not all-ASCII, because Swift has to count
        // grapheme clusters from the start to find a UTF-16 offset. So ONE curly
        // apostrophe, emoji or non-breaking space anywhere in the input turned the whole
        // pass quadratic: 296KB went from 0.030s to 1.970s, a 65x cliff, triggered by a
        // character that appears in ordinary prose constantly.
        let out = NSMutableString(capacity: nsInput.length)
        var cursor = 0
        for match in matches {
            let token = nsInput.substring(with: match.range)
            // Defence in depth, not the active mechanism. Idempotence currently holds
            // because no marker contains a 40-character run from the entropy class, so
            // this branch is unreachable today. It stays because the moment somebody
            // widens that class, it becomes the thing standing between this function and
            // eating its own output.
            let skip = token.hasPrefix("[REDACTED:") || !looksLikeASecret(token)
            if skip { continue }
            out.append(nsInput.substring(with: NSRange(location: cursor, length: match.range.location - cursor)))
            out.append("[REDACTED:HIGH_ENTROPY]")
            cursor = match.range.location + match.range.length
        }
        if cursor == 0 { return input }
        out.append(nsInput.substring(from: cursor))
        return out as String
    }

    /// The false-positive budget, and the single most delicate judgement in this file.
    ///
    /// The old rule counted 4 character classes and treated `-` and `_` as one of them,
    /// which got the question backwards twice over. It fired on `kebab-case-identifiers`
    /// and file paths, which are punctuation-rich and secret-poor, while a 64-character
    /// random alphanumeric API token, which is nothing but entropy, scored 3 and walked
    /// straight through. Punctuation was never the signal.
    ///
    /// What actually distinguishes a secret from a long ordinary token is mixed case
    /// AND digits in the same run. Prose does not do that. Identifiers do not do that.
    /// Hex digests do not do that, since they are single-case by convention, which is
    /// what keeps git SHAs and md5 sums intact.
    /// A, E, I, O, U and Y, either case. The cheapest usable test for "this run of letters
    /// is a word". Random base64 clears the letters-only test by accident far more often
    /// than it clears letters-only AND contains a vowel.
    private static func isVowel(_ v: UInt32) -> Bool {
        switch v {
        case 0x41, 0x45, 0x49, 0x4F, 0x55, 0x59: return true   // A E I O U Y
        case 0x61, 0x65, 0x69, 0x6F, 0x75, 0x79: return true   // a e i o u y
        default: return false
        }
    }

    private static func looksLikeASecret(_ s: String) -> Bool {
        var upper = false, lower = false, digit = false, base64Padding = false
        var sawPlus = false
        var sawURLSafe = false
        var runLength = 0
        var sawSlash = false
        var segment = 0
        var shortSegments = 0
        var leadingEmpty = false
        var isFirstSegment = true
        // Per-segment state for the name signal below. Tracked in the same pass so the
        // function stays one linear scan.
        var segmentCount = 0
        var namelikeSegments = 0
        var segmentHasVowel = false
        var segmentIsNamelike = true

        func closeSegment() {
            segmentCount += 1
            if segment >= 4 && segmentHasVowel && segmentIsNamelike { namelikeSegments += 1 }
            segmentHasVowel = false
            segmentIsNamelike = true
        }

        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x41...0x5A:
                upper = true; segment += 1
                if isVowel(scalar.value) { segmentHasVowel = true }
            case 0x61...0x7A:
                lower = true; segment += 1
                if isVowel(scalar.value) { segmentHasVowel = true }
            case 0x30...0x39: digit = true; segment += 1; segmentIsNamelike = false
            // `+` and `=` are tracked SEPARATELY and the difference is a leak. `+` belongs
            // to standard base64 only. `=` is padding and is shared by BOTH alphabets, so
            // it says nothing about which one is in use and cannot take part in the
            // mixed-alphabet test below.
            case 0x2B:                                            // +, standard base64 only
                base64Padding = true; sawPlus = true
                segment += 1; segmentIsNamelike = false
            case 0x3D:                                            // =, padding, either one
                base64Padding = true; segment += 1; segmentIsNamelike = false
            case 0x2D, 0x5F:                                      // - and _, base64url only
                sawURLSafe = true; segment += 1
            case 0x2F:                                            // the path separator
                sawSlash = true
                if isFirstSegment && segment == 0 { leadingEmpty = true }
                if segment < 4 { shortSegments += 1 }
                isFirstSegment = false
                closeSegment()
                segment = 0
            default: segment += 1
            }
            runLength += 1
        }
        if sawSlash && segment < 4 { shortSegments += 1 }
        if sawSlash { closeSegment() }

        // Base64 padding is decisive and is checked BEFORE the path rule. It used to run
        // after, which meant a blob carrying `+` and `==` could still be thrown away as a
        // path because of one unlucky short run between slashes.
        //
        // The brake exists because this shortcut returns true before ANY other rule gets a
        // say, so anything it gets wrong is unrecoverable. Without it, a plus-addressed
        // email address was destroyed the moment its local part reached 40 characters:
        // `support+order-confirmation-and-shipping-updates@motorcityorganics.com` came out
        // as `[REDACTED:HIGH_ENTROPY]@motorcityorganics.com`. All lowercase, no digit, and
        // nothing downstream could object because this line had already returned.
        //
        // The brake is `+` TOGETHER WITH `-` or `_`, and the precision matters more than it
        // looks. Standard base64 is `A-Za-z0-9+/` and base64url is `A-Za-z0-9-_`, so no
        // real token carries a `+` alongside a `-` or `_`. **But `=` is padding and belongs
        // to BOTH alphabets**, so it says nothing about which is in use.
        //
        // The first version of this brake missed that and tested `+` or `=` against `-` or
        // `_`, which spared raw `base64.urlsafe_b64encode()` output with its padding left
        // on: `aojyTcDoAfFSVWztzGhCANprePvlznHDQqs-oTX-PQ==` went from redacted to fully
        // in the clear. That is the ordinary shape of a password-reset token, an email
        // verification token or a signed cookie, it carries no `/` so no path rule applies
        // either, and with no digit it fell through the final test as well. A fix for a
        // cosmetic mangle had opened a real leak, which is the wrong side of this trade in
        // every case.
        //
        // What is still deliberately traded away: a plus-addressed local part of 40 or more
        // characters containing NO hyphen and NO underscore is still redacted. That case
        // annoys, and the one above harms.
        if base64Padding && !(sawPlus && sawURLSafe) && runLength >= 40 { return true }

        // Path rejection, on TWO weak signals rather than one.
        //
        // The single-signal version rejected any token with one segment under four
        // characters, and base64 produces those by chance constantly. Measured over
        // 200,000 random 40-character AWS secret access keys it discarded 14% of them,
        // and the miss rate climbed with the length of the secret, reaching 34% at
        // session-token size. Rejecting the highest-value credential one time in seven,
        // to protect a cosmetic property, is the wrong side of that trade.
        //
        // A real path has either several short segments or an empty leading one, because
        // an absolute path opens with a separator. A base64 blob has at most one short
        // run and never opens with one.
        // Mean segment length is the third signal, and it is what separates a path from a
        // base64 blob that happens to contain a short run. A path is many short names
        // joined by separators, so its mean segment is small; a blob split by an incidental
        // slash leaves long segments either side. Without this, a bare 40-character key
        // with no label was discarded as a path about 1.7% of the time, and a bare key is
        // the case with no other signal to fall back on.
        // The leading separator alone is not enough, and the gap it left was the single
        // largest term in this file's published leak rate. `leadingEmpty` fires on ANY
        // token beginning with `/`, and a random base64 secret begins with `/` about one
        // time in 64, which is 1.56% and almost exactly the ~1.3% bare-token leak rate
        // that was being reported as a general weakness of the entropy rule. It was not
        // general at all: `/JalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12` walked out in the
        // clear while the same forty characters without the slash were redacted.
        //
        // A real absolute path of forty characters or more has more than one component.
        // Requiring three segments, meaning the empty leading one plus two more, keeps
        // every path fixture and takes the accidental leading slash away from a blob.
        if sawSlash && leadingEmpty && segmentCount >= 3 { return false }
        if sawSlash && shortSegments >= 2 && meanSegmentLength(of: s) < 10 { return false }

        // The name signal, and the one that generalises. Both rules above are shape rules,
        // and both are defeated by the same thing: a `.` anywhere earlier in the path. The
        // token class stops at a dot, so the match starts AFTER it, which throws away the
        // leading separator that `leadingEmpty` depends on and re-bases the segment
        // statistics on whatever follows. Measured over 814 real paths and URLs from this
        // machine, 357 of them, 43.9%, were destroyed:
        // `/Users/x/Code/y/.build/arm64-apple-macosx/debug/ModuleCache/Darwin-2FHUQ8FY7X9OP`
        // matched from `build` onward and went out as one redaction. A GitHub permalink is
        // the same defect wearing a URL: `https://github.com/owner/repo/blob/<sha>/README.md`
        // matched from `com` onward, and it survived review only because the fixture in the
        // test used single-letter owner and repo names, which is what dragged the mean
        // segment length under 10. Real names are longer.
        //
        // So the third signal is not a shape at all, it is content: a path segment is a
        // NAME. Four characters or more, letters plus at most a hyphen or an underscore, no
        // digits, and at least one vowel. Random base64 clears letters-only by accident far
        // more often than it clears letters-only AND a vowel, which is the entire reason the
        // vowel test is there rather than being a flourish: `mtgk`, `DTZfp`, `CRKFLDvGh` and
        // `ZQRd` are the runs that were buying blobs a free pass.
        //
        // Three such names, a majority of the segments, and four segments minimum. Every
        // threshold here was measured rather than chosen. The AWS secret access key decides
        // the floor of four: its two slashes leave three segments, so it can never reach
        // this rule at all.
        //
        // Price, measured causally rather than estimated. 100,000 random base64 strings at
        // each of 40, 64, 128 and 200 characters, generated from a fixed seed and run
        // through the redactor with and without this rule, so the difference is the exact
        // set of secrets newly spared and not a sampling artefact. 24.0 per 400,000,
        // measured over ten seeds and 4,000,000 trials as 240 newly spared against zero
        // newly caught, against 355 of 814 real paths that stopped being destroyed.
        // Without the vowel test the cost roughly triples.
        //
        // The first version of this comment said "twelve" and meant it as a fact. Ten seeds
        // range from 15 to 31, and two earlier one-off runs gave 12 and 22, so the twelve
        // was the lowest of everything measured and was published alone as though the seed
        // made it exact. A fixed seed makes the COMPARISON exact, because both arms see
        // identical inputs, and says nothing about how much the estimate itself moves.
        // Seeding removes the noise between two arms, never the noise in the number.
        if segmentCount >= 4 && namelikeSegments >= 3 && namelikeSegments * 2 >= segmentCount { return false }

        return upper && lower && digit && runLength >= 32
    }
}
