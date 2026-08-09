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
            ("PEM", #"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"#
                  + #"(?:[ \t]*[\r\n]+[A-Za-z0-9+/=]{4,})*"#
                  + #"(?:[ \t]*[\r\n]+-----END [A-Z0-9 ]*PRIVATE KEY-----)?"#),
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
                  + #"(?:\\r?\\n[A-Za-z0-9+/=]{4,})*"#
                  + #"(?:\\r?\\n-----END [A-Z0-9 ]*PRIVATE KEY-----)?"#),
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
        out = redactLabelledValues(in: out)
        out = replaceHighEntropy(in: out)
        return out
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

            var j = nameEnd
            while j < s.count, s[j] == "\"" || s[j] == "'" { j += 1 }
            let beforeSpace = j
            while j < s.count, s[j] == " " || s[j] == "\t" { j += 1 }
            if j < s.count, s[j] == "=" || s[j] == ":" {
                j += 1
                while j < s.count, s[j] == " " || s[j] == "\t" { j += 1 }
            } else if j > beforeSpace {
                // Whitespace alone is a separator too. netrc writes `password hunter2`,
                // and so does every CLI flag (`--password hunter2`). Requiring = or :
                // meant a .netrc, which exists to hold credentials, leaked entirely.
                // Prose survives this because the value brake rejects short words:
                // "password reset requested" yields "reset", which is not a credential.
            } else {
                out.append(s[i]); i += 1; continue
            }

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
                out.append(s[i]); i += 1; continue
            }
            out.append(contentsOf: s[i..<valueStart])
            out.append("[REDACTED:ASSIGNED_SECRET]")
            i = j
        }
        return out
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
        // Punctuation alone is the weakest signal, because snake_case identifiers carry it:
        // PARTITION_KEY=created_at is a column name, not a credential. Require real length
        // before punctuation on its own is enough.
        return hasSymbol && v.count >= 12
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
        let range = NSRange(input.startIndex..<input.endIndex, in: input)
        return regex.stringByReplacingMatches(
            in: input, options: [], range: range,
            withTemplate: "$1[REDACTED:URL_CREDENTIAL]$3")
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
        let neutralised = redact(body)
            .replacingOccurrences(of: "</untrusted_data", with: "<\u{200B}/untrusted_data")
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
    private static func looksLikeASecret(_ s: String) -> Bool {
        var upper = false, lower = false, digit = false, base64Padding = false
        var runLength = 0
        var sawSlash = false
        var segment = 0
        var shortSegments = 0
        var leadingEmpty = false
        var isFirstSegment = true
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x41...0x5A: upper = true; segment += 1
            case 0x61...0x7A: lower = true; segment += 1
            case 0x30...0x39: digit = true; segment += 1
            case 0x2B, 0x3D: base64Padding = true; segment += 1  // + and =, the base64 tell
            case 0x2F:                                            // the path separator
                sawSlash = true
                if isFirstSegment && segment == 0 { leadingEmpty = true }
                if segment < 4 { shortSegments += 1 }
                isFirstSegment = false
                segment = 0
            default: segment += 1                                 // - and _ carry no signal
            }
            runLength += 1
        }
        if sawSlash && segment < 4 { shortSegments += 1 }

        // Base64 padding is decisive and is checked BEFORE the path rule. It used to run
        // after, which meant a blob carrying `+` and `==` could still be thrown away as a
        // path because of one unlucky short run between slashes.
        if base64Padding && runLength >= 40 { return true }

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
        if sawSlash && leadingEmpty { return false }
        if sawSlash && shortSegments >= 2 && meanSegmentLength(of: s) < 10 { return false }

        return upper && lower && digit && runLength >= 32
    }
}
