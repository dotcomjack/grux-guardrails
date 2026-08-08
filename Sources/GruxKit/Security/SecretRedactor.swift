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
                  + #"(?:[ \t]*[\r\n]+[A-Za-z0-9+/=]{16,})*"#
                  + #"(?:[ \t]*[\r\n]+-----END [A-Z0-9 ]*PRIVATE KEY-----)?"#),
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
            ("JWT", L + #"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"#)
        ]
        return raw.compactMap { pair in
            (try? NSRegularExpression(pattern: pair.1, options: [])).map { (pair.0, $0) }
        }
    }()

    /// Generic high-entropy run, executed LAST so the specific patterns get first crack.
    ///
    /// `/` is deliberately NOT in this class. It used to be, and the result was that
    /// `/var/folders/mn/2xk8h9_d3qz7fzz.../T/build.log` matched as ONE token and the
    /// whole path was replaced, as was a GitHub permalink including its domain. A path
    /// separator is structure, not secret material, so excluding it splits a path into
    /// short segments that fall under the length floor on their own.
    private static let entropyRegex: NSRegularExpression? = {
        try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9])[A-Za-z0-9+=_\-]{32,}(?![A-Za-z0-9])"#,
            options: []
        )
    }()

    /// Replace every secret-shaped token in `input` with `[REDACTED:KIND]`.
    /// Safe to call repeatedly on its own output.
    public static func redact(_ input: String) -> String {
        var out = input
        for (tag, regex) in patterns {
            out = replaceAll(in: out, regex: regex, with: "[REDACTED:\(tag)]")
        }
        out = replaceHighEntropy(in: out)
        return out
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
        let safeID = id.filter { $0.isHexDigit }
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
        String(UInt64.random(in: UInt64.min...UInt64.max), radix: 16)
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

        // Walk matches in reverse so earlier ranges stay valid as we mutate.
        var result = input
        for match in matches.reversed() {
            guard let swiftRange = Range(match.range, in: result) else { continue }
            let token = String(result[swiftRange])
            // Defence in depth, not the active mechanism. Idempotence currently holds
            // because no marker contains a 32-character run from the entropy class, so
            // this branch is unreachable today. It stays because the moment somebody
            // widens that class, it becomes the thing standing between this function and
            // eating its own output.
            if token.hasPrefix("[REDACTED:") { continue }
            if looksLikeASecret(token) {
                result.replaceSubrange(swiftRange, with: "[REDACTED:HIGH_ENTROPY]")
            }
        }
        return result
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
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x41...0x5A: upper = true
            case 0x61...0x7A: lower = true
            case 0x30...0x39: digit = true
            case 0x2B, 0x3D: base64Padding = true   // + and =, the base64 tell
            default: break                           // - and _ carry no signal
            }
            runLength += 1
        }
        // A long base64 blob is worth redacting even when it happens to be single case,
        // because + and = do not occur in identifiers or prose.
        if base64Padding && runLength >= 40 { return true }
        return upper && lower && digit && runLength >= 32
    }
}
