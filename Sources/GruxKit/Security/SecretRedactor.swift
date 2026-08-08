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
///    each cleaned on the way in. Without this, `[REDACTED:ANTHROPIC_KEY]` is itself a
///    long mixed-class token and the entropy pass eats its own output.
///
/// This is deliberately a matcher, not a parser. It cannot catch a secret that does
/// not look like one, and it is the last line rather than the only one. Do not use it
/// to justify feeding the agent credentials it did not need.
public enum SecretRedactor {

    /// Ordered, most-specific prefixes first, JWT before generic entropy, generic last.
    private static let patterns: [(tag: String, regex: NSRegularExpression)] = {
        let raw: [(String, String)] = [
            ("ANTHROPIC_KEY", #"sk-ant-[A-Za-z0-9_\-]{10,}"#),
            // Generic OpenAI-style secret key (sk-... and sk-proj-...). Runs after the
            // more specific sk-ant- so Anthropic keys keep their own tag. The 16-char
            // floor catches real keys, which are far longer, while leaving short "sk-"
            // prose alone.
            ("OPENAI_KEY", #"sk-(?:proj-)?[A-Za-z0-9_\-]{16,}"#),
            ("AWS_KEY", #"AKIA[0-9A-Z]{16}"#),
            ("PEM", #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#),
            ("GITHUB_PAT", #"ghp_[A-Za-z0-9]{30,}"#),
            ("GITHUB_FINE_GRAINED", #"github_pat_[A-Za-z0-9_]{20,}"#),
            ("SLACK_TOKEN", #"xox[baprs]-[A-Za-z0-9\-]{20,}"#),
            ("STRIPE_LIVE_SECRET", #"sk_live_[A-Za-z0-9]{20,}"#),
            ("STRIPE_LIVE_PUBLIC", #"pk_live_[A-Za-z0-9]{20,}"#),
            ("STRIPE_LIVE_RESTRICTED", #"rk_live_[A-Za-z0-9]{20,}"#),
            ("ELEVENLABS_KEY", #"sk_[a-f0-9]{48,}"#),
            ("JWT", #"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"#)
        ]
        return raw.compactMap { pair in
            (try? NSRegularExpression(pattern: pair.1, options: [])).map { (pair.0, $0) }
        }
    }()

    /// Generic high-entropy run, executed LAST so the specific patterns get first crack.
    /// Word-ish lookarounds and a 40-character floor, and a token is only redacted when
    /// it spans at least 4 character classes (upper, lower, digit, symbol). That filter
    /// is what keeps long base-ten numbers, hex digests, repeated letters and ordinary
    /// long words out of the redactor.
    private static let entropyRegex: NSRegularExpression? = {
        try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9])[A-Za-z0-9+/=_\-]{40,}(?![A-Za-z0-9])"#,
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
    /// Pipe ANY screen, ambient, file or network text through this before it reaches a
    /// prompt. The fence is not a guarantee, it is a signal the model can act on, and it
    /// is strictly better than concatenation.
    public static func wrapAsUntrusted(_ kind: String, _ body: String) -> String {
        return "<untrusted_data kind=\"\(kind)\">\n\(redact(body))\n</untrusted_data>"
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
            // Skip anything that is already a redaction marker. This is the line that
            // makes redact() idempotent.
            if token.hasPrefix("[REDACTED:") { continue }
            if charClassCount(token) >= 4 {
                result.replaceSubrange(swiftRange, with: "[REDACTED:HIGH_ENTROPY]")
            }
        }
        return result
    }

    private static func charClassCount(_ s: String) -> Int {
        var upper = false, lower = false, digit = false, symbol = false
        for scalar in s.unicodeScalars {
            if scalar.value >= 0x41 && scalar.value <= 0x5A { upper = true }
            else if scalar.value >= 0x61 && scalar.value <= 0x7A { lower = true }
            else if scalar.value >= 0x30 && scalar.value <= 0x39 { digit = true }
            else { symbol = true }
        }
        var n = 0
        if upper { n += 1 }
        if lower { n += 1 }
        if digit { n += 1 }
        if symbol { n += 1 }
        return n
    }
}
