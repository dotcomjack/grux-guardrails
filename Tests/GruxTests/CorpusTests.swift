import XCTest
@testable import GruxGuardrails

/// The gate. These two numbers are the definition of correct, and they are published in
/// the README, so anyone can re-run them and check.
final class CorpusTests: XCTestCase {

    /// Zero survivors. A survivor means a credential reached the model.
    func testLeakCorpusHasZeroSurvivors() {
        var survivors: [String] = []
        for c in Corpus.leaks {
            let out = SecretRedactor.redact(c.text)
            if out.contains(c.secret) { survivors.append("\(c.label): \(out)") }
        }
        XCTAssertEqual(survivors.count, 0,
                       "\(survivors.count)/\(Corpus.leaks.count) leaked:\n" + survivors.joined(separator: "\n"))
    }

    /// Zero mangles. A mangle means ordinary text was destroyed, which is how a redactor
    /// gets switched off, and a switched-off redactor protects nothing.
    func testBenignCorpusHasZeroMangles() {
        var mangled: [String] = []
        for text in Corpus.benign {
            let out = SecretRedactor.redact(text)
            if out != text { mangled.append("\(text)\n   -> \(out)") }
        }
        XCTAssertEqual(mangled.count, 0,
                       "\(mangled.count)/\(Corpus.benign.count) mangled:\n" + mangled.joined(separator: "\n"))
    }

    /// A statistical gate, because a 14% leak once hid behind a single hand-picked
    /// fixture that happened to pass. Bare high-entropy credentials with no label to help.
    func testBareCredentialLeakRateIsPublished() {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        var generator = SystemRandomNumberGenerator()
        var leaked = 0
        let trials = 20_000
        for _ in 0..<trials {
            let key = String((0..<40).map { _ in alphabet[Int(generator.next() % 64)] })
            if SecretRedactor.redact(key).contains(key) { leaked += 1 }
        }
        let rate = Double(leaked) / Double(trials) * 100
        print(String(format: "bare 40-char credential leak rate: %.3f%% (%d/%d)", rate, leaked, trials))
        // ~0.85% as measured, observed between 0.78% and 0.97% across runs because every
        // run draws fresh credentials, and published rather than tuned away. This is the
        // hardest case in the library: a credential with NO label and NO provider prefix,
        // which is textually indistinguishable from a base64-ish path fragment. In practice
        // almost every real credential carries one signal or the other, and both of those
        // paths are at zero.
        //
        // The number above read 1.3% until 2026-08-14. That was the pre-0.5.0 rate: 0.5.0
        // took it from 1.295% to 0.875% and updated the CHANGELOG without updating this
        // comment, CONTRIBUTING.md rule 6, or docs/CORPUS.md. One measurement lived in four
        // places and only one of them moved. If this rate changes again, grep for it.
        //
        // The 2.0 guard is LOOSER than CONTRIBUTING.md rule 6 asks for. At 20,000 trials the
        // sampling deviation is about 0.065 points, so 2.0 sits roughly 18 deviations above
        // the mean and the rate could more than double before this trips. A guard of 1.5
        // would still clear noise by 10 deviations. It is left at 2.0 for now and written
        // down rather than quietly narrowed, because moving a published threshold in either
        // direction is a change to the claim the library makes.
        XCTAssertLessThan(rate, 2.0, "bare credential leak rate regressed to \(rate)%")
    }

    /// Nothing but a wall clock would have caught the cubic pattern that shipped in 0.4.0,
    /// where 8KB of ordinary CSS-class-shaped text took 40 seconds.
    func testNoInputShapeIsSuperlinear() {
        let shapes: [(String, (Int) -> String)] = [
            ("hyphen-joined keywords", { n in (0..<n).map { "data-auth-state-x\($0)" }.joined(separator: "-") }),
            ("underscore run", { n in (0..<n).map { "a\($0)_token_b\($0)" }.joined(separator: "_") }),
            ("repeated PEM headers", { n in String(repeating: "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n", count: n) }),
            ("query string", { n in "https://x.io/?" + (0..<n).map { "k\($0)=v\($0)" }.joined(separator: "&") }),
            // Round 6. One unbroken run of name characters that is nothing but credential
            // words. Every start position in a run shares its end, so restarting one
            // character along re-walked the whole remainder: 48KB of this cost eleven
            // seconds and 80KB of the dotted form cost twenty. The shape was already
            // covered by the first row above and survived anyway, purely because 8KB is
            // small enough to stay under the time budget. Scale is part of the test.
            ("unbroken keyword run", { n in String(repeating: "key", count: n * 40) }),
            ("unbroken dotted run", { n in String(repeating: "auth.", count: n * 40) }),
        ]
        for (name, build) in shapes {
            let small = build(50)
            let large = build(400)          // 8x the input
            let t0 = Date(); _ = SecretRedactor.redact(small)
            let smallTime = max(Date().timeIntervalSince(t0), 0.0005)
            let t1 = Date(); _ = SecretRedactor.redact(large)
            let largeTime = Date().timeIntervalSince(t1)
            // 8x input should cost well under 64x (quadratic). Anything worse is a hang.
            XCTAssertLessThan(largeTime, 5.0,
                              "\(name): 8x input took \(largeTime)s (small was \(smallTime)s)")
            // And the ratio itself, because an absolute budget alone is what let the
            // quadratic through: a slow-but-quadratic shape passes it until the input grows.
            XCTAssertLessThan(largeTime / max(smallTime, 0.001), 24.0,
                              "\(name): 8x input cost \(largeTime / smallTime)x, which is superlinear")
        }
    }
}
