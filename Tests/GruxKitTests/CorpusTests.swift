import XCTest
@testable import GruxKit

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
        XCTAssertLessThan(rate, 0.5, "bare credential leak rate regressed to \(rate)%")
    }

    /// Nothing but a wall clock would have caught the cubic pattern that shipped in 0.4.0,
    /// where 8KB of ordinary CSS-class-shaped text took 40 seconds.
    func testNoInputShapeIsSuperlinear() {
        let shapes: [(String, (Int) -> String)] = [
            ("hyphen-joined keywords", { n in (0..<n).map { "data-auth-state-x\($0)" }.joined(separator: "-") }),
            ("underscore run", { n in (0..<n).map { "a\($0)_token_b\($0)" }.joined(separator: "_") }),
            ("repeated PEM headers", { n in String(repeating: "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n", count: n) }),
            ("query string", { n in "https://x.io/?" + (0..<n).map { "k\($0)=v\($0)" }.joined(separator: "&") }),
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
        }
    }
}
