import Foundation

/// The acceptance gate for `SecretRedactor`, and the thing that replaces "65 tests green".
///
/// Five audit rounds each found credential leaks that the unit tests were structurally
/// blind to, because every label case the suite exercised happened to be snake_case and
/// keyword-first. `POSTGRES_PASSWORD=` was covered, so `DB_PASS=` on the next line looked
/// covered too. It was not, and nothing in the suite could tell.
///
/// So correctness here is defined by two corpora with published numbers rather than by a
/// count of passing assertions:
///
/// - `LEAKS` must reach **zero survivors**. Every entry contains a credential that must
///   not reach a model. A survivor is a hard failure.
/// - `BENIGN` must reach **zero mangles**. Every entry is ordinary text an agent reads
///   constantly. A redactor that eats these is one people switch off.
///
/// Both are deliberately adversarial about SPELLING rather than about exotic formats,
/// because spelling is where every real leak has come from: camelCase, glued words,
/// abbreviations, an intervening scheme word, a different delimiter.
///
/// Every credential below is synthetic.
enum Corpus {

    struct Case {
        let label: String
        /// The full line as an agent would encounter it.
        let text: String
        /// The substring that must NOT survive redaction.
        let secret: String
    }

    // MARK: - Must never survive

    static let leaks: [Case] = [
        // Env vars, the spellings that actually appear in the wild.
        Case(label: "env/snake", text: "POSTGRES_PASSWORD=s3cretPassw0rdForProd", secret: "s3cretPassw0rdForProd"),
        Case(label: "env/abbrev-pass", text: "DB_PASS=s3cretPassw0rdForProd", secret: "s3cretPassw0rdForProd"),
        Case(label: "env/abbrev-pwd", text: "MYSQL_PWD=s3cretPassw0rdForProd", secret: "s3cretPassw0rdForProd"),
        Case(label: "env/rabbit", text: "RABBITMQ_DEFAULT_PASS=s3cretPassw0rdForProd", secret: "s3cretPassw0rdForProd"),
        Case(label: "env/pg-glued", text: "PGPASSWORD=s3cretPassw0rdForProd", secret: "s3cretPassw0rdForProd"),
        Case(label: "env/private-key", text: "PRIVATE_KEY=abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "env/session", text: "SESSION_KEY=abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "env/export", text: "export API_TOKEN=abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "env/quoted", text: "SECRET_KEY='abcdefghijklmnopqrstuvwxyz012345'", secret: "abcdefghijklmnopqrstuvwxyz012345"),

        // camelCase and glued, which the boundary-anchored matcher could never reach.
        Case(label: "camel/accessToken", text: "accessToken=abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "camel/clientSecret", text: "clientSecret: abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "camel/refreshToken", text: "\"refreshToken\": \"abcdefghijklmnopqrstuvwxyz012345\"", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "glued/npmrc", text: "_auth=abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),

        // HTTP, where an auth-scheme word sits between the separator and the credential.
        Case(label: "http/bearer", text: "Authorization: Bearer 8f14e45fceea167a5a36dedd4bea2543", secret: "8f14e45fceea167a5a36dedd4bea2543"),
        Case(label: "http/basic", text: "Authorization: Basic ZGVwbG95Ym90Omh1bnRlcjIK", secret: "ZGVwbG95Ym90Omh1bnRlcjIK"),
        Case(label: "http/token-scheme", text: "Authorization: token ghp_ABCDEFGHIJ0123456789abcdefghij0123", secret: "ghp_ABCDEFGHIJ0123456789abcdefghij0123"),
        Case(label: "http/x-api-key", text: "X-Api-Key: abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),

        // Credentials inside URLs. URLGuard denies this shape unconditionally, so the two
        // halves of the package disagreed about whether user:pass@ is a credential.
        Case(label: "url/postgres", text: "DATABASE_URL=postgres://app_user:s3cretPassw0rdForProd@db.acme.io:5432/prod", secret: "s3cretPassw0rdForProd"),
        Case(label: "url/redis", text: "redis://default:hunter2hunter2hunter2@cache.acme.io:6379", secret: "hunter2hunter2hunter2"),
        Case(label: "url/mongo", text: "mongodb+srv://svc:P4ssw0rdP4ssw0rd@cluster0.acme.mongodb.net", secret: "P4ssw0rdP4ssw0rd"),
        Case(label: "url/git", text: "https://deploybot:ghp_ABCDEFGHIJ0123456789abcdefghij0123@github.com/acme/private.git", secret: "ghp_ABCDEFGHIJ0123456789abcdefghij0123"),

        // Other delimiters and shapes.
        Case(label: "netrc", text: "machine api.acme.io login deploybot password s3cretPassw0rdForProd", secret: "s3cretPassw0rdForProd"),
        Case(label: "yaml/indented", text: "  client_secret: abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "query/access-token", text: "https://api.acme.io/v1/me?access_token=abcdefghijklmnopqrstuvwxyz012345&x=1", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "dotted-value", text: "auth_token: 3f2504e0-4f89-11d3-9a0c-0305e82c3301.SGVsbG9TaWduYXR1cmVIZXJl", secret: "SGVsbG9TaWduYXR1cmVIZXJl"),

        // Provider prefixes, which must keep working.
        Case(label: "provider/anthropic", text: "key sk-ant-api03-ABCDEF0123456789abcdef here", secret: "sk-ant-api03-ABCDEF0123456789abcdef"),
        Case(label: "provider/hf", text: "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", secret: "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"),
        Case(label: "provider/stripe", text: "sk_live_ABCDEFGHIJ0123456789abc", secret: "sk_live_ABCDEFGHIJ0123456789abc"),
        Case(label: "provider/supabase", text: "sbp_0123456789abcdef0123456789abcdef01234567", secret: "sbp_0123456789abcdef0123456789abcdef01234567"),

        // Round 6. Names carrying no credential word at all: a session identifier is what
        // a stolen cookie replays, so it is a credential even though nothing in it says so.
        Case(label: "cookie/set-cookie", text: "Set-Cookie: session=3f8a9c2b1d4e5f6a7b8c9d0e1f2a3b4c", secret: "3f8a9c2b1d4e5f6a7b8c9d0e1f2a3b4c"),
        Case(label: "cookie/header", text: "Cookie: sid=abc123def456ghi789jkl012", secret: "abc123def456ghi789jkl012"),
        Case(label: "cookie/jsessionid", text: "JSESSIONID=A1B2C3D4E5F6A7B8C9D0E1F2", secret: "A1B2C3D4E5F6A7B8C9D0E1F2"),
        Case(label: "csrf", text: "csrf=9f8e7d6c5b4a39281706f5e4d3c2b1a0", secret: "9f8e7d6c5b4a39281706f5e4d3c2b1a0"),

        // Separators the scanner could not previously reach.
        Case(label: "sep/rocket", text: "apiKey => abcdefghijklmnopqrstuvwxyz012345", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "sep/call", text: "setApiKey(\"abcdefghijklmnopqrstuvwxyz012345\")", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "yaml/next-line", text: "password:\n  abcdefghijklmnopqrstuvwxyz012345\n", secret: "abcdefghijklmnopqrstuvwxyz012345"),
        Case(label: "yaml/block-scalar", text: "  clientSecret: >-\n    abcdefghijklmnopqrstuvwxyz012345\n", secret: "abcdefghijklmnopqrstuvwxyz012345"),

        // A scheme with no header name in front of it, which is how request logs print it.
        // Lowercase hex, so the entropy pass cannot see it: that rule needs mixed case.
        Case(label: "scheme/bare-bearer", text: "Bearer 8f14e45fceea167a5a36dedd4bea2543", secret: "8f14e45fceea167a5a36dedd4bea2543"),
        Case(label: "flag/curl-u", text: "curl -u deploybot:hunter2Passw0rd https://api.acme.io", secret: "hunter2Passw0rd"),
        Case(label: "flag/long-password", text: "deploy --password s3cretPassw0rdForProd --verbose", secret: "s3cretPassw0rdForProd"),

        // Round 7. An INDENTED PEM. The whole-block pattern is line-anchored and had no
        // tolerance for leading whitespace, so a key inside YAML, JSON, a markdown block
        // or a code sample matched its header and stopped. The body then depended
        // entirely on the entropy pass, which needs mixed case AND a digit, so a
        // single-case base64 line walked out verbatim underneath a header that had been
        // helpfully replaced with [REDACTED:PEM]. The unindented form was consumed whole,
        // which is exactly what made it look covered.
        Case(label: "pem/indented",
             text: "  -----BEGIN RSA PRIVATE KEY-----\n  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  -----END RSA PRIVATE KEY-----",
             secret: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Case(label: "pem/yaml-block",
             text: "tls:\n  key: |\n    -----BEGIN PRIVATE KEY-----\n    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n    -----END PRIVATE KEY-----",
             secret: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    ]

    // MARK: - Must never be modified

    static let benign: [String] = [
        // Paths, the original reason `/` was almost removed from the alphabet.
        "/var/folders/mn/2xk8h9_d3qz7fzz1234567890/T/build-output.log",
        "https://github.com/a/b/blob/4f9a2c1e8d7b6a5f4e3d2c1b0a9f8e7d6c5b4a39/File.swift",
        "~/Library/Developer/Xcode/DerivedData/App-abcdefghijklmnop/Build/Products",
        "/usr/local/lib/node_modules/npm/node_modules/graceful-fs/polyfills.js",

        // Identifiers that look secret-ish and are not.
        "kCVPixelFormatType_32BGRA_FullRange",
        "NSApplicationDidFinishLaunchingNotification",
        "Access-Control-Allow-Credentials",
        "feature/JIRA-1234-add-new-thing-here",
        "elegant_wozniak_containername_1234",

        // Digests, kept single case by convention, which is what protects them.
        "4f9a2c1e8d7b6a5f4e3d2c1b0a9f8e7d6c5b4a39",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "d41d8cd98f00b204e9800998ecf8427e",

        // Assignments whose NAME contains a keyword but whose VALUE is not a secret.
        // These are the false positives a name-based matcher invites.
        "LOG_LEVEL=debug",
        "user=alice",
        "auth=none",
        "token_type=bearer",
        "authors=alice,bob",
        "tokenizer=wordpiece",
        "PATH=/usr/local/bin:/usr/bin",
        "CONTAINER_IMAGE_DIGEST=sha256_abcdefghijklmnopqrstuvwxyz",

        // Names containing credential words whose VALUES are not credentials. These are
        // the false positives that substring matching and a whitespace separator invite,
        // so they are the brake's job.
        "PARTITION_KEY=created_at",
        "PRIMARY_KEY=user_id",
        "SORT_KEY=timestamp",
        "keyboard_layout=qwerty",
        "password reset requested by admin",
        "the auth flow expired",
        "monkey_patch=enabled",

        // Ordinary prose and structure.
        "The meeting is at 3pm, ask sk about it.",
        "Run the task with --sk-mode enabled.",
        "task-management-system",
        "12345678901234567890123456789012345678901234567890",

        // Round 6. The whitespace separator used to make the token AFTER any token
        // containing a credential word disappear, which destroyed URLs, filenames and
        // paths in ordinary sentences. Measured against this project's own 8,590 lines of
        // source and docs, that and the punctuation-only value brake were together
        // destroying 0.780% of all lines. It is 0.396% now. These are the shapes that
        // regression would come back through.
        "reset your password https://example.com/reset",
        "see the auth README.md for setup",
        "auth failures are logged to /var/log/auth.log",
        "private notes live in ~/Documents/Notes/2026-08-09.md",
        "token counts are per-request, see docs/tokenizer.md",
        // Code, which an agent reads more of than it reads prose. The call-shaped
        // separator added in round 6 has to leave all of these alone.
        "func authenticate(user: String) async throws -> Session",
        "decryptWithKey(masterKeyMaterial)",
        "public private(set) var isReady = false",
        "case keyAnthropic = \"key.anthropic\"",
        "\"key\": \"projects_json\",",
        // Scheme words in prose. The bare `Bearer <token>` rule must not reach these.
        "Basic understanding of the auth flow is assumed",
        "bearer bonds were the collateral",
        "the session lasted forty minutes",
        // A uid:gid pair is not a credential, which is why the -u rule needs six
        // characters on the password half.
        "docker run -u 1000:1000 alpine",

        // Round 7. These four are the ONLY entries that exercise the whitespace-separable
        // name brake, and they exist because neutering that brake left all 82 tests green.
        // It shipped in round six with a CHANGELOG paragraph and no coverage at all: every
        // prose case written to justify it was actually being saved by the LOCATOR brake
        // sitting next to it, because each one happened to contain a URL, a path or a
        // filename. A guard that cannot be broken by a test is a guard nobody is checking.
        //
        // Each of these has a credential word buried inside a longer token, then
        // whitespace, then a value that clears the credential-shape brake and is not a
        // locator. Delete isWhitespaceSeparable and every one of them is destroyed.
        "the keyboard Serial9912345 was replaced",
        "the passenger Manifest2024 boarded early",
        "authorial Voice2026 is the whole point",
        "a keystone Species4471 went extinct",

        // Round 8. Paths and URLs that carry a DOT before the interesting part. The dot is
        // the whole problem: it is not in the token class, so the entropy match starts
        // after it, which discards the leading separator `leadingEmpty` needs and re-bases
        // the segment statistics on the remainder. Every one of these was destroyed before
        // the name signal landed, and none of them is saved by either older path rule.
        //
        // Measured on 814 real paths and URLs taken off this machine: 357 mangled, 43.9%.
        // The permalink is the one that made it visible, and it is worth noting WHY it
        // survived seven rounds of review. The fixture in testPathsStillSurvive uses
        // `github.com/a/b/blob/...`, and single-letter owner and repo names are what drag
        // the mean segment length under 10. Real names are longer, so the real URL failed
        // while the test that claimed to cover it passed.
        "https://github.com/acmewidget/demo-kit/blob/78790dd41a807c18621e06ef82d6ec45048cef1c/README.md",
        "https://github.com/anthropics/claude-code/blob/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b/CHANGELOG.md",
        "/Users/dev/Code/proj/.build/arm64-apple-macosx/debug/ModuleCache/Foundation-RFLD5H6WW7NI.swiftmodule",
        "~/Library/Application Support/Grux/reports/mentions-2026-08-09.md",
        "https://storage.googleapis.com/MyBucket/Uploads/2026/08/09/ReportFinal.pdf",
        "s3://my-production-bucket/Exports/Daily/2026-08-09/UserActivitySnapshot.parquet",
    ]
}
