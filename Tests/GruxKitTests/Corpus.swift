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

        // Ordinary prose and structure.
        "The meeting is at 3pm, ask sk about it.",
        "Run the task with --sk-mode enabled.",
        "task-management-system",
        "12345678901234567890123456789012345678901234567890",
    ]
}
