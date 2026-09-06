# Staged security advisories

Six GHSA drafts, one per leaking tag, written and validated but **not filed and not
published**. This file is the runbook for filing them.

## Status

| Step | State | Gate |
|---|---|---|
| Bodies written | **Done.** `docs/advisories/*.json`, six payloads, schema validated | |
| Drafts created on GitHub | Not yet created, as of 2026-08-14 | The repository must be public first |
| Advisories published | **Not started, and gated on a human** | Jack's explicit call |

**Creating the drafts is blocked by the repository being private, and that is measured, not
assumed.** As of 2026-08-14:

```
$ gh api /repos/dotcomjack/grux/security-advisories
{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}
```

**That measurement is kept verbatim and its subject is now the wrong repository, which is
itself the story.** It was taken on 2026-08-14 against `dotcomjack/grux`, because 0.6.0 had
announced the package was moving there. It never moved. `dotcomjack/grux` was created on
2026-08-18 as the macOS application, and this package stayed at `dotcomjack/grux-guardrails`.
Every command below has been repointed. Re-measured 2026-09-06 against the real repository,
which is public:

```
$ gh api /repos/dotcomjack/grux-guardrails/security-advisories
[]
```

An empty array, not a 404, so the endpoint is reachable and the block is lifted.

That is a 404, not an empty array, so the endpoint is not merely empty: it is unreachable
while the repository is private. This is the same class of block as GitHub private
vulnerability reporting, which is also public-repos-only. Neither is an oversight, and
neither can be forced.

## Do not publish these early

**A published advisory cannot be unpublished.** GitHub will withdraw one on request, but it
has already been mirrored into the GitHub Advisory Database and out to downstream consumers
by then, so treat publication as irreversible.

Publishing before the repository is public is also pointless in the specific way that
matters: a GHSA on a private repository is not visible to the people who need it, and the
affected tags are not fetchable, so nobody can act on it. The moment to publish is the moment
the tags become resolvable, because that is when the advisory starts reaching a consumer's
`Package.resolved` through Dependabot instead of relying on somebody reading a page.

## Before you file anything

1. **Confirm the repository is public.**
   `gh api /repos/dotcomjack/grux-guardrails --jq .visibility` returns `public`.
2. **Confirm the package identity still matches.** Every payload names the package as
   `github.com/dotcomjack/grux-guardrails`. If the repository ever moves, update `vulnerabilities[0].package.name`
   in all six first, or they are filed against a path that does not resolve.
   `gh api /repos/dotcomjack/grux-guardrails --jq .full_name` returns `dotcomjack/grux-guardrails`.
3. **Confirm the affected tags are actually there.** `git ls-remote --tags origin` lists
   `0.1.0` through `0.4.0`. An advisory whose affected range matches no published tag is
   noise.
4. **Confirm `0.5.0` exists**, since it is the patched version on all six.

## File the drafts

Payloads are in `docs/advisories/`, numbered in the order the source material recommends
filing them. **File `6-tag-0.4.0.json` first.** `0.4.0` is the tag most likely to be pinned
in the wild, because it is the only pre-`0.5.0` tag whose own changelog entry says "Use this
one."

```
cd docs/advisories

# 0.4.0 first, deliberately.
gh api repos/dotcomjack/grux-guardrails/security-advisories --method POST --input 6-tag-0.4.0.json

# Then the rest.
for f in 1-tag-0.1.0.json 2-tag-0.2.0.json 3-tag-0.2.1.json 4-tag-0.3.0.json 5-tag-0.3.1.json; do
  echo "filing $f"
  gh api repos/dotcomjack/grux-guardrails/security-advisories --method POST --input "$f" --jq '.ghsa_id'
done
```

Each call returns a `ghsa_id` and leaves the advisory in state `draft`. **Creating a draft
is not publishing it.** Nothing is visible to anyone outside the repository until the
separate publish step below.

## Verify the drafts

This is the playbook's own ST-01 check. It must return at least one row, and after a clean
run it returns six.

```
gh api repos/dotcomjack/grux-guardrails/security-advisories \
  --jq '.[] | [.ghsa_id, .state, .cwe_ids[0]] | @tsv'
```

Expect six rows, every `state` reading `draft`, and a CWE on each. Then read one back in
full and check the rendered body before going further:

```
gh api repos/dotcomjack/grux-guardrails/security-advisories --jq '.[0]'
```

## Publish, which is the irreversible step

**This one needs Jack's explicit go-ahead. Do not run it on your own judgement.**

Publishing is done from the advisory page in the browser, or by patching the draft to
`published`. Verify afterwards that the state actually changed, rather than trusting the
response:

```
gh api repos/dotcomjack/grux-guardrails/security-advisories --jq '.[] | [.ghsa_id, .state] | @tsv'
```

Then check the public record rather than the confirmation page. A filing that exists is not
a filing that is live:

```
gh api /advisories --method GET -f ghsa_id=<GHSA_ID> --jq '.[0].ghsa_id'
```

## Schema notes, measured rather than guessed

Read from GitHub's own OpenAPI description
(`components.schemas.repository-advisory-create`) on 2026-08-14.

- **Required:** `summary`, `description`, `vulnerabilities`.
- **`vulnerabilities[].package.ecosystem` is required, and `swift` is a valid value.** The
  full enum is `rubygems, npm, pip, maven, nuget, composer, go, rust, erlang, actions, pub,
  other, swift`. Do not fall back to `other`.
- **`severity` and `cvss_vector_string` are mutually exclusive.** GitHub's own field
  description reads "You must choose between setting this field or `cvss_vector_string`".
  **Sending both is a 422.** Every payload here carries `cvss_vector_string` and deliberately
  has no `severity` key. If you add one, the file stops working.
- `cve_id` is omitted on purpose. These are not CVEs and requesting one is a separate
  decision.
- `start_private_fork` is omitted. There is nothing to fix in a private fork: the fixes
  shipped in `0.5.0` two years of tags ago in version terms and are already public in the
  changelog.

## Where the content came from

The `description` in each payload is taken **verbatim** from a grounded source document
written 2026-08-13 and kept outside this repository. Every claim in it is tied to
`CHANGELOG.md` or to a cited source line, and the tag-`0.4.0`
findings were measured against a real build rather than inferred from a changelog. Nothing
was rewritten here, so this file cannot drift away from that source without somebody
noticing.

**The affected ranges are the one place a judgement was made, and it is stated rather than
buried.** Where the source names two ranges for one advisory (a per-defect split), the union
is used in the payload and the per-defect ranges stay in the body text:

| Payload | `vulnerable_version_range` | Source line it came from |
|---|---|---|
| `1-tag-0.1.0.json` | `= 0.1.0` | as written |
| `2-tag-0.2.0.json` | `>= 0.2.0, <= 0.2.1` | union of the leak range and `= 0.2.0` for the denial of service |
| `3-tag-0.2.1.json` | `>= 0.2.0, <= 0.2.1` | as written |
| `4-tag-0.3.0.json` | `>= 0.3.0, <= 0.4.0` | union of the path heuristic range and the NAT64 range |
| `5-tag-0.3.1.json` | `= 0.3.1` | as written |
| `6-tag-0.4.0.json` | `= 0.4.0` | as written |

`patched_versions` is `0.5.0` on all six, deliberately. Several defects were fixed in the
very next tag, but every intermediate tag carries a leak of its own, so `0.5.0` is the first
version a consumer can move to and be clear of all of them.

The reader-facing narrative version of all this is `docs/DISCLOSURE-2026-08.md`.
