# Contributing to cachette

Hangar (`https://hangar.nixthedev.ru/NiXTheDev/cachette`) is the authoritative repository. GitHub is the public front-end: a mirror of `release`, the issue tracker, and where outside contributors open pull requests.

## Where things live

| Thing | Place |
|---|---|
| Code, review, merges | Hangar, `release` branch |
| Issues | GitHub only (Hangar's external issue tracker points there) |
| PR submissions | GitHub for outside contributors; Hangar for maintainers |
| CI gates | Hangar Actions (`push-checks.yml`, `pr-checks.yml`, `release.yml`) |

Open issues on GitHub. PR descriptions should reference them (`GH-#`); Hangar's Issues tab redirects to GitHub, so there is no local issue state to sync.

## Submitting a change

1. Fork on GitHub, branch from `release`, open a PR there.
2. Keep the change focused; explain the "why" in the description.
3. Run the gates locally if you can:
   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
4. Signing is optional — signed commits are preferred but not required. A DCO `Signed-off-by:` trailer is welcome. You will still be credited as author when the change is merged.

## How a GitHub PR lands on Hangar

Maintainers bring PR heads over as refs and merge on Hangar:

```bash
# local clone with both remotes configured
git fetch github refs/pull/<n>/head:pr-<n>
git push hangar pr-<n>:github/pr-<n>
```

Then open a Hangar PR from `github/pr-<n>` into `release`, review it there, and **squash-merge** it. The final commit on `release` is signed by the Forgejo instance, so whatever the contributor sent — signed, unsigned, several commits, messy history — never lands verbatim and branch protection stays satisfied.

Preserve attribution in the squash commit:

- **author** = the PR author (Forgejo squash sets this by default),
- add `Co-authored-by: Name <email>` for every other contributor,
- add a `GitHub-PR: https://github.com/NiXTheDev/cachette/pull/<n>` trailer so the origin stays traceable.

Do **not** mirror GitHub branches back into Hangar's `release`. The mirror is one-way (Hangar → GitHub); contributions come back as refs, are reviewed on Hangar, and are merged there. That keeps a single source of truth.

## Workflow validation

The workflow files under `.forgejo/workflows/` are written for **Forgejo Actions**, not GitHub Actions: `uses:` references full instance URLs and the runner labels (`linux-amd64`, `linux-arm64`, `alpine-latest`, `ci`) are Forgejo-specific. Validate changes with the runner itself:

```sh
forgejo-runner validate --directory .
# or a single file:
forgejo-runner validate --path .forgejo/workflows/release.yml --workflow
```

`actionlint` assumes GitHub's action format and reports false positives on both of those; don't treat it as the gate.
