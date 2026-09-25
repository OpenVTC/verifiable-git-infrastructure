# vgi-cli

The `vgi` command for people who hold a repository in a VTC-governed git
namespace. (`vgi` on crates.io is an unrelated project, hence the crate name;
the binary is `vgi`.)

```sh
cargo install vgi-cli
```

## `vgi repo init`

Turns VGI commit trust on for one repository where no community bridge acts
on it — a namespace bound in manual mode, or a personal account the
community's GitHub App is not installed on. It is the step `cnm git create`
prints for such a namespace:

```sh
vgi repo init --vtc <vtc-did> --resource github.com/alice/gadgets [--dry-run]
```

It runs the bridge's own bootstrap plan (from `vgi-forge-github` /
`vgi-forge-forgejo`), so the files, rulesets and protections are byte-for-byte
what the bridge would write — but as you:

- **GitHub**, through your `gh` login (`gh auth login`; admin on the
  repository). Every request is one `gh api` process with an argument vector
  and the body on stdin; nothing passes through a shell. It commits
  `.github/workflows/verify-trust.yml` (the DIDs as literals) and the
  `web-flow` exempt keyring, removes stale `TRUST_REGISTRY_DID` / `VTC_DID`
  variables, and converges the "VGI commit trust" ruleset (pull request
  required, the check required and pinned to GitHub Actions, no force-push,
  no deletion, no bypass actors). The owners are you (on a personal
  repository, its account holder) plus each `--code-owner <login>`, each
  counted once. With two or more it also writes the managed
  `.github/CODEOWNERS` block and requires a code owner's review; with one,
  only the check — which on an organisation repository it refuses unless you
  pass `--solo`, since any other member with write access could then edit the
  workflow in the pull request it judges.
- **Forgejo / Gitea**, with `FORGEJO_TOKEN` (`write:repository`,
  `read:user`). The token is sent only to the repository's own host, and
  only after `GET /api/v1/version`, asked without it, answers as Forgejo or
  Gitea (`--forge auto` takes any host but `github.com` for Forgejo; pass
  `--forge github` for GitHub Enterprise Server). It allows fast-forward-only merges, commits
  `.forgejo/workflows/verify-trust.yml`, and converges the default branch's
  protection (no pushes, the check's context required, the workflow
  directories protected, applying to admins; you are on the merge
  allow-list).

These are per-repository guards. Manual mode does not set an organisation's
required workflow; that is the community bridge's job.

Every step is check-then-apply: a re-run changes nothing. `--dry-run` reads
the repository and prints each change, with the file or request body, and
makes none.

Inputs it finds when not given: the repository from the clone's `origin`
remote; the registry DID from the VTC DID document's `TrustRegistry`
referral (`--registry`); the verify-trust action pinned to the commit the
release tag matching this binary names, annotated tags dereferenced
(`--verify-trust-action`, `--verify-trust-version`); on Forgejo, the
release's published tarball SHA-256 (`--verify-trust-sha256`); on
github.com, the `web-flow` key (`--platform-keyring`). The report says where
each came from; the action commit and the SHA-256 are trust on first use, so
pass the flags to pin values you verified.

Upgrading to a new `--verify-trust-version` later: on GitHub, through a pull
request (the ruleset has no bypass); on Forgejo, lift the default branch's
protection and re-run, which writes the workflow and puts the protection
back. The [runbook](https://github.com/OpenVTC/verifiable-git-infrastructure/blob/main/docs/RUNBOOK.md#4-set-up-the-repository)
has the steps.

It does not adopt the repository: `git-ns/repo/adopt` is a Trust Task signed
with a VTA session, which this tool does not hold. It prints the
`cnm git adopt <resource> --owner <did>` command to run instead (pass
`--owner <did>` to have it filled in).

See the [runbook](https://github.com/OpenVTC/verifiable-git-infrastructure/blob/main/docs/RUNBOOK.md#4-set-up-the-repository).
