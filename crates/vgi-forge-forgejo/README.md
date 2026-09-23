# vgi-forge-forgejo

Forgejo adapter for [Verifiable Git Infrastructure (VGI)][vgi] git namespaces:
implements [`vgi-forge`][vgi-forge]'s `Forge` for a Forgejo instance (and
Gitea, best effort), acting as **one community's bot user** on it.

- **Identity: a bot user.** Its access token is scoped to `write:organization`,
  `write:repository` and `read:user` — the last only to look a person's login
  up by numeric id before every role change, and to confirm a token is the
  bot's. The token is long-lived, so it is held zeroized and never printed,
  and rotated in place (`rotate_token`: mint, verify, swap, delete the old).
  Forgejo mints tokens only under **basic** auth, so unattended rotation means
  the bridge also holds the bot's password; that is an explicit choice
  (`TokenRotation::WithPassword`), and without it an operator mints the token
  and `replace_token` verifies it before use.
- **Capabilities by probing** `/api/v1/version` (`9.0.0+gitea-1.22.0`, or a
  plain Gitea `1.22.3`): fast-forward-only merges from Forgejo 7 / Gitea 1.22,
  the Actions variables API from Forgejo 8 / Gitea 1.22. What is missing is
  switched off before a plan is built, not discovered half-way through one.
- **Binding** through the bridge's OAuth2 app (authorisation code + PKCE,
  confidential client). The adapter confirms the admin owns the org
  (`/users/{admin}/orgs/{org}/permissions` → `is_owner`), uses the one-time
  admin token to put the bot in a `vgi-bridge` team (admin on all
  repositories, may create them) and to create the org webhook, then wipes it.
  A re-bind converges the team and hook rather than duplicating them.
- **Account linking** with the same flow; the bridge keeps the numeric id and
  login and wipes the member's token. The PKCE verifier is derived from the
  flow's `state` under a key derived from the client secret, so no per-flow
  state is kept and a restart does not lose a flow in progress.
- **Roles.** Owner → `admin` collaborator; maintainer → `write` **and** the
  default branch's merge allow-list (`Maintain` on the adapter's ladder);
  committer → nothing, or `write` by opt-in. Everyone with `Maintain` or above
  is on the allow-list, because once it is on even an admin cannot merge
  without a place there.
- **Bootstrap** (check-then-apply, idempotent), in this order: merge settings
  (fast-forward only, Actions on — first, because it is the step an old
  instance refuses); `.forgejo/workflows/verify-trust.yml` (checkout and the
  action by **full URL** pinned to a commit, `resource-format: qualified`,
  `version` and `sha256` pinned, no dormant `if:` guard); `TRUST_REGISTRY_DID`
  and `VTC_DID` variables (written into the workflow where there is no
  variables API); and branch protection on the default branch — no pushes,
  applies to admins, the check's status context required, merging restricted
  to the allow-list, and the workflow directories and keyring as **protected
  files**, so no pull request can rewrite the check it is judged by.
- **Merge commits.** Fast-forward-only merges land the DID-signed commits
  unchanged. On an instance without them, `MergeFallback::InstanceSigningKey`
  allows instance-signed merge commits only and commits the instance's key
  (`/api/v1/signing-key.gpg`) as the exempt keyring; the default refuses.
- **Webhooks.** One org webhook, `repository` events only — the one change
  Forgejo announces. `X-Forgejo-Signature` (or `X-Gitea-Signature`), bare-hex
  HMAC-SHA256 of the raw body, checked in constant time before parsing. Roles,
  protection, renames and archiving are not announced by Forgejo, so the
  adapter reports `webhooks: false` and drift is found by the scheduled
  `inspect` sweep.

## Limits worth knowing

- **Status checks cannot be pinned to Actions.** Anyone with write access can
  post a commit status under the required context. The protected-files rule
  stops a pull request from rewriting the workflow, but a maintainer (or an
  opted-in committer) could post a passing status by hand. GitHub pins the
  check to the Actions App; Forgejo has no equivalent.
- **Instance administrators bypass branch protection** — Forgejo lets a site
  admin merge past every check. The instance is part of the trust base.
- The login-by-id lookup uses `/users/search?uid=`, which needs the users
  explore page enabled.

## Testing

`cargo test -p vgi-forge-forgejo` runs the mock-server suite.
`tests/forgejo_live.rs` drives the adapter against a real Forgejo in Docker
(bind through the real consent pages, create, bootstrap, roles, the
protected-workflow guarantee, archive, rotation) and checks every endpoint and
field it uses against the instance's own swagger:

```sh
VGI_FORGEJO_IT=1 cargo test -p vgi-forge-forgejo --test forgejo_live -- --ignored
```

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[vgi-forge]: https://crates.io/crates/vgi-forge
