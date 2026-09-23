# vgi-forge-forgejo

Forgejo adapter for [Verifiable Git Infrastructure (VGI)][vgi] git namespaces:
implements [`vgi-forge`][vgi-forge]'s `Forge` for a Forgejo instance (and
Gitea, best effort), acting as **one community's bot user** on it.

- **Identity: a bot user.** Its access token is scoped to `write:organization`,
  `write:repository` and `read:user` — the last only to look a person's login
  up by numeric id before every role change, and to confirm a token is the
  bot's. The token is long-lived, so it is held zeroized and never printed,
  and rotated in two phases: `mint_token` mints a new token, verifies it is
  the bot's, puts it in use and **hands the secret back** for the caller to
  persist (sealed) and distribute to any replica; only then does
  `retire_token` delete the one token it replaced — by id, never by pattern,
  so another bridge's or a person's tokens on the same bot are untouched.
  Forgejo mints and deletes tokens only under **basic** auth, so unattended
  rotation means the bridge also holds the bot's password; that is an
  explicit choice (`TokenRotation::WithPassword`), and without it an operator
  mints the token and `replace_token` verifies it before use.
- **Capabilities by probing** `/api/v1/version` (`9.0.0+gitea-1.22.0`, or a
  plain Gitea `1.22.3`): fast-forward-only merges from Forgejo 7 / Gitea 1.22,
  the Actions variables API from Forgejo 8 / Gitea 1.22. What is missing is
  switched off before a plan is built, not discovered half-way through one.
- **Binding** through the bridge's OAuth2 app (authorisation code + PKCE,
  confidential client). The adapter confirms the admin owns the org
  (`/users/{admin}/orgs/{org}/permissions` → `is_owner`), uses the one-time
  admin token to put the bot in a `vgi-bridge` team (admin on all
  repositories, may create them) and to create the org webhook, then wipes it.
  A re-bind converges the team and hook rather than duplicating them; a
  same-named team that already has other members is refused, not adopted
  (adopting it would give them admin on every repository). The bind `state`
  is the caller's single-use nonce, tied to the namespace it was started for.
- **Account linking** with the same flow; the bridge keeps the numeric id and
  login and wipes the member's token. The PKCE verifier is derived from the
  flow's `state` under a key derived from the client secret, so no per-flow
  state is kept and a restart does not lose a flow in progress. The link
  `state` is MACed together with the member's DID, and the callback must name
  that member again from the caller's session (`LinkCallback::redirect`), so
  a link cannot be completed into someone else's session. Without a store it
  is not single-use; a replay is bounded by its 15-minute lifetime and by the
  authorisation code, which is single-use and redeemable only with this
  state's verifier.
- **Roles.** Owner → `admin` collaborator; maintainer → `write` **and** the
  default branch's merge allow-list (`Maintain` on the adapter's ladder);
  committer → nothing, or `write` by opt-in. Everyone with `Maintain` or above
  is on the allow-list, because once it is on even an admin cannot merge
  without a place there.
- **Bootstrap** (check-then-apply, idempotent), in this order: merge settings
  (fast-forward only, Actions on — first, because it is the step an old
  instance refuses); `.forgejo/workflows/verify-trust.yml` (checkout and the
  action by **full URL** pinned to a commit, `resource-format: qualified`,
  `version` and `sha256` pinned, no dormant `if:` guard, and the registry and
  VTC DIDs written into it — Forgejo lets only a repository *owner* manage
  Actions variables, and a value in the protected workflow can only change
  through a pull request, which a variable an owner edits cannot say;
  `with_actions_variables()` opts into variables for a bot that is an owner);
  and branch protection on the default branch — no pushes,
  applies to admins, the check's status context required, merging restricted
  to the allow-list, and the workflow directories and keyring as **protected
  files**, so no pull request can rewrite the check it is judged by. The rule
  must be the one Forgejo applies: Forgejo compares plain rule names
  case-insensitively and applies the oldest, so another rule named like the
  branch (`Main` for `main`) is reported as drift and the protection step
  refuses to run past it. The required check's name may not contain glob
  characters (`*?[]{}\`): Forgejo matches required contexts as patterns and
  drops one that does not compile.
- **Changing a protected file afterwards** — a new verify-trust release, a
  new instance key — is its own audited maintenance step, `refresh_plan` /
  `refresh_managed_files` (`StepAction::RefreshProtectedFiles`). If anything
  differs it opens the managed rule to the bot alone (pushes on, push
  allow-list = the bot, protected files cleared, since Forgejo refuses them
  even to an allowed pusher), writes the files, restores the rule's exact
  prior settings and reads them back — attempting the restore whatever
  happened to the writes, and failing loudly if it could not. A rule left
  open shows up in `inspect` as a bypass actor and unprotected paths:
  critical drift, re-applied by the protection step.
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
  post a commit status under the required context, and so can a workflow
  token: a same-repository pull request runs the repository's *other*
  workflows (a community's own CI) on its own head, and a script those
  workflows execute from the PR — a `Makefile`, a test — can use the job's
  token to post a passing status for the verify-trust context. The
  protected-files rule stops a pull request from rewriting the workflow; it
  does not stop that. So on Forgejo the writers — maintainers, opted-in
  committers, and any workflow that runs PR code with a write token — are
  trusted not to forge the check. GitHub pins the check to the Actions App;
  Forgejo has no equivalent.
- **Instance administrators bypass branch protection** — Forgejo lets a site
  admin merge past every check. The instance is part of the trust base.
- The login-by-id lookup uses `/users/search?uid=`, which needs the users
  explore page enabled.

## Testing

`cargo test -p vgi-forge-forgejo` runs the mock-server suite.
`tests/forgejo_live.rs` drives the adapter against a real Forgejo in Docker
(bind through the real consent pages, create, bootstrap, roles, the
protected-workflow guarantee — changing, adding under, or deleting the
workflows directory are all refused — the audited refresh, archive, two-phase
rotation) and checks every endpoint and field it uses against the instance's
own swagger. The image is pinned by digest in `tests/forgejo/Dockerfile`:

```sh
VGI_FORGEJO_IT=1 cargo test -p vgi-forge-forgejo --test forgejo_live -- --ignored
```

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[vgi-forge]: https://crates.io/crates/vgi-forge
