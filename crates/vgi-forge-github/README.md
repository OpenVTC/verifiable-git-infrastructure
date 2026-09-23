# vgi-forge-github

GitHub adapter for [Verifiable Git Infrastructure (VGI)][vgi] git namespaces:
implements [`vgi-forge`][vgi-forge]'s `Forge` for github.com and GitHub
Enterprise Server, acting as **one community's own GitHub App**.

- **App registration** through the manifest flow, with a fixed permission set
  — Administration, Contents and Variables (write), Metadata and organisation
  Members (read), nothing else. The code exchange refuses an App that GitHub
  registered with more than that, and returns the key and secrets in a type
  that zeroizes on drop and never prints them.
- **Auth.** An RS256 App JWT (`iat` backdated 60 s, nine-minute lifetime)
  signed through `AppKeySigner` — in-process, or an enclave that signs but
  never exports. Each operation mints its own installation token, scoped to
  one repository and that operation's permissions, and drops it on return.
- **Binding** a namespace via the App's install page and a `state` nonce,
  compared in constant time; the installation must be this App's and on the
  expected owner.
- **Account linking** with the OAuth device flow (`authorization_pending` and
  `slow_down` handled); the bridge keeps the numeric id and login and discards
  the user token. Enable *Device Flow* on the App's settings page — the
  manifest format cannot.
- **Repositories**: create (organisations; a personal account reports the
  reduced capability set and gets manual instructions), inspect (people,
  pending invitations, ruleset), archive, and role convergence keyed on
  numeric account ids, never logins.
- **Bootstrap** (check-then-apply, idempotent): the verify-trust workflow
  (actions pinned by SHA, `resource-format: qualified`, no dormant `if:`
  guard so a missing variable fails closed), the `web-flow` exempt keyring
  (supplied by configuration), `TRUST_REGISTRY_DID` / `VTC_DID` variables,
  and a ruleset — PR required, "Verify commit trust" required **and pinned to
  the GitHub Actions App**, no force-push, no deletion, no bypass actors.
- **Webhooks**: `X-Hub-Signature-256` verified in constant time over the raw
  body before parsing; repository, member, membership, ruleset, branch
  protection and installation events become `ForgeEvent`s.

## Why not octocrab

octocrab 0.54 covers rulesets and the device flow, but not what the security
model needs: its installation tokens are requested with an empty body (no
per-repository or per-permission scoping) and cached for reuse; its App JWT
takes an in-memory `jsonwebtoken` key, so the key cannot live in an enclave
signer; it has no Actions-variables API; and it follows redirects. It would
also add hyper-rustls with a second crypto provider, tower, snafu and
jsonwebtoken to a graph that already carries reqwest. The adapter instead uses
a thin reqwest client (~300 lines) over the dozen endpoints it calls, with
redirects off and a configurable base URL (GHES, tests).

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[vgi-forge]: https://crates.io/crates/vgi-forge
