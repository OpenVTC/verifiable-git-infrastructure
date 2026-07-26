# VGI operator runbook

Activating commit trust on a repository, end to end. Read this if you run the
Trust Registry, the VTA, or the repositories the check protects.

The shape to hold in your head: **VGI verifies, the VTC decides.** A commit
names its signer DID on its own `committer` header; `verify-trust` proves that
DID signed it, then asks the registry whether that DID is authorized. Who may
sign, key rotation, and revocation are registry and VTA concerns — nothing
about them lives in the repository.

---

## 1. Prerequisites

These are outside VGI, and standing them up is the long pole.

| What | Why VGI needs it | What you take away |
|---|---|---|
| A **VTA** with a persona and Ed25519 signing key per contributor | `did-git-sign` fetches the key at sign time; no private key touches disk | each contributor's `did:webvh:…#key-N` |
| A **Trust Registry** speaking TRQP | answers "is this DID authorized, right now" | `TRUST_REGISTRY_DID` |
| Your **VTC's DID** | the community whose authority each trust tuple is evaluated under — TRQP's `authority_id` | `VTC_DID` |

Two DIDs, no URLs. The registry's endpoint is discovered from its own DID
document (§4), so there is nothing to keep in sync with it.

Provisioning the VTA and registry themselves is documented in
[verifiable-trust-infrastructure][vti], not here.

## 2. Enrol the signers

For each contributor, issue a grant in the registry over the tuple:

```
entity    = did:webvh:…            the contributor's DID (no fragment)
authority = <VTC_DID>              your VTC — TRQP calls this authority_id
action    = git.commit.sign
resource  = <owner>/<repo>         or <owner> for an org-wide grant
```

`entity` is the **bare DID**, not the verification-method id. A commit signed
as `did:webvh:QmAbc:example.com#key-0` is queried as
`did:webvh:QmAbc:example.com` — the fragment names which key, and which key is
already settled by then.

Choose the resource scope deliberately. A repo-scoped grant authorizes one
repository; an org-scoped grant authorizes every repository that passes
`fallback-resource: <owner>`. Grant semantics are OR, so a repo-level record
**cannot veto** an org-level grant — narrowing is a matter of not issuing the
broad grant in the first place.

This step is the whole access-control decision. There is no second list to
maintain, and nothing to commit to the repository.

## 3. Set up a contributor's machine

Once per contributor:

```sh
cargo install did-git-sign
did-git-sign init --global --vta-did did:webvh:scid:your-vta.example.com
did-git-sign health
```

`init` resolves the VTA, mints a temporary admin did:key, and prints a
`pnm contexts create …` command. Run that in your Personal Network Manager to
authorise the setup session, press Enter, then pick the persona and signing
key. It configures git:

- `gpg.format = ssh`, `gpg.ssh.program = did-git-sign`, `commit.gpgsign = true`
- **`user.email = <DID#key-id>`** — this is load-bearing. It is the only place
  a commit states which identity signed it. A repo that overrides `user.email`
  with an ordinary address will fail `noSignerDid` even with a valid signature.

Use `--global` for all repositories, or plain `init` for one. Verify with
`did-git-sign health` before the first push, not after the PR check fails.

`did-git-sign` refuses to sign a commit whose committer names a different DID
than the key it is about to use, so a mismatch fails at `git commit` with both
halves named rather than in CI as `unknownKey`.

## 3a. Contributors in more than one community

Two settings pick an identity, and they must agree: `user.email` becomes the
commit's claim, and the persona selection picks the key. `did-git-sign`
resolves the key in this order —

1. `DID_GIT_SIGN_KEY` (per-invocation),
2. `did-git-sign.key` in git config (per-repo),
3. the `did_key_id` in the config file (the `init` default).

**Do not hand-manage per-repo config.** `git config --local` works but does not
survive a fresh clone, and when you forget it you get no error — you get a
commit signed as the wrong community. Where the community *is* the
authorization boundary, silent misattribution is the failure to design against.

Use git's **conditional includes**, one file per community, carrying the
identity and the key selection together so they cannot drift:

```ini
# ~/.gitconfig
[includeIf "hasconfig:remote.*.url:https://github.com/OpenVTC/**"]
    path = ~/.config/git/community-openvtc
[includeIf "hasconfig:remote.*.url:https://github.com/OtherOrg/**"]
    path = ~/.config/git/community-other
```

```ini
# ~/.config/git/community-openvtc
[user]
    email = did:webvh:QmAbc:openvtc.example#key-0
    name  = Your Name
[did-git-sign]
    key = did:webvh:QmAbc:openvtc.example#key-0
```

`hasconfig:remote.*.url` (git ≥ 2.36) keys off the remote rather than the
filesystem, so membership follows the repository rather than where you happened
to clone it — and a throwaway clone outside your usual tree still gets the right
persona. Use `includeIf "gitdir:~/devel/openvtc/"` instead if your layout is
authoritative and you prefer path matching.

Keep `user.email` in the same file as `did-git-sign.key`. Splitting them is
what lets them drift, and the pair is what the commit's verifiability rests on.

Reserve `DID_GIT_SIGN_KEY` for one-off overrides — and note that it moves the
key without moving `user.email`, so the sign-time check will refuse unless you
override both.

## 4. Set up the repository

**Workflow** — `.github/workflows/verify-trust.yml`:

```yaml
on: pull_request

jobs:
  verify:
    name: Verify commit trust
    if: vars.TRUST_REGISTRY_DID != ''
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }        # so origin/<base>..HEAD resolves
      - uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.3.0
        with:
          range:        origin/${{ github.base_ref }}..HEAD
          registry-did: ${{ vars.TRUST_REGISTRY_DID }}
          vtc-did:      ${{ vars.VTC_DID }}
          exempt-keyring: .github/trusted-platform-keys.asc
          resolve-agent-names: true     # optional; one HTTPS fetch per claimed name
```

`fetch-depth: 0` is not optional — without the base ref present the range does
not resolve.

**Registry endpoint discovery.** There is no `registry-url` to set. The
endpoint comes from the registry's own DID document, which advertises one
service entry per binding it serves:

```json
"service": [
  { "id": "…#rest",    "type": ["TRQPRest", "TrustRegistry"],
    "serviceEndpoint": { "uri": "https://registry.example",
                         "profile": "https://trustoverip.org/profiles/trp/v2" } },
  { "id": "…#didcomm", "type": "DIDCommMessaging",
    "serviceEndpoint": { "uri": "did:web:mediator.example", "accept": ["didcomm/v2"] } },
  { "id": "…#tsp",     "type": "TSPTransport",
    "serviceEndpoint": "did:web:mediator.example" }
]
```

Selection takes the highest-preference binding present in **both** the document
and the verifier: **TSP → DIDComm → HTTPS**. `verify-trust` is built with
`trql-client`'s default features, so today it can construct only HTTPS and
selects that; if your registry advertises none of what the verifier speaks, the
run fails naming both sides' transports rather than downgrading quietly.

Note the `#tsp` and `#didcomm` endpoints are **mediator DIDs**, not URLs — a
consumer of those bindings resolves a second hop. Only `#rest` carries a URL.

`registry-url` remains as an override for a registry that publishes no service
entry (local, dev). Prefer discovery: over HTTPS the registry's reply is
unsigned — `registry-did` is only stamped on the *outgoing* request as
`recipient` — so trust in the answer rests on reaching the right host. Two
independently settable values that nothing cross-checks is exactly the gap an
override reintroduces.

**Platform keyring** — `.github/trusted-platform-keys.asc`:

```sh
curl -sS https://github.com/web-flow.gpg > .github/trusted-platform-keys.asc
```

GitHub's web-UI merge and squash commits are PGP-signed by `web-flow`, not by a
DID. Without this file every merge commit fails `pgpRejected`. Committing the
key is what makes the exemption explicit and auditable.

**Repository variables** — plain variables, not secrets; they are public values
and fork PRs must be able to read them:

```sh
gh variable set TRUST_REGISTRY_DID --body 'did:webvh:…registry'
gh variable set VTC_DID            --body 'did:webvh:…your-community'
```

Setting these is what un-dormants the `if:` guard. Until then the job is a
no-op, which is deliberate: it keeps the workflow harmless in a repo that has
not been enrolled, and in forks.

**Branch protection** — the check is worthless unless it is *required*. On a
ruleset for `main`:

- require a pull request before merging
- require the **"Verify commit trust"** status check to pass
- block force-pushes and branch deletion

## 5. Verdicts and what to do about them

`trusted` and `exempt` pass. Everything else fails, with a distinct status so
the remediation is unambiguous:

| Verdict | Cause | Fix |
|---|---|---|
| `unsigned` | no `gpgsig` header | signing is off — `did-git-sign health` |
| `noSignerDid` | signed, committer is not a DID | `user.email` was overridden; re-run `init` |
| `unresolvedSigner` | the claimed DID would not resolve | DID document unreachable, or publishes no Ed25519 method |
| `unknownKey` | the claimed DID publishes no such key | signed by a key that identity does not hold |
| `badSignature` | key is published, signature fails | the commit was altered after signing |
| `unauthorized` | valid signature, registry says no | no grant — issue one, or the signer was revoked |
| `registryUnavailable` | the registry could not be consulted | registry outage; the check fails closed by design |

`registryUnavailable` makes registry availability a merge-blocking dependency.
That is the intended trade — "denied" and "unreachable" are indistinguishable
on the wire, so passing on doubt would be the wrong default — but plan
monitoring for it accordingly.

`--json` emits the same report machine-readably, with full signer DIDs and a
`signerNames` map carrying each name's provenance.

## 6. Day-to-day operations

**Add a contributor.** One grant in the registry. No pull request, no repo
change, effective on the next run. If the grant is org-scoped, it covers every
repository configured with that `fallback-resource`.

**Revoke a contributor.** Revoke the grant. Effective on the next run. Their
existing commits stay in history and keep verifying cryptographically — they
simply stop being authorized, which is the honest description of what changed.

**Rotate a key.** Update the DID document. The DID is unchanged, so the grant
stays valid and no repository is touched. This is why enrolment is by identity
rather than by key.

**Retire a repository.** Nothing to clean up in the repo; drop the grants whose
resource named it.

## 7. Things that carry more weight than they look like

**`resource` is the only scope.** With no committed signer list, the tuple
resource is the sole thing binding a signer to this repository. Widening
`resource` or `fallback-resource` widens who may sign, and nothing in the
repository will contradict it. Treat both as security-relevant configuration
and review changes to them as you would a permissions change.

**The registry is the single gate.** Enrolment, authorization and revocation
all resolve to one TRQP answer. This is the design's premise, not an oversight
— but it means registry compromise is sufficient to authorize commits, so the
registry's own operational security is the system's floor.

**`max-signers` bounds attacker-directed resolution.** The signer set comes
from the commits, so a pull request chooses which DIDs CI resolves — and for
`did:web` / `did:webvh` that is an outbound fetch to a host the author picked.
DIDs are deduplicated, then capped (default 32). Raise it only for a range
that is legitimately that wide.

**GitHub's own "Verified" badge is a separate axis.** These SSH signatures show
as verified in the GitHub UI only if the contributor also adds that Ed25519
public key to their GitHub account as a signing key. VGI's check is entirely
independent of it. If you additionally enable GitHub's built-in *Require signed
commits* rule, it will reject DID-signed commits whose keys are not registered
with GitHub — enable one or the other deliberately, not both by reflex.

**Squash and rebase merges rewrite commits.** The result is signed by
`web-flow` and passes via the exempt keyring, not as `trusted`. That is
expected: the DID-signed commits in the pull request are what got verified.

[vti]: https://github.com/OpenVTC/verifiable-trust-infrastructure
