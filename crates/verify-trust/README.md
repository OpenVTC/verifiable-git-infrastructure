# verify-trust

The CI verifier of [Verifiable Git Infrastructure (VGI)][vgi]. For every commit
in a range it answers two questions, and **fails closed** on any doubt:

1. **Who signed it, cryptographically?** The commit names a signer DID on its
   `committer` header; that DID is resolved, its document must publish the
   Ed25519 key embedded in the commit's PROTOCOL.sshsig blob, and the signature
   must verify over the exact bytes git signed.
2. **Is that DID trusted, right now?** The signer DID is checked against a Trust
   Registry with a TRQP authorization query.

There is **no per-repository signer list**. The committer header is
author-controlled text, so it is used strictly as a lookup hint whose answer is
then checked: a commit claiming a DID it cannot sign for fails step 1 — the DID
does not publish the signing key, and the signature covers the header making
the claim — and a commit signed by a DID nobody enrolled fails step 2.

That leaves every question of *who may sign here* in the registry, where
enrolment, rotation and revocation already live. Adding a contributor is one
grant, not a pull request against each repository they touch, and revoking one
takes effect on the next run with nothing to un-commit.

> **Not a generic git-signature checker.** verify-trust is bound to the DID /
> Trust-Registry ecosystem: you need a Trust Registry to verify against and
> signers whose keys are published in resolvable DID documents.

## Install

```sh
cargo install verify-trust
```

Or use the prebuilt binary via the GitHub Action (no toolchain on the runner):

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.4.6
  with:
    range:        origin/${{ github.base_ref }}..HEAD
    registry-did: ${{ vars.TRUST_REGISTRY_DID }}
    vtc-did:      ${{ vars.VTC_DID }}
```

## Usage

```sh
verify-trust \
  --range origin/main..HEAD \
  --registry-did did:webvh:...registry \
  --vtc-did      did:webvh:...your-community \
  --resource     your-org/your-repo
```

Exits `0` only when every commit is `trusted` (registry-authorized) or `exempt`
(a platform-made merge commit verified against a committed PGP keyring, whose
parents all pass and whose tree is their clean merge — recomputed ignoring
`.gitattributes`, which needs git 2.40 or newer). Every other
verdict fails, each with a distinct status so an operator can tell which
remediation applies:

| Verdict | Cause |
|---|---|
| `unsigned` | no `gpgsig` header |
| `noSignerDid` | signed, but the committer names no DID |
| `unresolvedSigner` | the claimed DID did not resolve |
| `unknownKey` | the claimed DID publishes no such key |
| `badSignature` | the DID publishes the key, but the signature fails |
| `unauthorized` | valid signature, registry says no |
| `registryUnavailable` | the registry could not be consulted |
| `pgpRejected` | PGP-signed, but by no key in the exempt keyring (or none is configured) |
| `platformSignedEdit` | platform-signed, but not a merge (web-UI or API edit, squash merge, Dependabot) — re-sign it with `did-git-sign` |
| `platformMergeUnverifiedParent` | platform-signed merge with a parent that neither passes nor is on the base branch |
| `platformMergeAltered` | platform-signed merge whose tree is not the clean merge of its parents (e.g. conflicts resolved in the web UI) |

`--json` emits a machine-readable report, in which commits keep their full
signer DIDs and `signerNames` maps each named signer to its name and that
name's provenance.

## Registry discovery

`--registry-url` is optional. By default the endpoint comes from the registry's
own DID document, which advertises one service entry per binding it serves:

```json
"service": [
  { "id": "…#rest",    "type": ["TRQPRest", "TrustRegistry"],
    "serviceEndpoint": { "uri": "https://registry.example",
                         "profile": "https://trustoverip.org/profiles/trqp/v2" } },
  { "id": "…#didcomm", "type": "DIDCommMessaging",
    "serviceEndpoint": { "uri": "did:web:mediator.example", "accept": ["didcomm/v2"] } },
  { "id": "…#tsp",     "type": "TSPTransport",
    "serviceEndpoint": "did:web:mediator.example" }
]
```

Selection takes the highest-preference transport present in **both** the
document and this build — **TSP, then DIDComm, then HTTPS**. `verify-trust`
takes `trql-client`'s default features, so today it can construct only the
HTTPS binding and selects that; a registry offering none of what we speak fails
with both sides' transports named, rather than downgrading silently.

There is deliberately **no fallback to guessing a URL from the DID's domain**.
`vta-sdk` does that for a VTA, where a wrong host merely fails authentication;
here a wrong host is one whose authorization answers we would believe.

Why discover rather than configure: over the HTTPS binding the registry's reply
carries no signature — `--registry-did` is only stamped on the *outgoing*
request as `recipient`. Trust in "is this DID authorized" therefore rests on
reaching the right host, so the endpoint is better derived from an identifier
with integrity behind it than supplied as a second value nothing cross-checks.

## Scoping and cost

Two inputs carry weight that a committed signer list used to:

- **`--resource`** (and `--fallback-resource`) is the only thing scoping a
  signer to this repository. A grant is accepted exactly when the registry
  authorizes the tuple under it, so widening either widens who may sign, with
  nothing in the repository to contradict it.
- **`--resource-format`** (default `legacy`) picks the form of both
  resources — see [Resource format](#resource-format).
- **`--max-signers`** (default 32) bounds the distinct DIDs one range may
  claim. The set is chosen by whoever wrote the commits, and for the
  network-resolved methods each entry is an outbound fetch to a host the author
  picked. DIDs are deduplicated first; exceeding the cap fails the run.

## Resource format

A resource either names the forge or leaves it implied:

| `--resource-format` | Resource | Org fallback | Default `--resource` |
|---|---|---|---|
| `legacy` (default) | `acme/widgets` | `acme` | `$GITHUB_REPOSITORY`, verbatim |
| `qualified` | `github.com/acme/widgets` | `github.com/acme` | derived from the CI environment |

The qualified grammar is `<forge-host>/<owner>[/<repo>]`: the first segment is
the forge's host (a dotted name such as `github.com`, a GitHub Enterprise
Server host, `codeberg.org`, or `localhost`), followed by one or more path
segments — a forge with nested groups keeps its full path. Path segments are
ASCII letters, digits, `.`, `_` and `-`, and everything is lowercased. Empty
segments, `.` and `..`, a leading or trailing `/`, a URL scheme, a port and
any other character are rejected, and so is an unqualified value, with the
fix suggested. The grammar is `vgi_core::normalize_resource`, the same one
the VTC's registry projection and the forge adapters use, so a grant and a
query name a repository with the same bytes:

```
$ GITHUB_SERVER_URL=https://github.com verify-trust --resource-format qualified --resource acme/widgets …
Error: --resource `acme/widgets` is not forge-qualified (--resource-format qualified expects `<forge-host>/<owner>[/<repo>]`); did you mean `github.com/acme/widgets`?
```

Under `qualified`, the default resource comes from the CI environment: the
host of `FORGEJO_SERVER_URL` plus `FORGEJO_REPOSITORY` on Forgejo Actions,
otherwise the host of `GITHUB_SERVER_URL` plus `GITHUB_REPOSITORY` (which
gives a GitHub Enterprise Server its own host). Only the host is kept — a port
in the server URL is dropped. Elsewhere, pass `--resource` explicitly.

A run uses **one form only**. It never tries the qualified resource and then
the legacy one: accepting a grant under either would widen who may sign while
both forms exist in the registry, and silently.

**Migration.** Registry grants must be written in the form the check uses:

1. Now: `legacy` is the default, so nothing deployed changes. Opt in with
   `--resource-format qualified` (`resource-format: qualified` on the Action)
   once the grants exist in qualified form — during the window the VTC can
   write both forms for each grant.
2. A later minor release flips the default to `qualified`. Pin
   `resource-format: legacy` to keep the old behaviour for one more release.
3. The release after that removes `legacy`.

## Signer names

Signers are reported by the agent name their DID document claims, so a review
reads `example.com/@alice` rather than a DID:

```
TRUSTED      a1b2c3d4e5f6  example.com/@alice (did:webvh:QmXkAbCdEf…:example.com) (via your-org/your-repo)

Signers:
  example.com/@alice
    did:webvh:QmXkAbCdEfGhIjKlMnOp:example.com
```

A claimed name is a **self-assertion** — `alsoKnownAs` is written by the DID's
own controller, so nothing stops a hostile DID from claiming
`mybank.com/@treasury`. Claims are therefore shown tagged `[unverified]` by
default. Pass `--resolve-agent-names` (or `resolve-agent-names: true` on the
Action) to resolve each claimed name forward and require it to lead back to the
DID that claims it; only a name that round-trips renders untagged. That costs
one outbound HTTPS fetch per claimed name, to a host the document's author
chose, which is why it is opt-in.

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
