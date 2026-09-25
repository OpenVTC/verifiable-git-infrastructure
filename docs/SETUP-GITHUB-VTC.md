# Put a GitHub organisation under a VTC

End to end: from a community with a VTA, a Trust Registry and a VTC, to a
GitHub organisation whose repositories the community governs — who owns each
one, who may merge, whose commits the check accepts — with every pull request
checked against the registry.

The shape to hold in your head: **the VTC decides, the bridge acts, the
registry answers.** Rights are records in the VTC. The VTC publishes the
commit rights to its Trust Registry, where `verify-trust` reads them, and
sends jobs to the community's **bridge**, the one service holding the
community's GitHub App, which turns rights into forge roles and puts the
check on each repository. Nobody edits the forge by hand; what changes there
anyway is reported back as drift.

Who does what below:

| Who | Does |
|---|---|
| **VTC operator** | configures and restarts the VTC (step 1) |
| **Bridge operator** | deploys the bridge (steps 2–3); often the same person |
| **Community administrator** (admin role on the VTC, whole-community scope) | binds the namespace, grants the first rights (steps 4–5) |
| **GitHub organisation owner** | approves the App registration and installs it (steps 3–4) |
| **Members** | link their GitHub accounts, sign their commits (step 6) |

The bridge's own operation — what it stores, how the check it posts behaves,
the Dependabot re-sign — is in [BRIDGE.md](BRIDGE.md). Day-two operations
(adding people, departures, drift, restores) are in the
[runbook](RUNBOOK.md#8-operating-a-vtc-managed-namespace).

---

## 0. Before you start

### What you need

| What | Why | Check |
|---|---|---|
| A **VTA** | mints the contributors' signing keys, and the bridge's DID | — |
| A **Trust Registry** the VTC can write to | the VTC publishes every commit right there with `registry/record/put`; `verify-trust` queries it | the VTC's `[registry] did` is set and `registry_status` is not `degraded` |
| A **VTC** with messaging running | holds the rights, sends bridge jobs over DIDComm (or TSP) | members can reach it from `openvtc` |
| A **GitHub organisation** you own | the namespace | you can open its *Settings* |
| A host for the bridge with a **public HTTPS URL** | GitHub sends webhooks and redirects there | TLS terminates at a proxy in front of it |

Standing up the VTA, the registry and the VTC is documented in
[verifiable-trust-infrastructure][vti] (`docs/03-vtc/`), not here.

### Versions

| Component | Needs |
|---|---|
| VGI (`vgi-bridge`, the `verify-trust` action and binary, `did-git-sign`) | **0.4.14** or later |
| `trust-tasks-rs` on the VTC | **0.22.6** or later (VTI `main` resolves 0.22.7) |
| VTC | `main` of verifiable-trust-infrastructure — the first with `[git_ns]`, `git-ns/bridge/event` 0.2, `drift/resolve` and `reseat` |
| `openvtc` (members) | `main` — the first with the *Repos* view |
| `git` on contributors' machines | 2.20+ (the commit-msg hook); 2.36+ for conditional includes by remote |

### Organisation or personal account

**Use an organisation.** Only there can the bridge

- **create repositories** — on a personal account GitHub gives an App no way
  to, so the account holder creates each one and the VTC adopts it;
- put the check out of every pull request's reach with an **org required
  workflow** — the check lives in `<org>/.vgi`, pinned to a commit by an org
  ruleset, and no pull request, however it is written, changes what runs
  (GitHub Team or Enterprise; see step 7);
- project **roles** at the levels the rights ask for — a personal account's
  collaborators can only be given `write`.

A personal account works, with less (§9.1).

**One GitHub App per GitHub host, per bridge, and it is private.** The manifest
registers the App as not public, so GitHub lets only the account that owns it
install it. On github.com a bridge therefore serves exactly one namespace: the
`app_owner` in its config. A second organisation needs a second bridge (and a
second entry in the VTC's `[git_ns] bridges` cannot name the same host twice
either — the map is keyed by host).

---

## 1. Configure the VTC for git namespaces

In the VTC's configuration file, add:

```toml
[git_ns]
# Which bridge serves which forge, by host. A bridge-mode bind on a host with
# no entry is refused `git-ns/namespace/bind:noBridge`. Fill this in at step 2,
# once the bridge has a DID.
bridges = { "github.com" = "did:webvh:…:bridge.acme-vtc.example" }

# Elevated and destructive git actions (grant/revoke `own`, `repo.create`,
# `ns.admin`; transfer; archive; adopt; bind; unbind) only from a community
# administrator. Default true — keep it unless you have decided otherwise.
elevated_requires_admin = true

# How often the projector reconciles, in seconds. Default 5. The registry
# pass itself runs on every change and at least once a minute.
tick_seconds = 5
```

Every key is optional; with no `[git_ns]` section at all the VTC serves only
manual-mode namespaces (§9.3). Unknown keys are refused, so a typo fails the
start rather than falling back to a default.

**Why `elevated_requires_admin`.** The design puts ownership changes, archive
and namespace-level grants behind a *step-up*. This VTC's only step-up is a
passkey elevation on an administrator's session, and a signed Trust Task has
no session. So, by default, those actions are accepted only from a community
administrator — in addition to the git right that entitles them, never
instead of it. In practice: an owner cannot transfer, archive or name a
co-owner without an administrator doing it; granting `maintain` and
`git.commit.sign`, and creating a repository, need no administrator.

The `[git_ns]` section is read at start: **restart the VTC** after changing
it (`POST /v1/admin/config/reload` does not re-read it).

**The community's policy.** The `gitNamespace` policy (Rego package
`vtc.git_namespace`) runs after the fixed rules and can only refuse. The
shipped default is **members only, no external signers**, and admits exactly
one grant to a non-member: the bridge's service grant (step 4). Its
`settings` are the three community choices:

| Setting | Default | Effect |
|---|---|---|
| `maintainer_grants_commit` | `false` | a maintainer may grant `git.commit.sign` on their repository |
| `cascade_on_departure` | `false` | a departed member's issued grants are revoked with them, rather than listed for review |
| `role_drift` | `"report"` | `"enforce"` puts back forge roles changed outside the VTC |

Change them by uploading and activating a `gitNamespace` policy through the
usual policy flow (`/v1/policies`). The default is right for a first
namespace.

**Success looks like:** the VTC starts; `cnm git namespace list` answers
(empty).

## 2. Deploy the bridge

### 2.1 Config

Start from [`crates/vgi-bridge/bridge.example.toml`](../crates/vgi-bridge/bridge.example.toml).
For one organisation on github.com:

```toml
vtc_did            = "did:webvh:…:acme-vtc.example"          # the only DID it takes jobs from
trust_registry_did = "did:webvh:…:registry.acme-vtc.example"
mediator_did       = "did:web:mediator.acme-vtc.example"     # the VTC's mediator
public_url         = "https://bridge.acme-vtc.example/"      # must be https
listen             = "0.0.0.0:8080"
data_dir           = "/var/lib/vgi-bridge"
master_key_file    = "/run/secrets/vgi-bridge-master-key"
# event_version = "0.2"   # the default; see step 3.3

[verify_trust]
# What the bootstrap writes into workflows. The action must be pinned to a
# 40-hex commit; `version` is the release the action downloads.
action  = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@<40-hex commit of v0.4.14>"
version = "v0.4.14"
# required_check = "Verify commit trust"

[[github]]
host         = "github.com"
app_name     = "acme-vgi-bridge"
app_owner    = "acme"                                        # the organisation
platform_keyring_file = "/etc/vgi-bridge/web-flow.asc"
```

Get the commit for the tag with
`gh api repos/OpenVTC/verifiable-git-infrastructure/commits/v0.4.14 --jq .sha`,
and GitHub's `web-flow` key with
`curl -fsSL https://github.com/web-flow.gpg > /etc/vgi-bridge/web-flow.asc`.

`platform_keyring_file` is optional to *start*, but not to run well: the
required-workflow and in-repo plans refuse to plan without it, the check the
bridge posts fails every GitHub-signed merge without it, and the Dependabot
re-sign does nothing without it. Set it.

`[checks]`, `[resign]`, `bridge_checks`, `dependabot_*` and the per-namespace
`[github.namespaces.<owner>]` table have working defaults; they are described
in [BRIDGE.md](BRIDGE.md) §6–6a. Leave `bridge_checks` on: without it, an
organisation without org rulesets falls back to a check any writer can forge.

### 2.2 Master key and identity

The master key seals every secret the bridge stores. It is 32 bytes, base64,
in a file only its owner can read (the bridge refuses a file readable by group
or others):

```sh
head -c 32 /dev/urandom | base64 > /run/secrets/vgi-bridge-master-key
chmod 600 /run/secrets/vgi-bridge-master-key
```

(`vgi-bridge init` writes one itself when the file does not exist, but a
secret mounted read-only into a container has to exist first.) Back it up
**apart from** the data directory — the store is useless without it, and the
two together are every credential the community has on GitHub.

**The bridge's DID: provision a `did:webvh` from the VTA.** Use a DID
template with an Ed25519 signing key, an X25519 key-agreement key, and a
`DIDCommMessaging` service naming `mediator_did`. Export its secrets bundle
and import it (bridge stopped — the admin commands take the store's lock):

```sh
vgi-bridge --config /etc/vgi-bridge/bridge.toml identity import bundle.json
shred -u bundle.json
vgi-bridge --config /etc/vgi-bridge/bridge.toml identity show
```

**Why not the `did:key` `init` mints.** The VTC reaches a bridge the way it
reaches any peer: it resolves the bridge's DID and uses a transport the
document advertises (TSP, then DIDComm). A `did:key` document advertises no
service, so a VTC on `main` has no transport to it: the bind fails
`unavailable` (*the bridge … refused the job (noMatchingProtocol)*), and so
would every job after it. `vgi-bridge init` still creates the master key file
and a `did:key`; `identity import` replaces it. Keep `did:key` for tests
where nothing sends the bridge a job.

The Ed25519 key in the bundle must be a verification method of the DID's
document (VTA templates publish it): the bridge signs its re-signed
Dependabot commits with it, and `verify-trust` accepts the signature only
from a key the DID publishes.

### 2.3 Run it

```sh
docker build -f crates/vgi-bridge/Dockerfile -t vgi-bridge .
docker run -d --name vgi-bridge \
  -v /etc/vgi-bridge:/etc/vgi-bridge:ro \
  -v vgi-bridge-data:/var/lib/vgi-bridge \
  -v /run/secrets/vgi-bridge-master-key:/run/secrets/vgi-bridge-master-key:ro \
  -p 127.0.0.1:8080:8080 vgi-bridge
```

The image runs as uid 10001: the key file and the data volume must be
readable (and the volume writable) by it. Run `identity import` in the same
container setup with the bundle mounted and `identity import <path>` as the
command, before the first `run`. Put the TLS proxy in front, forwarding the
paths in BRIDGE.md §1 and keeping `/healthz` internal.

### 2.4 Tell the VTC which bridge serves github.com

Put the DID from `identity show` into the VTC's `[git_ns] bridges` under
`"github.com"` (step 1) and restart the VTC.

**Success looks like:** `curl http://127.0.0.1:8080/healthz` answers `ok`;
the bridge's log shows the DIDComm link to the mediator up, and — since no
App is registered yet — a warning with a one-time registration URL.

## 3. Register the GitHub App

### 3.1 The manifest flow

The bridge registers its own App, so no one copies a private key by hand.

1. Find the warning in the bridge's log:

   ```
   the GitHub App is not registered yet; an admin of `acme` opens
   https://bridge.acme-vtc.example/github/github.com/register?state=… to register it
   ```

   The URL is valid for 24 hours; the bridge logs one at start for as long as
   no App is registered.
2. **An owner of the organisation** opens it. The page posts the manifest to
   GitHub; they review and create the App.
3. GitHub redirects to `/github/github.com/registered`. The bridge exchanges
   the code for the App's id, private key and webhook secret, seals them, and
   puts the adapter in service. It refuses an App registered under another
   account, a public one, or one with any permission beyond the reviewed set.
   If the exchange fails (GitHub down), open the same link again — it is spent
   only once an App is registered.

The App asks for repository Administration, Contents, Variables and Checks
(write), Metadata, Pull requests and Merge queues (read); organisation
Members (read) and Administration (write). No secrets, no `workflows`, no
Actions logs. Why each one is there is in BRIDGE.md §3.

### 3.2 Enable Device Flow — by hand

The manifest format cannot turn it on, and members link their accounts with
it. Open the App's settings
(`https://github.com/organizations/<org>/settings/apps/<app-slug>`), tick
**Enable Device Flow**, save.

Without it, a member's link attempt fails when the bridge asks GitHub for a
device code.

### 3.3 The event version

The bridge sends `git-ns/bridge/event` **0.2**, which the VTC on `main`
serves. Leave `event_version` unset. Only a VTC older than that needs
`event_version = "0.1"` (it would otherwise refuse every event as an
unsupported type); what the two versions do differently with transfers is in
BRIDGE.md §7.

**Success looks like:** the bridge's log says the adapter for `github.com` is
in service; the App appears under the organisation's *Settings → Developer
settings → GitHub Apps*; its settings page shows Device Flow enabled.

## 4. Bind the organisation

A **community administrator** binds; no git right is enough, because before
the bind there are none. From `cnm`, signed with the community profile's key:

```sh
cnm git namespace bind --forge github.com --owner acme --mode bridge
```

`--mode` defaults to `manual`: say `bridge`. `cnm` first prints what binding
makes public — *rights granted in github.com/acme will be published to the
community's Trust Registry: anyone can read who owns and who may commit to
each repository* — then:

```
github.com/acme — pending (ns_…)
Prove control of the owner on the forge to finish binding:
  https://github.com/apps/acme-vgi-bridge/installations/new?state=…
```

The same bind is on the admin console's **Repos** page (`/admin/repos`),
which signs it with the browser's console key where one is enrolled, or
hands you the `cnm` command.

**An organisation owner opens the URL** and installs the App on the
organisation. Choose **All repositories**: the bridge must see every
repository the community creates or adopts, and one outside the
installation's selection is `notFound` to it. GitHub redirects to
`/github/github.com/setup`, which completes the bind. The link lives 15
minutes on the bridge's side (`flow_ttl_secs`); an abandoned pending
namespace is discarded by the VTC after 24 hours, and you bind again.

On completion the bridge probes whether the organisation can have **org
rulesets** (it lists them with its organisation-Administration token: a Free
organisation answers 403) and records the answer. The VTC then:

- marks the namespace `bound` and gives the administrator who began the bind
  the first `git.ns.admin` (if they are still a member);
- grants the bridge `git.commit.sign` on `github.com/acme` — the **service
  grant**, `grantedBy` the VTC itself, so the commits the bridge re-signs for
  Dependabot pass. The shipped policy admits it as `bridge.serviceGrant`.

**Success looks like:**

```sh
cnm git namespace list
# github.com/acme  ns_…  bridge bound  admins: 1  repos: 0
cnm --json git namespace list      # forgeStatus: installation, missing permissions, org rulesets
```

and, on the console's namespace card: the App registered and installed, **no
missing permissions**, *org rulesets* yes (or no, and which guard that means
— step 7), the bridge's service grant, `role_drift` and
`cascade_on_departure`.

If `missingPermissions` is not empty, the owner declined something at
install: have them accept it on the installation page
(`https://github.com/organizations/<org>/settings/installations`). An owner
who declines organisation Administration gets no required workflow.

About two minutes after the bind the bridge asks the registry whether the
service grant is there and logs a warning naming the namespace if it is not.

**If the bind is refused:** `git-ns/namespace/bind:noBridge` — no
`[git_ns] bridges` entry for `github.com`, or the VTC was not restarted;
`alreadyBound` — it is bound or pending already (`cnm git namespace list`);
`permissionDenied` — the profile's DID is not a whole-community administrator.
The [runbook's troubleshooting table](RUNBOOK.md#8k-troubleshooting) has the
rest.

## 5. Grant the first rights

Every change from here is a signed `git-ns/*` Trust Task, authorized by the
**signer's own git rights** — not by an administrator session. A community
administrator's role binds namespaces; it grants only through the git rights
the administrator's DID holds (and, under `elevated_requires_admin`, is what
elevated actions additionally need).

The rights, from broad to narrow:

| Right | On | Lets the holder |
|---|---|---|
| `git.ns.admin` | `github.com/acme` | everything below on every repository; adopt; unbind |
| `git.repo.create` | `github.com/acme` | create a repository and own it |
| `git.repo.own` | `github.com/acme/widgets` | grant/revoke `own`, `maintain`, `commit.sign` there; transfer; archive |
| `git.repo.maintain` | `github.com/acme/widgets` | merge and triage on GitHub |
| `git.commit.sign` | a repository or the namespace | author commits the check accepts |

`own ⇒ maintain ⇒ commit.sign`; `ns.admin ⇒ repo.create` and `own` on every
repository. Resources are forge-qualified and lowercase.

A second namespace admin (so the namespace never hangs on one person), and
`repo.create` for the people who will start repositories:

```sh
cnm git grant --subject did:webvh:…:alice --right git.ns.admin \
  --resource github.com/acme --reason "second namespace admin"
cnm git grant --subject did:webvh:…:bob --right git.repo.create \
  --resource github.com/acme --expires-in 365d
```

Both are elevated or destructive, so under the default config they must be
signed by a community administrator who also holds `git.ns.admin` there (the
binder does). Namespace rights go to **current members only**, and every DID
must be DID-core syntax (`did:<method>:<id>`, no fragment) — anything else is
`malformedRequest`, and `cnm` refuses it before signing.

**Success looks like:** `cnm git view --resource github.com/acme` lists the
rights; the console's namespace card shows two admins.

## 6. Members: link GitHub accounts, set up signing

### 6.1 Link a GitHub account

A right becomes a **GitHub role** only for a member whose GitHub account is
linked: the bridge keys roles on GitHub's numeric account id, never a login.
Commit rights need no link — they are checked on commits, not logins — but
owners and maintainers need one to get `admin` / `maintain` on GitHub, and
owner review (step 7) counts only linked owners.

In **openvtc**: *Communities* → select the community → **`r`** opens its
*Repos* view → **`l`** starts the link. For GitHub it shows

```
Open  https://github.com/login/device
and enter  WDJB-MJHT
Waiting for github.com to confirm — checking every …s; the attempt lapses at 14:05 UTC.
```

Enter the code on GitHub and authorize the App. The view then shows
`✓ Linked @alice on github.com.` The bridge keeps the account's id and login
and revokes (or, without the App's client secret, discards) the user token —
it keeps no token of the member's.

`cnm` has no link command: linking is a member's own act, signed as the
member (`git-ns/account/link`). A departed member's links are removed with
them.

### 6.2 Set up signing

Each contributor, once per machine:

```sh
cargo install did-git-sign
did-git-sign init --global --vta-did did:webvh:…:your-vta.example.com
did-git-sign health
```

`health` must show the signing key reachable and `Commit-msg hook: …` current.
The hook writes the `Signed-by-DID:` trailer that names the signer, and is
written once by `init` — an upgraded binary does not replace it, and a hook
older than v2 puts the trailer where `verify-trust` cannot read it on some
messages (`noSignerDid`). `OUTDATED` means re-run `init`. Contributors in
more than one community use conditional includes instead of `--global`
([runbook §3a](RUNBOOK.md#3a-contributors-in-more-than-one-community)).

openvtc's *Repos* view shows the same health beside the member's repositories
— whether `did-git-sign` is set up for this persona, and the hook's version
at each scope, with the fix.

## 7. Create a repository — or adopt one

### 7.1 Create

A holder of `git.repo.create` (or `ns.admin`):

```sh
cnm git create --namespace ns_… widgets --visibility public \
  --description "Widgets"
```

(or `n` in openvtc's *Repos* view; or the console). The VTC reserves the
name, records the requester as its owner, and sends the bridge a
`createRepo` job; the bridge creates the repository and runs the
**bootstrap**, check-then-apply: files, then the ruleset. `cnm git repos`
shows its state go `pendingCreate` → `active`, and the console its four
bootstrap steps (workflow, keyring, variables, required check) and each
step's outcome.

### 7.2 Adopt an existing repository

A namespace admin (and, under the default config, a community administrator):

```sh
cnm git adopt github.com/acme/legacy --owner did:webvh:…:alice --owner did:webvh:…:bob
```

The VTC records the owners, has the bridge **inspect** the repository, and
bootstraps whatever is missing. A repository the bridge sees appear on its
own (created by hand, transferred in) is reported as unmanaged — only
namespace admins see it — for someone to adopt the same way.

### 7.3 The guard in force

The check is worthless if the pull request can rewrite it: a
`pull_request` workflow runs from the pull request's own files. The bridge
picks one guard per repository, in this order:

| Guard (console label) | When | What is on GitHub |
|---|---|---|
| **Required workflow** (`requiredWorkflow`) | the organisation has org rulesets (Team/Enterprise) and the App has organisation Administration | a public `acme/.vgi` repository holding `.github/workflows/verify-trust.yml` (DIDs and the `web-flow` key as literals), itself protected; an org ruleset **`VGI required workflow`** requiring it at a **pinned commit** on the managed repositories' default branch, no bypass. Nothing in the repository itself. |
| **Bridge-posted check** (`bridgePostedCheck`) | no org rulesets, `bridge_checks` on, and the App has Checks, Pull requests, Merge queues and the `pull_request` / `merge_group` events | no workflow at all. The bridge runs verify-trust itself and posts *Verify commit trust* as the App; the ruleset requires it from the App's own integration id. |
| **Owner review** (`codeOwnerReview`) | neither of the above, two or more owners with linked accounts | the workflow and keyring committed under `.github/`; a managed block at the end of `CODEOWNERS` giving `/.github/` to the owners; the ruleset requiring a code owner's approval, dismissed by new pushes, not the last pusher's own |
| **Solo** (`none`, shown as *solo: workflow edits not review-protected*) | the same, one owner | the workflow and keyring, no review rule. The owner could weaken their own check — accepted, since they control the repository anyway. Re-planned when a second owner arrives. |

Owner review and solo count only owners **with a linked GitHub account**
(plus, on a personal account, the account holder): the bootstrap cannot plan
owner review for a repository none of whose owners has linked one. Link
before creating, where these guards apply.

Every repository also gets the repository ruleset **`VGI commit trust`** on
the default branch: pull request required, *Verify commit trust* required, no
force-push, no deletion, no bypass actors — the bridge included.

**Repository variables:** none. The managed workflows carry the registry and
VTC DIDs as literals, because any repository admin can change a variable
(and a repository variable overrides an organisation one); the bootstrap
**removes** `TRUST_REGISTRY_DID` and `VTC_DID` if a repository had them.

**Verify it.** On GitHub, as an owner:

- *Repository → Settings → Rules → Rulesets*: `VGI commit trust`, active, no
  bypass list, requiring *Verify commit trust*.
- Required workflow: *Organisation → Settings → Repository → Rulesets*:
  `VGI required workflow`, active, no bypass, the `.vgi` workflow at a commit
  SHA, the repository among its targets; `acme/.vgi` public.
- Bridge-posted: no `.github/workflows/verify-trust.yml` in the repository.
- Owner review: `.github/CODEOWNERS` (or the one GitHub already read) ending
  with `# BEGIN VGI managed owner rules`, naming every owner; GitHub reports
  no errors for it (`GET /repos/{owner}/{repo}/codeowners/errors`).
- *Settings → Actions → General*: Actions enabled, and allowed to run
  `actions/checkout` and the verify-trust action (not needed for the
  bridge-posted check).

In the VTC: `cnm --json git repos --namespace ns_…` — `syncState` `inSync`,
`guard` as above, `driftCount` 0, every bootstrap step true.

## 8. The first pull request

On a clone, with `did-git-sign` set up and a `git.commit.sign` right on the
repository (an owner has it by implication; to add someone,
`cnm git grant --subject <did> --right git.commit.sign --resource github.com/acme/widgets`):

```sh
git switch -c first-change
echo hi > hello.txt && git add hello.txt && git commit -m "Say hello"
git log -1 --format='%(trailers:key=Signed-by-DID)'   # names your DID
git push -u origin first-change && gh pr create --fill
```

**Passing.** Under a workflow guard the *Verify commit trust* job's log ends

```
TRUSTED      1a2b3c4d5e6f  alice (did:webvh:QmXk…:acme.example) (via github.com/acme/widgets)
…
PASS: 1/1 commits pass
```

Under the bridge-posted check, the check run is titled *All 1 commits are
signed by trusted DIDs*, with a per-commit table in its summary. The merge
button unlocks.

**Failing.** Push a commit made with `git -c commit.gpgsign=false commit`, or
one signed by someone with no grant:

```
TRUSTED      1a2b3c4d5e6f  alice (did:webvh:QmXk…:acme.example) (via github.com/acme/widgets)
UNSIGNED     9f8e7d6c5b4a  commit carries no signature
UNAUTHORIZED 0a1b2c3d4e5f  bob (did:webvh:…) is not authorized by the registry
…
FAIL: 1/3 commits pass
```

or, posted by the bridge, *2 of 3 commits are not trusted* with ❌ against
each. The check is required, so the pull request cannot merge — and nobody,
the bridge included, can bypass the ruleset. Every verdict and its fix is in
the [runbook](RUNBOOK.md#5-verdicts-and-what-to-do-about-them).

**Merge with a merge commit.** GitHub signs web-UI merges with `web-flow`;
the check exempts a *clean merge* of passing parents and nothing else. A
squash merge or rebase-merge produces single-parent `web-flow` commits that
fail `platformSignedEdit` wherever they are checked next.

---

## 9. Variants

### 9.1 A personal account

The fallback, not the recommendation. What changes:

- **Config:** `app_owner = "<login>"` and `app_owner_is_user = true`. The
  App is private, so it installs only on that account; bind that account
  (`--owner <login>`).
- **No repository creation by the bridge.** `cnm git create` reserves the
  name and prints steps instead of creating it:

  ```
  github.com/alice/gadgets — pendingCreate
    1. Create the repository `alice/gadgets` on github.com, public, with no initial commit.
    2. In a clone of it, run `vgi repo init --vtc … --resource github.com/alice/gadgets` …
    3. Run `cnm git adopt github.com/alice/gadgets --owner did:…` to tell the VTC the repository exists.
  ```

  **Skip step 2**: there is no `vgi` command (see *Not implemented*, below),
  and in bridge mode the adopt's bootstrap does what it describes. Create the
  repository on GitHub (the account holder: `gh repo create alice/gadgets --public`),
  then run step 3 — finishing one's own reservation is a normal-class action.
- **The guard** is the **bridge-posted check** (personal accounts have no org
  rulesets), and the bridge becomes a merge dependency: while it is down,
  pull requests wait for their check. If the App lacks the check permissions
  (an App registered before them — BRIDGE.md §3), the in-repo workflow with
  **owner review** (two or more linked owners) or **solo** is used instead,
  and repository writers are trusted not to forge a check run.
- **Roles:** a personal account's collaborators can only be `write`; the
  account holder is the repository's admin regardless.

### 9.2 Forgejo (Codeberg or self-hosted)

The same VTC, the same bridge (another `[[forgejo]]` entry), another
namespace. What changes:

- **A bot instead of an App.** Create the bot user, its token (scopes
  `write:organization`, `write:repository`), and an OAuth2 application with
  redirect URIs `https://<public_url>/forgejo/<host>/bind` and `…/link`;
  store the secrets with `vgi-bridge secret set forgejo/<host>/…`
  (BRIDGE.md §4). Add the bridge's DID under the instance's host in the
  VTC's `[git_ns] bridges` — the same DID can serve several hosts.
- **Config:** `[verify_trust] sha256` is required (a Forgejo runner cannot
  verify the release's attestation; take the hash as in
  [runbook §4a](RUNBOOK.md#forgejo-actions-runners)). Workflows run on a
  runner labelled **`docker`**; the bridge has no setting to change it.
- **Bind:** `cnm git namespace bind --forge codeberg.org --owner acme --mode bridge`;
  an organisation owner signs in through the OAuth app at the printed URL.
  The bridge adds the bot to a `vgi-bridge` team and creates the org
  webhook.
- **Linking:** openvtc shows a URL (and its QR code) to authorise on the
  instance, not a device code.
- **The bootstrap:** `.forgejo/workflows/verify-trust.yml` committed, with
  the DIDs as Actions variables where the instance has the variables API and
  as literals otherwise; **fast-forward-only merges** (Forgejo 7+, Gitea
  1.22+), so DID-signed commits land unchanged and no platform key is needed —
  `instance_signing_key_fallback = true` allows instance-signed merge commits
  on an older instance instead; a branch rule that lets nobody push, applies
  to admins, and lists every workflow directory and the keyring as
  **protected file patterns**, so no pull request can change the check that
  judges it. The console shows the guard as `protectedFiles`.
- **Limit:** Forgejo cannot pin a status to its poster, so **repository
  writers are trusted** not to post a fake success. Give write only to people
  you would trust with that.

### 9.3 Manual mode — no bridge

For a VTC without a bridge, or a forge no bridge serves. The VTC still
records rights and publishes the commit rights to the registry; nothing acts
on the forge.

```sh
cnm git namespace bind --forge github.com --owner acme      # --mode manual is the default
```

The namespace is bound at once and the binder is its admin. Then:

- **Repositories:** `cnm git create` prints the steps (as in §9.1); do step 1
  by hand, then set the repository up **by hand as in
  [runbook §4](RUNBOOK.md#4-set-up-the-repository)**, then `cnm git adopt`.
  Use `resource-format: qualified` in the workflow: the VTC publishes only the
  qualified form (`github.com/acme/widgets`), never `acme/widgets`.
- **Roles, drift, the Dependabot re-sign, the bridge-posted check:** none.
  Forge roles are yours to keep in step with the rights; a drift revert is
  refused `notRevertible` ("manual mode").
- **Account links:** none (`git-ns/account/link:unsupportedForge`) — no
  bridge to run the flow. Links matter only for roles, which manual mode does
  not project.

---

## Not implemented, or not yet consistent

Checked against `main` of this repository, verifiable-trust-infrastructure
and openvtc when this was written:

- **`vgi repo init` does not exist.** The VTC's manual steps, and the
  adapters' hints, name it; no crate here builds a `vgi` binary. Use
  [runbook §4](RUNBOOK.md#4-set-up-the-repository) by hand, or, in bridge
  mode, adopt and let the bootstrap do it.
- **Namespace admins get no organisation role.** The bridge projects roles
  per repository only and refuses a namespace-level `projectRoles`
  (`notCapable`: "project git.ns.admin by hand"). Make namespace admins
  organisation owners (or not) yourself.
- **Namespace-level commit rights count only under the bridge-posted
  check.** The VTC publishes `git.ns.admin`'s implied commit right, a
  namespace-wide `git.commit.sign`, and the bridge's service grant on the
  namespace resource (`github.com/acme`); the bridge-posted check queries it
  as the fallback resource. The workflows the bootstrap writes — required
  workflow, in-repo, Forgejo — pass no `fallback-resource`, so there only
  repository-level rights count: a namespace admin who does not own the
  repository, and **commits the bridge re-signs for Dependabot**, fail
  `unauthorized`. Until the workflows carry the namespace fallback, grant
  people on the repository, and re-sign Dependabot pull requests by hand in
  such repositories ([runbook §8e](RUNBOOK.md#8e-dependabot-pull-requests)).
- **Committers get no GitHub role.** `git.commit.sign` projects to no role
  (the default map; nothing in the bridge config changes it): committers
  contribute through forks, and the required check decides what lands.
- **A GitHub required workflow with Actions disabled** in the target
  repository has not been verified against a live organisation; the bridge
  reports disabled Actions as drift either way.

[vti]: https://github.com/OpenVTC/verifiable-trust-infrastructure
