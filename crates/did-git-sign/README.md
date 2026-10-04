# did-git-sign

A standalone CLI tool that signs git commits using DID Ed25519 keys managed by a
[Verifiable Trust Agent (VTA)](https://github.com/LF-Decentralized-Trust-labs/verifiable-trust-infrastructure).
It acts as a git SSH signing proxy — no private key material ever touches disk.

## How It Works

Git supports pluggable signing programs via `gpg.ssh.program`. When you commit,
git calls `did-git-sign` with the commit data on stdin. The tool:

1. Loads its config (`.did-git-sign.json`) and retrieves the VTA credential from the OS keyring
2. Authenticates with the VTA (or reuses a cached token)
3. Fetches the Ed25519 signing key from the VTA on-the-fly
4. Produces an SSH signature (PROTOCOL.sshsig format) and writes it to `<file>.sig`, as ssh-keygen does (to stdout when git passes no file)
5. Zeroizes the key material from memory

Your DID verification method ID (e.g. `did:webvh:abc:example.com#key-0`) is
recorded in a `Signed-by-DID:` git trailer, linking every commit to your
decentralized identity.

That trailer is load-bearing, not decorative. An sshsig blob carries a raw
Ed25519 key and **no identity**, so the trailer is the only place a commit
states which DID signed it — [`verify-trust`][verify-trust] reads it, resolves
that DID, and requires it to publish the signing key. A commit carrying no DID
claim fails CI as `noSignerDid` however valid its signature.

The trailer sits inside the commit message, which is part of the payload the
signature covers, so it is as tamper-evident as the committer header was. It
lives there rather than in `user.email` so that `user.email` can stay an
ordinary address, which is what GitHub and GitLab match commits against when
attributing them to an account. A `commit-msg` hook installed by `init` writes
it; older commits that carry the DID in `user.email` still verify, through a
fallback in `verify-trust`.
Signing therefore refuses when the committer names a DID other than the key's;
see [Selecting which community persona signs](#selecting-which-community-persona-signs).

## Prerequisites

- A running VTA with your persona DID(s) and Ed25519 signing key(s) provisioned.
- Your **VTA DID** (e.g. `did:webvh:scid:your-vta.example.com`). `init`
  discovers the service URL from the DID document, mints a short-lived admin
  did:key for the setup session, and prints the `pnm contexts create` command
  to authorise it.
- `init` and signing reach the VTA over the transport it advertises: TSP or
  DIDComm through its mediator, REST only when it advertises no mediator. A VTA
  that publishes no REST service is reachable only through its mediator, and
  the mediator DID is stored with the credentials so signing connects the same
  way `init` did.
- If the context has no DID yet (as after `pnm contexts create`), `init`
  offers to create a `did:webvh` there on a DID-hosting server the VTA has
  registered, as `pnm contexts provision --server` does. With no server
  registered, create the DID first: `pnm did-mgmt dids create --context <ctx> …`.

## Install

```bash
cargo install did-git-sign
```

The `tsp` feature is on by default, so the TSP leg of setup is built in;
`--no-default-features` builds without it and falls back to DIDComm.

`did-git-sign` is the signing half of
[Verifiable Git Infrastructure (VGI)](https://github.com/OpenVTC/verifiable-git-infrastructure);
the CI verifier is the separate [`verify-trust`](https://crates.io/crates/verify-trust) crate.

## Setup

Setup is two steps, and neither replaces a signing setup you already have:
`init` sets up an identity without writing any git configuration, and
`enable` makes a repository (or a directory of them) sign with it.

```bash
did-git-sign init --vta-did did:webvh:scid:your-vta.example.com
cd your-repo && did-git-sign enable      # this repository signs with it
```

`init` resolves the VTA, mints a temporary admin did:key, and prints the
`pnm` command that authorises it: `pnm contexts create … --admin-handoff` for a
context that does not exist yet, or `pnm acl create … --contexts <ctx>
--handoff` for one that does (an openvtc persona context, say —
`pnm contexts create` refuses an existing context). Run the one that applies in
your Personal Network Manager, press Enter, then pick the persona and signing
key:

- **Context.** Each is shown with the number of DIDs in it *and its
  sub-contexts* (`openvtc-bob — OpenVTC BOB (2 DIDs)`). openvtc keeps every
  persona in a sub-context of the account context (`<account>/<slug>`) and pins
  no primary DID, so pointing `--context` at the account context finds them all.
- **DID.** Every DID in the chosen context and its sub-contexts, each with its
  name (when one is known) and the context it lives in. With exactly one, it is
  used and named.
- **Key.** Only the chosen DID's own signing keys: active Ed25519 keys in the
  DID's context that its document lists under `assertionMethod`, shown with the
  `DID#key-N` each signs as.

Only when the context and all its sub-contexts hold no DID does `init` offer to
create one, and the default answer is **No**: a new DID has no git rights in any
community until one grants them. Under `--yes` it never creates one; it stops
and says to point `--context` at the context holding your persona, or to create
a DID with `pnm did-mgmt dids create --context <ctx> …`. (0.12.1 to 0.15 created
one by default, and under `--yes`.)

`enable` adds one line to the repository's `.git/config`, an `include.path`
naming did-git-sign's settings for that identity, and changes nothing else.
`did-git-sign disable` removes that line. Every other repository keeps signing
the way it did before.

To sign in every repository under a directory instead, enable the directory:
one `includeIf "gitdir:<dir>/"` line in your global git config, removed by
`disable --dir` with the same path.

```bash
did-git-sign enable --dir ~/code/
did-git-sign disable --dir ~/code/
```

`enable` refuses when `core.hooksPath` already belongs to another tool (husky,
lefthook, pre-commit): the include would replace it and that tool's hooks would
stop running.

`init --global` is refused since 0.14. It used to write these settings into
your global git config, replacing any existing signing key.

### Non-interactive

Name the persona and key to skip the picker (and `--yes` to skip the
"press Enter once authorised" prompt):

```bash
did-git-sign init \
  --vta-did    did:webvh:scid:your-vta.example.com \
  --key-id     your-vta-key-id \
  --did-key-id did:webvh:scid:your-vta.example.com#key-0 \
  --yes
```

### Options

| Flag | Description |
|------|-------------|
| `--vta-did` | VTA DID; the service URL is discovered from its document (required) |
| `--context` | Context to provision into; the DID is looked for in it and its sub-contexts (default `did-git-sign`) |
| `--key-id` | VTA key id for the signing key (skips interactive selection) |
| `--did-key-id` | DID verification-method id to sign as (skips interactive selection) |
| `--profile` | Save the identity under a name (see [Profiles](#profiles-more-than-one-identity)) |
| `--default` | With `--profile`: also make it the default identity |
| `--name` | Recorded in the config file; no longer written to git |
| `--vta-url` | Override the VTA URL instead of resolving it from the DID |
| `--yes` | Assume the admin grant is already registered; skip the prompt |

### What `init` writes

Everything goes under did-git-sign's own directory (`~/.config/did-git-sign/`,
or `~/Library/Application Support/did-git-sign/` on macOS). No git
configuration is written.

1. **`config.json`**: the default identity (`did_key_id`, `user_name`).
2. **VTA credentials** (URL, DIDs, private key, signing key id) in the OS
   keyring (macOS Keychain / Linux Secret Service). The VTA URL must be
   `https://` (cleartext `http://` only to loopback) and carry no
   `user:password@` part.
3. **`allowed_signers`**: one line per identity, for `git log --show-signature`.
4. **`hooks/`**: a `commit-msg` hook that appends the `Signed-by-DID:` trailer,
   and for every other standard hook a stub that runs the repository's own
   `.git/hooks/<name>`, so existing hooks keep running.
5. **`gitconfig/<name>.gitconfig`**: the settings a repository needs to sign as
   this identity, and the file `enable` includes (`<name>` is the profile, or
   `default`):
   - `gpg.format = ssh`, `gpg.ssh.program = did-git-sign`, `commit.gpgsign = true`
   - `user.signingKey` and `gpg.ssh.defaultKeyFile` = `config.json`
   - `gpg.ssh.allowedSignersFile` = `allowed_signers`
   - `core.hooksPath` = `hooks/`
   - `did-git-sign.key = <DID#key-id>`: selects the signing persona *and* is the
     claim the `commit-msg` hook writes into the trailer

   `user.email` and `user.name` are never written: they stay what you set, so
   forges attribute commits to your account.

The trailer always goes in the message's final paragraph, the trailer block
`git log --format='%(trailers)'` and `verify-trust` read, even when the message
contains a `---` line (every Dependabot commit does). The hook uses
`git interpret-trailers --no-divider`, which needs **git ≥ 2.20** (2.19.2 on
the maint line).

### Upgrading: re-run `init` to refresh the hook

`init` writes the hooks; installing a newer `did-git-sign` binary does not
replace them. Each hook carries a version line (`# did-git-sign-hook-version:
N`), and `did-git-sign health` reports `Commit-msg hook: OUTDATED` when the
installed one is older than the binary's (the current hook is version 2).
Re-run `did-git-sign init` to replace them; it overwrites only hooks it wrote.

Hooks from before the version line (v1) placed the trailer **above** any `---`
line in a commit message. Commits made that way are signed but carry no claim
`verify-trust` reads, and fail as `noSignerDid`. After upgrading the hook,
`git commit --amend --no-edit` runs it again and adds the claim at the end
(for older commits in a branch, `reword` them in `git rebase -i`, which also
runs the hook).

An install made before 0.14 wrote its settings into git config directly.
`did-git-sign uninstall` removes those, but only the ones that still hold
did-git-sign's values, so a signing setup you have since restored is kept.

## Profiles: more than one identity

Each identity keeps its credentials in the keyring under its own
`did:…#key-N`. A profile gives it a name, and its own include file, so a
repository picks who signs with one command:

```bash
did-git-sign init --profile bob   --vta-did <VTA DID> --context bob
did-git-sign init --profile carol --vta-did <VTA DID> --context carol

did-git-sign profiles                 # list them; marks the default and the one this repo uses
did-git-sign enable --profile bob     # this repository signs as bob
did-git-sign use carol                # …now as carol (same as enable --profile carol)
did-git-sign health --profile carol
```

The first `init` sets the default. A later `init --profile` adds the identity
beside it without replacing it (`--default` replaces it). `enable --profile`
swaps the repository's include for that profile's, so the key and the
`Signed-by-DID:` claim always move together. Profiles are recorded in
`profiles.json` beside the config; it holds DIDs only, never secrets.

## Usage

After setup, commits are signed automatically:

```bash
git commit -m "my signed commit"
```

Verify signatures:

```bash
git log --show-signature
```

Check your configuration, the installed `commit-msg` hook, and VTA
connectivity (`--did-jsonl <path>` also checks the signing key against a
`did.jsonl` log):

```bash
did-git-sign health
```

`did-git-sign verify` performs a test sign. `did-git-sign uninstall` removes an
identity: its keyring entries, its `allowed_signers` line, its include file and
the lines that include it, and the config file if it is the default. It never
unsets your own signing settings.

### Showing names instead of DIDs

`init`'s context and DID pickers label each entry with a human name where the
VTA has one — an ACL label, or the context's own name — falling back to an
abbreviated DID. Pass `--resolve-agent-names` to `init` or `health` to also
read back the agent name a DID document claims (`example.com/@alice`):

```bash
did-git-sign health --resolve-agent-names
```

Each claimed name is resolved forward and must lead back to the DID that claims
it before it is shown as that DID's; a claim that does not round-trip is tagged
`[unverified]`, because `alsoKnownAs` is self-asserted and an unchecked name is
only what a DID says about itself. Resolution costs an outbound HTTPS fetch per
claimed name, so it is opt-in. Names never replace the DID in a summary or
diagnostic — they are printed above it.

### Selecting which community persona signs

With more than one provisioned persona, you can choose which one signs without
re-running `init`. At sign time the signing key is resolved in this order:

1. The `DID_GIT_SIGN_KEY` environment variable (per-invocation override).
2. The `did-git-sign.key` per-repo git config setting.
3. The `did_key_id` in the config file git points at (the `init` default).

The value is the persona's `did:webvh:…#key-N`. It must have credentials stored
in the keyring (i.e. you ran `init` for that persona); otherwise signing fails
with a clear message rather than silently signing as a different persona.

```bash
# One commit as a specific persona:
DID_GIT_SIGN_KEY=did:webvh:abc:example.com#key-1 git commit -m "…"

# Pin a persona for this repository:
git config did-git-sign.key did:webvh:abc:example.com#key-1
```

**One setting, so the persona and the claim cannot drift.** The `commit-msg`
hook reads the same selector the signer does, in the same order —
`DID_GIT_SIGN_KEY`, then `did-git-sign.key` — so whatever picks the key also
writes the claim. This is why the second `user.email` line each example used to
carry is gone: there is nothing left to keep in step by hand.

Signing still refuses a commit whose claim and key disagree, naming both
halves, rather than writing one that fails in CI as `unknownKey`. That now only
happens if you write a `Signed-by-DID:` trailer yourself, or commit with the
hook bypassed (`--no-verify`) in a repo whose `user.email` is a different DID.

For contributors in more than one community, do not manage this per repository
by hand: a `git config --local` you forget does not error, it signs as the
wrong community. Use git's conditional includes, one file per community:

```ini
# ~/.gitconfig
[includeIf "hasconfig:remote.*.url:https://github.com/OpenVTC/**"]
    path = ~/.config/git/community-openvtc
```

```ini
# ~/.config/git/community-openvtc
[did-git-sign]
    key = did:webvh:abc:example.com#key-0
```

`hasconfig:remote.*.url` (git ≥ 2.36) keys off the remote, so membership follows
the repository rather than where it was cloned; `includeIf "gitdir:…"` matches
on path instead if your layout is authoritative.

## Security Model

### What protects the signing key

The signing key is protected by the **VTA credential in your OS keyring**, and
by the access the VTA grants that credential. Anything that can read that
keyring entry can ask the VTA for what the credential allows, with or without
`did-git-sign`.

### The signing gate is an accident guard, not a boundary

`did-git-sign` signs only when its parent process is git (`git` or a `git-*`
subcommand binary), and only in the `git` sshsig namespace. Every attempt,
allowed or refused, is appended to `audit.log` under the did-git-sign config
directory (`~/.config/did-git-sign/` on Linux).

That **prevents accidental and naive use**: the binary configured as an SSH
signing program for something other than git, a script calling
`did-git-sign -Y sign` directly, or the persona key being used for `file` or
other sshsig namespaces. The audit log gives you a local record to review.

It is **not a boundary against code running as your user**. Such code can run
real `git` with `did-git-sign` as its signing program, and so get a signature
over a commit it chose; it can read the VTA credential from the keyring
directly; and it can edit or truncate the audit log, which is an ordinary file
you own. If you suspect that has happened, treat the persona's VTA credential
as compromised and revoke it in the VTA.

There is no switch that turns the gate off in a released binary. The
`insecure-policy-bypass` cargo feature exists only for this crate's tests, and
it does not compile without debug assertions.

### Other properties

- **Bounded input** — signing refuses input larger than 16 MiB; git's commit
  and tag objects are far smaller.
- **No key material on disk** — the VTA credential private key is stored in the
  OS keyring, and the Ed25519 signing key is fetched from the VTA at sign-time
  and held only in memory.
- **Token caching** — the VTA access token is cached in the OS keyring to avoid
  re-authentication on every commit. Tokens are validated with a 30-second
  safety margin before reuse.
- **Zeroization** — signing key material is zeroized immediately after use via
  the `zeroize` crate.
- **`DID_GIT_SIGN_SSH_KEYGEN` override is test-only.** The path to `ssh-keygen`
  used for the verify / find-principals / check-novalidate delegation paths
  can be overridden via this environment variable so test fixtures can point
  at a mock binary. **Do not set it in production.** An attacker with write
  access to your environment could redirect signature verification to a
  binary that always returns success and silently accept forged signatures.
  The override has no effect on the *signing* path, which never invokes
  `ssh-keygen`.

## Architecture

```
git commit
    |
    v
git calls: did-git-sign -Y sign -f .did-git-sign.json -n git <buffer file>
    |                                                (commit data)
    v
did-git-sign:
    1. Load config from .did-git-sign.json (did_key_id + user_name only)
    2. Load VTA credentials from OS keyring
    3. Authenticate with VTA (or use cached token from keyring)
    4. Fetch Ed25519 key: VTA.get_key_secret(key_id)
    5. Sign commit data (PROTOCOL.sshsig format)
    6. Write SSH signature to <buffer file>.sig
    7. Zeroize key material
    |
    v
git stores signature in commit
```

## Config File Format

The `.did-git-sign.json` file contains only your DID identity:

```json
{
  "did_key_id": "did:webvh:abc123:example.com#key-0",
  "user_name": "Your Name"
}
```

**No VTA credentials or key identifiers are stored on disk.** All VTA
configuration and sensitive material is stored in the OS keyring under the
service name `did-git-sign`:

| Keyring Entry | Contents |
|---------------|----------|
| `{did_key_id}:vta` | VTA URL, VTA DID, credential DID, credential private key, signing key ID, and the VTA's mediator DID when it is reached over DIDComm |
| `{did_key_id}:token` | Cached VTA access token and expiry |

[verify-trust]: https://crates.io/crates/verify-trust
