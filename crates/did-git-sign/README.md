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
4. Produces an SSH signature (PROTOCOL.sshsig format) and writes it to stdout
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

## Install

```bash
cargo install did-git-sign
```

`did-git-sign` is the signing half of
[Verifiable Git Infrastructure (VGI)](https://github.com/OpenVTC/verifiable-git-infrastructure);
the CI verifier is the separate [`verify-trust`](https://crates.io/crates/verify-trust) crate.

## Setup

### Per-repository

```bash
did-git-sign init --vta-did did:webvh:scid:your-vta.example.com
```

`init` resolves the VTA, mints a temporary admin did:key, and prints a
`pnm contexts create …` command. Run it in your Personal Network Manager to
authorise the setup session, press Enter, then select the persona and signing
key interactively. This writes `.did-git-sign.json` in the current directory
and configures the local git repo.

### Global (all repositories)

```bash
did-git-sign init --global --vta-did did:webvh:scid:your-vta.example.com
```

Saves config to `~/.config/did-git-sign/` and sets global git config.

This also sets `did-git-sign.key` and `core.hooksPath` for **every repository
on the machine** — that pair decides the identity your commits claim, and it
must match the key that signs them. Right for one community; wrong for two, and
quietly so, since commits in the other community would claim this DID. `init`
prints the per-remote alternative when you use `--global`; see
[Selecting which community persona signs](#selecting-which-community-persona-signs).

`init` refuses to take `core.hooksPath` if something else already owns it
(husky, lefthook, pre-commit), rather than silently stopping those hooks.

### Non-interactive

Name the persona and key to skip the picker (and `--yes` to skip the
"press Enter once authorised" prompt):

```bash
did-git-sign init \
  --vta-did    did:webvh:scid:your-vta.example.com \
  --key-id     your-vta-key-id \
  --did-key-id did:webvh:scid:your-vta.example.com#key-0 \
  --name       "Your Name" \
  --yes
```

### Options

| Flag | Description |
|------|-------------|
| `--vta-did` | VTA DID; the service URL is discovered from its document (required) |
| `--context` | Context id to provision into (default `did-git-sign`) |
| `--key-id` | VTA key id for the signing key (skips interactive selection) |
| `--did-key-id` | DID verification-method id to sign as (skips interactive selection) |
| `--name` | Git `user.name` (optional) |
| `--vta-url` | Override the VTA URL instead of resolving it from the DID |
| `--global` | Configure global git instead of per-repo |
| `--yes` | Assume the admin grant is already registered; skip the prompt |

### What `init` configures

The `init` command performs the following:

1. **Saves config** to `.did-git-sign.json` (local) or `~/.config/did-git-sign/config.json` (global) — contains only `key_id`, `did_key_id`, and `user_name`
2. **Stores VTA credentials** (URL, DIDs, private key) in the OS keyring (macOS Keychain / Linux Secret Service)
3. **Verifies VTA connectivity** by authenticating and fetching the signing key
4. **Configures git:**
   - `gpg.format = ssh`
   - `gpg.ssh.program = did-git-sign`
   - `gpg.ssh.defaultKeyFile = <config path>`
   - `commit.gpgsign = true`
   - `user.signingKey = <config path>`
   - `did-git-sign.key = <DID#key-id>` — selects the signing persona *and* is
     the claim the `commit-msg` hook writes into the trailer; see below
   - `core.hooksPath = <hook dispatcher>` — see below
   - `user.name = <name>` (if provided)

   `user.email` is left alone: it stays an ordinary address so forges can
   attribute your commits to your account.
5. **Creates an `allowed_signers` file** for signature verification and sets `gpg.ssh.allowedSignersFile`
6. **Installs a `commit-msg` hook** that appends the `Signed-by-DID:` trailer.
   Because `core.hooksPath` is a single slot, the hook directory it installs
   also carries a delegating stub for every other standard hook, each of which
   execs the repository's own `.git/hooks/<name>` — so hooks you already have,
   and hooks you add later, keep running. `uninstall` removes the directory and
   unsets `core.hooksPath`.

## Usage

After setup, commits are signed automatically:

```bash
git commit -m "my signed commit"
```

Verify signatures:

```bash
git log --show-signature
```

Check your configuration and VTA connectivity:

```bash
did-git-sign health
```

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
git calls: did-git-sign -Y sign -f .did-git-sign.json -n git
    |                                                (stdin: commit data)
    v
did-git-sign:
    1. Load config from .did-git-sign.json (key_id + did_key_id only)
    2. Load VTA credentials from OS keyring
    3. Authenticate with VTA (or use cached token from keyring)
    4. Fetch Ed25519 key: VTA.get_key_secret(key_id)
    5. Sign commit data (PROTOCOL.sshsig format)
    6. Output SSH signature to stdout
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
| `{did_key_id}:vta` | VTA URL, VTA DID, credential DID, credential private key, signing key ID |
| `{did_key_id}:token` | Cached VTA access token and expiry |

[verify-trust]: https://crates.io/crates/verify-trust
