# Doorman security model

Doorman authenticates real macOS users and provisions real macOS accounts, so
it is squarely in the trusted-computing-base of anything that links it. This
document states the threat model, the guarantees the library tries to provide,
and the concrete mitigations in the code.

## Threat model

Doorman runs in two roles:

1. **As an unprivileged verifier** — a program calls `doorman_authenticate*`
   with a name and password. The attacker may control the *name* and *password*
   strings and may race the filesystem/directory.
2. **As a privileged login/provisioning agent** (root) — a display manager or
   admin tool drops privileges to launch a session, or creates/modifies
   accounts. Other *local, unprivileged users* are the adversary here: they may
   read the process table, inspect argv/environment, and read world-readable files.

Doorman does **not** defend against a root-level attacker on the same host, a
malicious OpenDirectory/PAM configuration, or a compromised system toolchain —
those are outside its trust boundary.

## Guarantees and mitigations

### Credentials in memory
- Plaintext passwords collected through the conversation are transferred by
  ownership to the core, which **scrubs them through a `volatile` pointer**
  (`_dm_scrub` / `_dm_scrub_free`) and frees them the instant verification
  returns. The volatile write cannot be removed by dead-store elimination.
- The PAM bridge scrubs every response buffer it copies into PAM storage.
- The CLI scrubs its password and confirmation buffers after use.

### Password verification (offline dsLocal backend)
- The re-derived PBKDF2 key is compared to the stored key with a
  **constant-time** comparison (`_dm_consttime_equal`), so a byte-by-byte match
  position cannot leak through timing.
- The re-derived key scratch buffer is scrubbed before returning.
- PBKDF2 is driven with the record's own salt and iteration count over the
  UTF-8 bytes of the password (byte length, not character count).

### Path-traversal / injection
- **The account name is validated** (`_dm_name_ok`) before it is ever placed
  into `/var/db/dslocal/.../<name>.plist` or handed to a system tool: only
  `[A-Za-z0-9_.-]` is accepted, a leading `-`/`.` is rejected, and `/`, control
  characters, and over-long names are refused. A crafted name therefore cannot
  climb out of the users directory in the offline reader, nor masquerade as a
  command-line option to `dscl`/`dseditgroup`.
- **No shell is ever spawned.** All system tools run via `NSTask` with an
  explicit argument vector, so shell metacharacters are inert.
- **Passwords are set through the OpenDirectory API**, never via
  `dscl -passwd <plaintext>`, so a password is never visible in the process
  table to other local users.
- `userdel -r` only deletes a home directory that is under `/Users/` and free of
  `..`, so a tampered directory record cannot redirect the deletion.

### Privilege drop and session launch
- When launching a session as root, Doorman drops privileges in the correct
  order — `setgid` → `initgroups` → `setuid` — and each call is checked; any
  failure aborts the child with a non-zero exit rather than continuing with
  elevated privileges. As a defence in depth it then asserts that regaining
  root via `setuid(0)` is impossible before `exec`.
- The child’s **entire environment is assembled in the parent** and handed over
  with `execle()`. The post-fork path performs no `setenv`/`getenv` heap churn,
  avoiding the classic fork-in-a-threaded-process allocator hazard, and it
  starts a fresh session with `setsid()`.
- The environment is built from scratch (not inherited), so no attacker-set
  variables leak into the user’s session; `PATH` is pinned to system locations.

### Fail-closed behaviour
- The `AUTO` backend only falls back from OpenDirectory to the offline reader
  for *lookup/system* faults, never to turn a **rejected** password into a
  second attempt.
- Every provisioning entry point returns `DOORMAN_ERR_PERM` when not root,
  rather than partially attempting the operation.

## Reporting

This is experimental software. If you find a vulnerability, please open an issue
describing the impact and a reproduction; do not include real credentials.
