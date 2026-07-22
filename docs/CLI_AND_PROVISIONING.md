# Doorman CLI, account provisioning, and Unix-tool interop

Doorman is not only an authentication *library*; it also ships account
management and a command-line tool so you can create, manage, and log in to
macOS accounts **the same way you would on Linux**, while the stock macOS/Unix
tools keep working against the very same accounts.

## Why this interoperates (the important part)

Linux stores accounts in flat files (`/etc/passwd`, `/etc/shadow`,
`/etc/group`). macOS stores them in **Open Directory** (local node under
`/var/db/dslocal`). Doorman does **not** invent a parallel account store — its
provisioning writes through the canonical macOS interfaces:

| Operation | What Doorman drives underneath |
|-----------|--------------------------------|
| create/delete user | `dscl .` on the local Open Directory node |
| set/reset password | the OpenDirectory API (no plaintext on any argv) |
| create home directory | `createhomedir` (materializes the macOS user template) |
| create/delete group, membership | `dseditgroup` |
| authenticate | OpenDirectory / OpenPAM / dsLocal (see the library docs) |

Because it is the same store the whole OS uses, **accounts created by Doorman
are ordinary macOS accounts**: `id`, `dscl`, `dscacheutil`, `passwd`, System
Settings, and the Login Window all see and manage them, and passwords set by
Doorman verify with `dscl . -authonly` (and vice-versa). There is no
divergence to keep in sync. The integration test (`tests/integration.sh`)
asserts exactly this cross-tool interop.

> Note: this is why "does `passwd` still work?" is yes. Doorman does not
> replace `/usr/bin/passwd`; it writes the same `ShadowHashData`. You can set a
> password with `doorman passwd` and verify it with the system `passwd`/`dscl`,
> or vice-versa.

## The `doorman` command

```
doorman authenticate <user>        verify a password (read from stdin)
doorman login <user> [--exec CMD]  authenticate, then open/launch a session
doorman useradd [opts] <name>      create a user
doorman userdel [-r] <name>        delete a user (-r removes the home dir)
doorman passwd [--stdin] <user>    set/reset a password
doorman groupadd [-g gid] <name>   create a group
doorman groupdel <name>            delete a group
doorman usermod -aG <group> <user> add a user to a group
doorman gpasswd -a|-d <user> <group>  add/remove a group member
doorman users | sessions | groups <user>
```

`useradd` understands the common Linux flags: `-m/-M` (create/skip home),
`-u UID`, `-g GID`, `-s SHELL`, `-c COMMENT` (RealName), `-d HOME`,
`-p PASSWORD`, `-G g1,g2` (supplementary groups), plus `--admin` and `--hidden`.

## Linux-compatible tool names

The same binary responds to the classic tool names when invoked under them, so
existing Linux account scripts run unchanged. `make install` (and the Nix
`doorman-cli` package) install these symlinks alongside `doorman`:

```
useradd  userdel  passwd  groupadd  groupdel  usermod  gpasswd  ->  doorman
```

So `useradd -m -s /bin/zsh alice` and `passwd alice` work on macOS, backed by
this framework. (They live in Doorman's `bin` dir; your `PATH` order decides
whether they shadow the system tools — Doorman never overwrites `/usr/bin`.)

### Example

```console
# create a user with a home directory and password, add to a group
$ sudo useradd -m -c "Alice Example" -s /bin/zsh -p 'S3cret!' alice
$ sudo groupadd builders
$ sudo usermod -aG builders alice

# the stock tools see it immediately
$ id alice
$ dscl . -read /Users/alice NFSHomeDirectory
$ dscl . -authonly alice 'S3cret!'      # succeeds

# authenticate / log in through the framework
$ printf 'S3cret!\n' | doorman authenticate alice
$ printf 'S3cret!\n' | sudo doorman login alice --exec '/usr/bin/id -un'
alice
```

## Provisioning from C

The CLI is a thin shell over the library API (`doorman/include/doorman.h`):

```c
doorman_user_spec_t spec = {
    .name = "alice", .full_name = "Alice Example",
    .password = "S3cret!", .shell = "/bin/zsh",
    .create_home = true, .admin = false,
};
doorman_create_user(&spec);                 /* useradd  */
doorman_add_user_to_group("alice", "builders");
doorman_set_password("alice", "newpass");    /* passwd   */
doorman_delete_user("alice", /*remove_home=*/true); /* userdel -r */
```

All provisioning calls require root and return `DOORMAN_ERR_PERM` otherwise.

## Security notes

- **Passwords never touch a command line.** Doorman writes passwords through the
  OpenDirectory API (`ODRecord changePassword:toPassword:`), not `dscl -passwd`,
  so the plaintext is never visible in the process table (`ps`) of other local
  users. The CLI reads the password from a no-echo prompt or stdin and scrubs
  the buffer immediately after use.
- **Names are validated before use.** Every account/group name is checked
  against a conservative character set (and rejected if it contains `/`, `..`,
  a leading `-`/`.`, control characters, or is over-long) before it is
  interpolated into a record path or passed to a tool. This blocks path
  traversal in the offline reader and argument smuggling into the tools.
- **No shell is ever invoked.** Provisioning spawns `dscl`/`dseditgroup`/
  `createhomedir` via `NSTask` with an explicit argument vector, so there is no
  shell to inject into.
- **Home deletion is fenced.** `userdel -r` only removes a home directory that
  lives under `/Users/` and contains no `..` component.
- Creating accounts and homes needs root; the API enforces this.
- These operations mutate real system accounts. Test against throwaway users.

For the full threat model and the authentication-path protections (constant-time
hash comparison, memory scrubbing, fork-safe session launch), see
[`SECURITY.md`](SECURITY.md).
