# macOS vs Linux authentication: the complete difference map

This is the reference that `libdoorman` implements against. It enumerates every
axis on which macOS user authentication differs from Linux, states what each
platform actually does, and records **how the framework bridges the gap** so a
caller can authenticate on macOS the same way it would on Linux.

Legend for the "Bridge" column used throughout:

- ✅ **Bridged** — the framework hides the difference; callers use one API.
- ⚠️ **Partial** — bridged for the common case; caveats noted.
- ⛔ **Not bridgeable** — a platform reality the caller must be aware of; the
  framework surfaces it honestly rather than pretending.

---

## 0. The one-paragraph summary

Linux authentication is a stack of *flat text files* (`/etc/passwd`,
`/etc/shadow`, `/etc/group`) read through *NSS*, with credential verification
*delegated to PAM* and authorization handled separately (sudo, polkit).
macOS authentication is a *directory service* (Open Directory / opendirectoryd)
storing structured records, with credential verification reachable through
*several* native layers (OpenDirectory, OpenPAM, Authorization Services, Local
Authentication) and password material entangled with *FileVault, the Secure
Enclave, SecureToken, and the login keychain*. The APIs differ, the storage
differs, the hashing container differs, and macOS couples "knowing the
password" to unlocking encrypted material in ways Linux does not.

---

## 1. Identity / account database

| | Linux | macOS |
|---|---|---|
| Store | `/etc/passwd`, `/etc/group` (+ NIS/LDAP/SSS) | Open Directory; local node = dsLocal plists in `/var/db/dslocal/nodes/Default/{users,groups}/*.plist` |
| Resolver | NSS (`/etc/nsswitch.conf`): `files`, `systemd`, `sss`, `ldap`, `winbind` | opendirectoryd; search policy configured, not a switch file |
| CLI | `getent`, `useradd`, `usermod`, `passwd` | `dscl`, `sysadminctl`, `dsimport`, `dseditgroup` |
| Record shape | fixed 7 colon-separated fields | arbitrary multi-valued attributes (`RecordName`, `RealName`, `UniqueID`, `NFSHomeDirectory`, `UserShell`, `GeneratedUID`, ...) |
| `getpwnam` source | reads `files`/NSS | serviced by opendirectoryd (there is **no** real `/etc/passwd`; it only holds `root`/`daemon`/`nobody` for single-user boot) |

**Bridge:** ✅ `doorman_enumerate_users` / `doorman_lookup_user` use
`getpwent`/`getpwnam`, which opendirectoryd services on macOS and NSS services
on Linux — so the caller gets the same `struct passwd`-shaped data on both.
The multi-valued OD attribute model is only exposed where it matters (account
policy checks in `acct_mgmt`).

---

## 2. Password hash: storage location and algorithm

| | Linux | macOS |
|---|---|---|
| Location | `/etc/shadow` (root-only), field 2 | `ShadowHashData` blob inside the user's dsLocal record (root-only) |
| Container | `$id$rounds$salt$hash` in one string | binary plist → dict keyed by mechanism |
| Modern default | `$y$` yescrypt (was `$6$` SHA-512-crypt) | `SALTED-SHA512-PBKDF2` (`entropy` + `salt` + `iterations`) |
| Other schemes | `$1$` md5, `$5$` sha256, `$6$` sha512, `$2b$` bcrypt, `$7$`/`$gy$` | legacy `SALTED-SHA512`, `SHA1`, plus Kerberos keys, `SRP`, etc. |
| Verify primitive | `crypt(3)` (hash == verify: feed stored value as setting) | no exposed crypt; recompute PBKDF2 or ask OpenDirectory |
| Aging metadata | shadow fields: lastchg/min/max/warn/inactive/expire | OD `accountPolicy` plists (global + per-user), not inline |

**Bridge:** ✅ The `DSLOCAL` backend parses `ShadowHashData`, pulls
`SALTED-SHA512-PBKDF2`, and verifies with PBKDF2-HMAC-SHA512 in constant time —
the structural twin of Linux's "re-run `crypt` and compare". For anything
beyond local SALTED-SHA512-PBKDF2 (Kerberos, network records, alternate
mechanisms) the `OPENDIRECTORY` backend defers to opendirectoryd, which knows
every mechanism. `AUTO` picks OpenDirectory first, dsLocal as fallback.

---

## 3. The authentication API / abstraction layer

This is the biggest structural difference: Linux has **one** blessed
application entry point (PAM); macOS has **several** overlapping ones.

| Purpose | Linux | macOS |
|---|---|---|
| App-facing authn API | **PAM** (`libpam`, `security/pam_appl.h`) | OpenDirectory (`ODRecord verifyPassword:`), **OpenPAM** (same header!), `dscl . -authonly` |
| Module location | `/lib/security/pam_*.so`, cfg `/etc/pam.d/` | `/usr/lib/pam/pam_*.so.2`, cfg `/etc/pam.d/` — but modules delegate to OD (`pam_opendirectory`) |
| GUI credential UI | none (app draws it) | Local Authentication (`LAContext`) for password/Touch ID/Watch |
| Keychain/secret unlock | not part of authn | Keychain Services unlocks the login keychain *with the same password* |
| Smartcard | `pam_pkcs11`, `pam_poldi` | CryptoTokenKit / PIV, `pam_smartcard` |

Key point: **macOS ships OpenPAM.** `pam_start`/`pam_authenticate`/
`pam_acct_mgmt`/`pam_setcred`/`pam_open_session` and `/etc/pam.d/` all exist.
So a PAM-written Linux program can, in principle, keep calling PAM on macOS —
the stack just resolves to `pam_opendirectory` instead of `pam_unix`.

**Bridge:** ✅ `libdoorman` offers a single conversation-driven API modeled on
PAM, with a `PAM` backend that literally drives macOS's OpenPAM stack (closest
port), plus `OPENDIRECTORY`/`DSLOCAL` backends for callers that want to skip
the PAM config surface. The conversation callback (`doorman_conv_t`) is a 1:1
analogue of `struct pam_conv` (message styles map to `PAM_PROMPT_ECHO_*`).

---

## 4. Authentication vs authorization

| | Linux | macOS |
|---|---|---|
| Authn (who are you) | PAM | OpenDirectory / OpenPAM |
| Fine-grained authz | **polkit** (`.policy` actions), capabilities | **Authorization Services** (rights database `/var/db/auth.db`, policy in `authorization.plist`, `AuthorizationCreate`) |
| Privilege escalation | `sudo` (sudoers) + PAM | `sudo` (+ PAM, incl. `pam_tid` Touch ID); GUI "click the lock" via Authorization Services |
| Root account | often active (wheel/sudo) | disabled by default; `admin` (gid 80) → sudo |

polkit has **no** macOS equivalent; Authorization Services fills the role but
with a totally different API and rights model.

**Bridge:** ⚠️ `libdoorman` is an **authentication** framework (the PAM half),
which is what a display manager needs. It deliberately does **not** try to
emulate polkit or Authorization Services rights; a caller needing "authorize
this specific privileged action" should use Authorization Services directly.
This boundary is called out so callers don't expect authz semantics.

---

## 5. Credential establishment (the `pam_setcred` phase)

| | Linux | macOS |
|---|---|---|
| What "establish credentials" means | acquire Kerberos TGT (`pam_krb5`), join kernel keyring, set up group creds | unlock login keychain, establish Kerberos/OD credential, activate SecureToken context |
| API | `pam_setcred(pamh, PAM_ESTABLISH_CRED)` | `pam_setcred` (OpenPAM) → `pam_opendirectory`; or Security/Keychain APIs |

On Linux, authenticating and *establishing credentials* are separate steps for
good reason (Kerberos tickets, keyrings). macOS has the same split conceptually
but ties it to the login keychain and (on Apple Silicon) SecureToken.

**Bridge:** ✅ `doorman_setcred()` mirrors `pam_setcred`. With the `PAM`
backend it calls the real `pam_setcred`, running whatever the `session`/`auth`
modules configure (including OD credential setup). For the directory backends
it is a documented, safe no-op that returns success (there is no generic,
non-GUI way to unlock another user's login keychain pre-session; that must
happen inside the user's own security session). The caveat is surfaced, not
hidden.

---

## 6. Groups and supplementary group resolution

| | Linux | macOS |
|---|---|---|
| Store | `/etc/group` (+ `/etc/gshadow`) | OD group records; membership can be **nested** and **computed** |
| Membership model | flat: names listed in the group line | UUID-based membership resolved by `opendirectoryd`/`membership` (`mbr_*` APIs); nested groups |
| Resolve for login | `initgroups`, `getgrouplist` | `getgrouplist` works, but true membership may include dynamic/nested results |
| Notable groups | `wheel`/`sudo` | `admin` (80), `staff` (20), `wheel` (0), `everyone` |
| NGROUPS | ~65536 (was 16/32) | 16 in the classic API; membership API handles more |

**Bridge:** ✅ `doorman_get_groups` wraps `getgrouplist` (fed by opendirectoryd
on macOS, NSS on Linux) so a caller gets the same supplementary GID list on
both. `doorman_open_session` calls `initgroups` before dropping privileges,
matching what a Linux DM does. ⚠️ Deeply nested/computed OD memberships beyond
what `getgrouplist` returns are not separately expanded.

---

## 7. UID / GID conventions

| | Linux | macOS |
|---|---|---|
| root | 0 | 0 |
| System accounts | UID < 1000 (Debian/RH) or < 500 (old) | UID 1–500, names prefixed `_` (e.g. `_spotlight`) |
| First human user | 1000 | 501 |
| `nobody` | 65534 | -2 (4294967294) |
| Hidden from login | shell = nologin / not in DM filter | `IsHidden=1` attribute, `_`-prefix, or UID < 500 |

**Bridge:** ✅ `doorman_enumerate_users(interactive_only=true)` applies the
platform-appropriate filter (UID ≥ 500 threshold, `_`-prefix and nologin shell
exclusion on macOS) so the "who shows up on the login screen" set matches a
Linux DM's UID ≥ 1000 filter conceptually.

---

## 8. Account state / policy / lockout

| | Linux | macOS |
|---|---|---|
| Disable an account | `!`/`*` in shadow hash, `chage -E 1`, `usermod -L` | `;DisabledUser;` token in `AuthenticationAuthority`; `pwpolicy`/OD accountPolicy |
| Expiration | shadow expire fields | OD `accountPolicy` (`policyAttributeExpiresEveryNDays`, hard expiry) |
| Failed-login lockout | `pam_faillock` / `pam_tally2` | OD accountPolicy (`maxFailedLoginAttempts`, `minutesUntilFailedAuthenticationReset`) |
| Password quality | `pam_pwquality`/`pam_cracklib` | OD accountPolicy content rules; `pwpolicy` |

**Bridge:** ⚠️ `doorman_acct_mgmt` checks the `AuthenticationAuthority` for the
`;DisabledUser;` token (directory backends) and delegates to `pam_acct_mgmt`
for the PAM backend (which evaluates the full OD account policy). Rich policy
introspection (days-until-expiry, remaining attempts) is not yet surfaced as
structured data; the PAM backend is the way to get full policy enforcement.

---

## 9. Password ⇄ encryption / keychain coupling (macOS-specific)

This category essentially does not exist on Linux and is the deepest source of
"macOS is different".

| Concept | Linux analogue | macOS reality |
|---|---|---|
| Disk encryption unlock | LUKS, optionally `pam_mount` | **FileVault** unlock is gated on the user's password **and** a **SecureToken** (Intel) / **Bootstrap Token** (Apple Silicon). Only SecureToken holders can unlock at boot. |
| Secret store unlock | gnome-keyring/kwallet via `pam_gnome_keyring` | **login keychain** auto-unlocks with the login password; wrong path leaves it locked |
| Hardware-bound keys | TPM (varies) | **Secure Enclave**; keys never leave hardware |
| Pre-boot auth | separate from login | FileVault pre-boot login *is* an OD auth that then chains to loginwindow |

**Bridge:** ⛔ Not bridgeable by an authentication library alone. `libdoorman`
verifies the password (which is the prerequisite), and documents that FileVault
/ SecureToken / keychain unlock are separate macOS subsystems. A full "log in
like Linux" on FileVault-enabled Apple Silicon must additionally hold a
SecureToken; the framework surfaces this as a known limitation rather than
silently failing. (`AuthenticationAuthority` exposes whether a user has a
`;SecureToken;`.)

---

## 10. Session and login lifecycle

| | Linux | macOS |
|---|---|---|
| Session manager | **systemd-logind** (seats, sessions, `loginctl`), or ConsoleKit | **launchd** (per-user GUI domain) + **loginwindow** + WindowServer; no logind |
| PAM session hook | `pam_systemd` registers session, creates `XDG_RUNTIME_DIR` | `pam_launchd`-style bootstrap; `XDG_RUNTIME_DIR` doesn't exist natively |
| Accounting records | `utmp`/`wtmp`/`btmp` | `utmpx` (BSD), plus `asl`/unified logging |
| Security session | n/a | per-`SecuritySession` / audit session (`au_session`) |
| Env for GUI session | `XDG_*`, `WAYLAND_DISPLAY`/`DISPLAY` | Aqua uses launchd env; no XDG by default |
| Session catalog | `.desktop` in `/usr/share/{x,wayland}-sessions` | none (loginwindow starts Aqua); no `.desktop` concept |

**Bridge:** ✅ For the display-manager use case: `doorman_enumerate_sessions`
reads the same freedesktop `.desktop` directories a Linux DM uses (so a ported
Wayland DM's session list works unchanged) and adds a synthetic `aqua` entry.
`doorman_open_session` performs the Linux DM launch dance (fork →
setgid/initgroups/setuid → build `HOME`/`USER`/`SHELL`/`PATH`/`XDG_RUNTIME_DIR`/
`XDG_SESSION_TYPE`/`WAYLAND_DISPLAY` → exec). ⚠️ It does **not** register with
launchd/loginwindow or create a macOS SecuritySession; it launches a session
process the way a Linux greeter does. Integrating with launchd/WindowServer for
a *stock Aqua* login is out of scope (that is loginwindow's job).

---

## 10a. Environment propagation (`pam_getenvlist`)

| | Linux | macOS |
|---|---|---|
| Modules export env into session | `pam_getenvlist` collects it | OpenPAM has `pam_getenvlist` too, but stock macOS modules export little |

**Bridge:** ⚠️ `doorman_open_session` sets the standard login/XDG variables
directly. A future `doorman_getenvlist` could forward PAM-exported variables;
today the session environment is constructed explicitly.

---

## 11. Network / directory / enterprise auth

| | Linux | macOS |
|---|---|---|
| LDAP | `nss-ldap`/`sssd` + `pam_ldap` | OD LDAPv3 plugin (native bind) |
| Active Directory | `sssd`/`winbind` | OD AD plugin; `dsconfigad` |
| Kerberos | `pam_krb5`, `/etc/krb5.conf` | built-in Heimdal; OD manages tickets |
| Cached offline login | sssd cache | **mobile accounts** (cached network accounts) |
| Modern SSO | (varies) | **Platform SSO** / SSO extensions |

**Bridge:** ✅ Because the `OPENDIRECTORY` and `PAM` backends go through
opendirectoryd, network/AD/mobile accounts authenticate through the *same*
`doorman_authenticate` call with no extra caller code — this is a place macOS's
directory model actually makes the bridge cleaner than Linux's.

---

## 12. Biometrics and hardware-backed auth

| | Linux | macOS |
|---|---|---|
| Fingerprint | `fprintd` + `pam_fprintd` | **Touch ID** via `LAContext` / `pam_tid.so` (sudo) |
| Security key | `pam_u2f`, `pam_yubico` | smartcard/PIV via CryptoTokenKit |
| Proximity unlock | none standard | **Apple Watch** auto-unlock |
| Key protection | TPM (optional) | **Secure Enclave** (standard) |

**Bridge:** ⚠️ Password/knowledge-factor auth is fully bridged. Touch ID and
Watch unlock are GUI/`LAContext` mechanisms; the `PAM` backend can invoke
`pam_tid` where a service configures it, but a general non-interactive Touch ID
API is intentionally out of scope for a headless login library.

---

## 13. Tooling and file-path cheat sheet

| Task | Linux | macOS |
|---|---|---|
| List users | `getent passwd` | `dscl . -list /Users` |
| Read a record | `getent passwd alice` | `dscl . -read /Users/alice` |
| Verify a password | (no direct tool; PAM) | `dscl . -authonly alice` |
| Create user | `useradd` | `sysadminctl -addUser` / `dscl` |
| Set password | `passwd`, `chpasswd` | `dscl . -passwd`, `sysadminctl -resetPasswordFor` |
| Password policy | `chage`, `pam_pwquality` | `pwpolicy` |
| Groups | `/etc/group`, `groups` | `dseditgroup`, `dscl . -read /Groups/admin` |
| Auth config | `/etc/pam.d/`, `/etc/nsswitch.conf` | `/etc/pam.d/`, OD search policy, `/var/db/dslocal` |
| Session mgmt | `loginctl` | `launchctl`, loginwindow |

---

## 14. Account creation & management

| | Linux | macOS |
|---|---|---|
| Create a user | `useradd` edits `/etc/passwd`+`/etc/shadow` | `sysadminctl`/`dscl` writes an Open Directory record |
| Create a home | `useradd -m` copies `/etc/skel` | `createhomedir` copies `/System/Library/User Template` |
| Set a password | `passwd`/`chpasswd` writes `/etc/shadow` | `passwd`/`dscl -passwd` writes `ShadowHashData` |
| Create a group | `groupadd` edits `/etc/group` | `dseditgroup` writes an OD group record |
| Group membership | edit the group line | `dseditgroup -o edit` (UUID-based membership) |
| Tools | `useradd`, `usermod`, `userdel`, `groupadd`, `gpasswd`, `passwd` | `sysadminctl`, `dscl`, `dseditgroup`, `createhomedir`, `pwpolicy` |

**Bridge:** ✅ Doorman provides a full provisioning API (`doorman_create_user`,
`doorman_delete_user`, `doorman_set_password`, `doorman_create_home`,
`doorman_create_group`, `doorman_delete_group`,
`doorman_add_user_to_group`/`..._remove_...`) plus a CLI that also answers to
the Linux tool names (`useradd`, `userdel`, `passwd`, `groupadd`, `groupdel`,
`usermod`, `gpasswd`). It writes through the canonical macOS substrate (`dscl`,
`dseditgroup`, `createhomedir`), so accounts it creates are ordinary macOS
accounts and the stock tools fully interoperate (verified by
`tests/integration.sh`). New accounts get a proper macOS home from the user
template. See [`CLI_AND_PROVISIONING.md`](CLI_AND_PROVISIONING.md).

## Bridge scorecard

| # | Area | Status | doorman surface |
|---|---|---|---|
| 1 | Identity DB | ✅ | `doorman_enumerate_users`, `doorman_lookup_user` |
| 2 | Password hash | ✅ | `DSLOCAL` + `OPENDIRECTORY` backends |
| 3 | Authn API | ✅ | conversation API + `PAM`/`OPENDIRECTORY`/`DSLOCAL` backends |
| 4 | Authorization (polkit) | ⚠️/out-of-scope | use Authorization Services directly |
| 5 | Credential establishment | ✅ | `doorman_setcred` |
| 6 | Group resolution | ✅ | `doorman_get_groups`, `initgroups` in launch |
| 7 | UID conventions | ✅ | `interactive_only` filtering |
| 8 | Account policy/lockout | ⚠️ | `doorman_acct_mgmt` (full policy via `PAM`) |
| 9 | FileVault/keychain/SecureToken | ⛔ | documented; password verified as prerequisite |
| 10 | Session lifecycle | ✅ (DM) / ⚠️ (Aqua) | `doorman_enumerate_sessions`, `doorman_open_session` |
| 11 | Network/AD/mobile | ✅ | via `OPENDIRECTORY`/`PAM` backends |
| 12 | Biometrics/hardware | ⚠️ | `PAM` backend where configured |
| 13 | Tooling | ✅ (doc) | this document |
| 14 | Account creation/management | ✅ | provisioning API + CLI (`useradd`/`passwd`/...); writes native OD store |

The framework's guiding rule: **bridge everything that can be bridged behind a
Linux-shaped API, and honestly surface the handful of macOS realities
(FileVault/SecureToken/keychain, Aqua session registration, polkit-style
authorization) that a login library cannot paper over.**
