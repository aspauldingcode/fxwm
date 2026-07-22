# Basalt

<div align="center">

![Project Logo](project-logo.png)

</div>

A Work-In-Progress Desktop Environment for macOS.

**⚠️ WARNING: EXTREMELY EXPERIMENTAL ⚠️**
This project interacts with low-level macOS WindowServer components and modifies system launch configurations via temporary overlays.

## Overview

Basalt (internal name `fxwm`) is an experimental window manager and desktop environment renderer for macOS. It utilizes code injection to allow itself to render custom UI elements _directly on screen_ using Metal. 

## Current State

- **Metal Renderer:** High-performance 2D rendering engine that replaces the compositor.
- **Custom UI Framework:** Lightweight, retain-mode UI system supporting view hierarchies (`PVView`) and interactive controls (`PVButton`).
- **Input Handling:** Processes mouse events for custom UI interaction (Hover, Click states).
- **Text Rendering:** Custom bitmap font rendering engine.
- **System Injection:** Uses `tmpfs` overlays to safely inject libraries into restricted system paths without permanent modification.

## Architecture

- **`doorman/`**: **Doorman** (`libdoorman`), a standalone macOS authentication framework. A PAM-inspired library that verifies credentials (OpenDirectory / dsLocal `ShadowHashData` / native OpenPAM), enumerates users and sessions, and launches a session as the authenticated user — the auth backend that decides who gets in at the door. fxwm consumes it for its login screen, and other projects (e.g. a ported Wayland display manager) can link it independently. See [`doorman/README.md`](doorman/README.md).
- **`manager/`**: The core logic loaded into WindowServer. Contains the Metal renderer, UI framework, font engine, and event hooks. Its login view delegates all authentication to `libdoorman`.
- **`src/`**: The bootstrap loader. Handles the read-write overlay creation and injection setup to override the system process.
- **`cli/`**: The `doorman` command-line tool — authentication plus Linux-style account management. Also answers to `useradd`/`userdel`/`passwd`/`groupadd`/`groupdel`/`usermod` when installed under those names.
- **`examples/macdm/`**: A minimal console "display manager" showing how an external login program links and drives `libdoorman`.
- **`tests/`**: Unprivileged unit tests (`test_doorman.m`) and a privileged end-to-end integration test (`integration.sh`) that creates, logs in to, and deletes a real macOS account and checks stock-tool interop.
- **`Makefile`**: Plain (non-Nix) macOS build of the library, CLI, example, and tests. CI (`.github/workflows/ci.yml`) runs it on a macOS 26 builder.
- **`docs/LINUX_AUTH.md`**: How Linux authenticates users (PAM, NSS, shadow/`crypt`, display managers) and how `libdoorman` ports that model to macOS.
- **`docs/AUTH_DIFFERENCES.md`**: The exhaustive macOS-vs-Linux authentication difference map (identity DB, hashing, PAM/OpenDirectory, authorization, FileVault/SecureToken/keychain, sessions, groups, biometrics, account provisioning) with a per-area scorecard of what `libdoorman` bridges.
- **`docs/CLI_AND_PROVISIONING.md`**: The `doorman` CLI, the account/group provisioning API, and why the stock Unix tools (`passwd`, `id`, `dscl`) interoperate with Doorman-created accounts.

## Building and Running

Prerequisites:
- macOS (Apple Silicon/aarch64)
- [Nix](https://nixos.org/download.html) with Flakes enabled.

### Build

```bash
nix build
```

### Run

To run the compositor injection (requires root privileges to mount overlays and restart WindowServer):

```bash
nix run
```

*Note: This will restart your WindowServer, forcing a logout. Ensure you have saved all work before running.*
