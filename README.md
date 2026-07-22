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

- **`macauth/`**: Standalone macOS authentication framework (`libmacauth`). A PAM-inspired library that verifies credentials (OpenDirectory / dsLocal `ShadowHashData` / native OpenPAM), enumerates users and sessions, and launches a session as the authenticated user. fxwm consumes it for its login screen, and other projects (e.g. a ported Wayland display manager) can link it independently. See [`macauth/README.md`](macauth/README.md).
- **`manager/`**: The core logic loaded into WindowServer. Contains the Metal renderer, UI framework, font engine, and event hooks. Its login view delegates all authentication to `libmacauth`.
- **`src/`**: The bootstrap loader. Handles the read-write overlay creation and injection setup to override the system process.
- **`examples/macdm/`**: A minimal console "display manager" showing how an external login program links and drives `libmacauth`.
- **`docs/LINUX_AUTH.md`**: How Linux authenticates users (PAM, NSS, shadow/`crypt`, display managers) and how `libmacauth` ports that model to macOS.
- **`docs/AUTH_DIFFERENCES.md`**: The exhaustive macOS-vs-Linux authentication difference map (identity DB, hashing, PAM/OpenDirectory, authorization, FileVault/SecureToken/keychain, sessions, groups, biometrics) with a per-area scorecard of what `libmacauth` bridges.

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
