# fxwm

A low-level window manager experiment for macOS that hooks into the SkyLight compositor layer.

## Overview

fxwm injects into the macOS WindowServer process to intercept and modify compositor behavior. It uses function hooking to tap into private SkyLight framework APIs, allowing for custom window management and rendering at the compositor level.

## Components

- **fxwm** - The injector binary that loads the dylib into WindowServer
- **libprotein_render.dylib** - The payload that hooks SkyLight functions and implements custom rendering

## Features

- Hooks `CGXUpdateDisplay` and other SkyLight internals
- Tracks window creation/destruction via `WSWindowCreate` hooks
- Creates custom compositor windows using `CAContext` and private APIs
- Renders an overlay displaying logs from `/tmp/protein.log`

## Building

Requires Nix with flakes enabled:

```bash
nix build
```

The build produces arm64e binaries (Apple Silicon with pointer authentication).

## Requirements

- macOS on Apple Silicon (arm64e)
- Xcode Command Line Tools
- System Integrity Protection OFF (for WindowServer injection)

## Technical Details

- Uses [Dobby](https://github.com/jmpews/Dobby) for function hooking on arm64e
- Resolves private symbols via dyld shared cache parsing
- Communicates with CoreAnimation via `CAContext` for GPU-accelerated rendering

## License

Research/experimental use only.
