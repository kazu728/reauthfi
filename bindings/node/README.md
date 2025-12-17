# reauthfi (Node.js)

Thin Node.js wrapper for the macOS captive portal detector CLI. It spawns the
`reauthfi` binary (bundled in this package or available on your system PATH).

![Demo](https://raw.githubusercontent.com/kazu728/reauthfi/main/assets/demo.gif)

## Installation

```bash
npm install reauthfi
# or
yarn add reauthfi
```

Requires Node.js 22+ (per `engines` in `package.json`).

Homebrew users can install the CLI separately (recommended for system-wide use):

```bash
brew install kazu728/tap/reauthfi
```

> **Supported platforms:** macOS (arm64). Ensure a `reauthfi` binary is available
> either in this package (if you publish with one) or on your PATH. You can also
> set `REAUTHFI_BINARY` to point to a custom binary.

### Binary bundling

Published npm packages include a macOS arm64 `reauthfi` binary built by GitHub
Actions at release time. If you need to build manually (e.g., local testing),
build the binary for `aarch64-apple-darwin`, copy it next to `index.js` as
`bindings/node/reauthfi`, and ensure it is executable.

## Usage

The package ships with a CLI entry point and a small programmable API that calls
the CLI under the hood.

CLI usage:

```bash
npx reauthfi --help
```

Programmatic example:

```ts
import { run } from "reauthfi";

await run(["--no-open", "--verbose"]);
```

On unsupported platforms (non-macOS or non-arm64) the module throws an
`Unsupported platform` error before attempting to spawn the binary.

## License

MIT License.
