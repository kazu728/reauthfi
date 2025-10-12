# reauthfi (Node.js)

Node.js bindings for the macOS captive portal detector. This package exposes the
same detection logic used by the CLI through a simple JavaScript interface.

![Demo](https://raw.githubusercontent.com/kazu728/reauthfi/main/assets/demo.gif)

## Installation

```bash
npm install reauthfi
# or
yarn add reauthfi
```

Homebrew users can install the CLI companion:

```bash
brew install kazu728/tap/reauthfi
```

> **Supported platforms:** macOS (arm64). The bundled N-API binary targets
> `aarch64-apple-darwin`.

## Usage

The package ships with a CLI entry point and a programmable API.

CLI usage:

```bash
npx reauthfi --help
```

Programmatic example:

```ts
import { run } from "reauthfi";

await run(["--no-open", "--verbose"]);
```

On unsupported platforms the module throws an `Unsupported platform` error.

## License

MIT License.
