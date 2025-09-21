# reauthfi

Captive portal detector and browser opener for macOS.

`reauthfi` detects Wi‑Fi captive portals and opens the login page in your default browser.

![Demo](./assets/demo.gif)

## Installation

### Homebrew

```bash
brew install kazu728/tap/reauthfi
```

### Cargo

Install from crates.io:

```bash
cargo install reauthfi
```

Supported platforms:

- macOS (Apple/Google endpoints)

## Usage

Basic:

```bash
reauthfi
```

Options:

```bash
--verbose        Show detailed detection logs
--no-open        Print portal URL only (do not open browser)
--gateway        Prioritize gateway-first detection
--timeout <sec>  Request timeout in seconds (default: 10)
```

Expected output:

```text
🔍 Detecting Captive Portal...
  → Portal URL: https://portal.example.com/login
📱 Opening in browser...
✅ Done!
```

## License

MIT License
