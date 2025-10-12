# reauthfi-core

Core library for the `reauthfi` captive portal detector.

## Overview

`reauthfi-core` contains the detection logic shared by the CLI and Node.js bindings.
It probes known endpoints, inspects gateway responses, and opens the detected portal
URL on supported platforms (currently macOS).

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
reauthfi-core = "0.1.2"
```

Basic example:

```rust
use reauthfi_core::{run, ExecutionStatus, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options {
        verbose: true,
        no_open: true,
        gateway: false,
        timeout: 10,
    };

    match run(&options) {
        Ok(ExecutionStatus::Completed) => println!("No captive portal detected"),
        Ok(ExecutionStatus::NetworkNotReady) => println!("Network not ready"),
        Err(err) => eprintln!("Detection failed: {err}"),
    }

    Ok(())
}
```

On non-macOS platforms the library currently returns `ReauthfiError::UnsupportedPlatform`.

## License

MIT License.
