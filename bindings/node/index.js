const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

function assertSupportedPlatform() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    throw new Error(`Unsupported platform: ${process.platform} ${process.arch} (macOS arm64 required)`);
  }
}

function resolveBinary() {
  if (process.env.REAUTHFI_BINARY && fs.existsSync(process.env.REAUTHFI_BINARY)) {
    return process.env.REAUTHFI_BINARY;
  }

  const bundled = path.join(__dirname, 'reauthfi');
  if (fs.existsSync(bundled)) {
    return bundled;
  }

  return 'reauthfi';
}

function run(args = []) {
  assertSupportedPlatform();

  return new Promise((resolve, reject) => {
    const child = spawn(resolveBinary(), args, {
      stdio: 'inherit',
    });

    child.on('error', (err) => reject(err));
    child.on('exit', (code, signal) => {
      if (code === 0) {
        resolve();
      } else if (signal) {
        reject(new Error(`reauthfi terminated by signal: ${signal}`));
      } else {
        reject(new Error(`reauthfi exited with code ${code}`));
      }
    });
  });
}

module.exports = { run };
