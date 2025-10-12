const { platform, arch } = process;

if (platform !== 'darwin' || arch !== 'arm64') {
  throw new Error('reauthfi npm package supports only macOS arm64 (Apple Silicon) environments.');
}

let nativeBinding;
try {
  nativeBinding = require('./reauthfi.darwin-arm64.node');
} catch (err) {
  throw new Error('Failed to load native binding. Reinstall the package or run `npm run build`.', { cause: err });
}

module.exports = nativeBinding;
module.exports.run = nativeBinding.run;
