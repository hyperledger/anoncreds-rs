const os = require('os')

// Find appropriate target architecture for retrieving the anoncreds library
const arch = os.arch()

// Architecture mapping
// This is used because node-pre-gyp uses `os.arch()` for
// architecture detection, but our library uses a different
// naming convention
const archTable = {
  x64: 'x86_64',
  arm64: 'aarch64'
}

const targetArchitecture = archTable[arch]

if (targetArchitecture) {
  // We console.log here because when we use the `yarn install` script
  // er evaluate this script and use the output as an argument to
  // node-pre-gyp as `--arch=$(node -e arch.js)`
  console.log(targetArchitecture)
}
