const os = require('os')

// Find appropriate target architecture settings for retrieving anoncreds binaries
const platform = os.platform()
const arch = os.arch()

const archTable = {
  x64: 'x86_64',
  arm64: 'aarch64',
}

const targetArchitecture = platform === 'darwin' ? 'universal' : archTable[arch]

if (targetArchitecture) {
  console.log(targetArchitecture)
}
