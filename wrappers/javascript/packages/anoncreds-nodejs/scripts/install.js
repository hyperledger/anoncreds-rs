const { execSync } = require('node:child_process')
const { arch, platform } = require('os')

const archTable = {
  x64: 'x86_64',
  arm64: 'aarch64'
}

const targetPlatform = platform === 'win32' ? 'windows' : platform
const targetArchitecture = archTable[arch()]

const command = `node-pre-gyp install --target_arch=${targetArchitecture} --target_platform=${targetPlatform}`

execSync(command)
