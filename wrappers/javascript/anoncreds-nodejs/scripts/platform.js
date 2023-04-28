/* eslint-disable @typescript-eslint/no-var-requires */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable no-undef */
const os = require('os')

// Find appropriate target architecture for retrieving the anoncreds library
const platform = os.platform()

// We swap win32 with windows as that is the key that we use
const targetPlatform = platform == 'win32' ? 'windows' : platform

console.log(targetPlatform)
