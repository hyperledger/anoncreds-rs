import type { NativeMethods } from './NativeBindingInterface'

import { Library } from '@2060.io/ffi-napi'
import fs from 'fs'
import os from 'os'
import path from 'path'

import { nativeBindings } from './bindings'

const LIBNAME = 'anoncreds'
const ENV_VAR = 'LIB_ANONCREDS_PATH'

type Platform = 'darwin' | 'linux' | 'win32'

type ExtensionMap = Record<Platform, { prefix?: string; extension: string }>

const extensions: ExtensionMap = {
  darwin: { prefix: 'lib', extension: '.dylib' },
  linux: { prefix: 'lib', extension: '.so' },
  win32: { extension: '.dll' },
}

const libPaths: Record<Platform, Array<string>> = {
  darwin: ['/usr/local/lib/', '/usr/lib/', '/opt/homebrew/opt/'],
  linux: ['/usr/lib/', '/usr/local/lib/'],
  win32: ['c:\\windows\\system32\\'],
}

// Alias for a simple function to check if the path exists
const doesPathExist = fs.existsSync

const getLibrary = () => {
  // Detect OS; darwin, linux and windows are only supported
  const platform = os.platform()

  if (platform !== 'linux' && platform !== 'win32' && platform !== 'darwin')
    throw new Error(`Unsupported platform: ${platform}. linux, win32 and darwin are supported.`)

  // Get a potential path from the environment variable
  const pathFromEnvironment = process.env[ENV_VAR]

  // Get the paths specific to the users operating system
  const platformPaths = libPaths[platform]

  // Look for the file in the native directory of the package.
  // node-pre-gyp will download the binaries to this directory after installing the package
  platformPaths.unshift(path.join(__dirname, '../../native'))

  // Check if the path from the environment variable is supplied and add it
  // We use unshift here so that when we want to get a valid library path this will be the first to resolve
  if (pathFromEnvironment) platformPaths.unshift(pathFromEnvironment)

  // Create the path + file
  const libaries = platformPaths.map((p) =>
    path.join(p, `${extensions[platform].prefix ?? ''}${LIBNAME}${extensions[platform].extension}`)
  )

  // Gaurd so we quit if there is no valid path for the library
  if (!libaries.some(doesPathExist))
    throw new Error(`Could not find ${LIBNAME} with these paths: ${libaries.join(' ')}`)

  // Get the first valid library
  // Casting here as a string because there is a guard of none of the paths
  const validLibraryPath = libaries.find((l) => doesPathExist(l)) as string

  // TODO
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  return Library(validLibraryPath, nativeBindings)
}

let nativeAnoncreds: NativeMethods | undefined = undefined
export const getNativeAnoncreds = () => {
  if (!nativeAnoncreds) nativeAnoncreds = getLibrary() as unknown as NativeMethods
  return nativeAnoncreds
}
