import type { NativeBindings } from './NativeBindings'

import { NativeModules, Platform } from 'react-native'

declare global {
  const _anoncreds: NativeBindings
}

export const register = (): NativeBindings => {
  const libraryName = 'anoncreds'

  let doesAnoncredsExist = false
  try {
    doesAnoncredsExist = Boolean(_anoncreds)
  } catch (e) {
    doesAnoncredsExist = false
  }

  // Check if the constructor exists. If not, try installing the JSI bindings.
  if (!doesAnoncredsExist) {
    const anoncredsModule = NativeModules.Anoncreds as { install: () => boolean } | null

    if (anoncredsModule == null) {
      let message = `Failed to create a new ${libraryName}' instance: The native ${libraryName} Module could not be found.'
      message += '\n* Make sure is correctly autolinked.`

      if (Platform.OS === 'ios' || Platform.OS === 'macos') {
        message += '\n* Make sure you ran `pod install` in the ios/ directory.'
      }

      if (Platform.OS === 'android') {
        message += '\n* Make sure gradle is synced.'
      }

      // check if Expo

      const ExpoConstants = NativeModules.NativeUnimoduleProxy?.modulesConstants?.ExponentConstants
      if (ExpoConstants != null) {
        if (ExpoConstants.appOwnership === 'expo') {
          // We're running Expo Go
          throw new Error(
            `@hyperledger/${libraryName}-react-native is not supported in Expo Go! Use EAS ('expo prebuild') or eject to a bare workflow instead.`
          )
        } else {
          message += '\n* Make sure you ran `expo prebuild`.'
        }
      }

      message += '\n* Make sure you rebuilt the app.'
      throw new Error(message)
    }

    // Check if we are running on-device (JSI)
    if (anoncredsModule.install == null) {
      throw new Error(
        `Failed to create a new ${libraryName} instance: React Native is not running on-device. ${libraryName} can only be used when synchronous method invocations (JSI) are possible. If you are using a remote debugger (e.g. Chrome), switch to an on-device debugger (e.g. Flipper) instead.`
      )
    }

    // Call the synchronous blocking install() function
    const result = anoncredsModule.install()
    if (!result)
      throw new Error(
        `Failed to create a new ${libraryName} instance: The native ${libraryName} Module could not be installed! Looks like something went wrong when installing JSI bindings.`
      )

    // Check again if the constructor now exists. If not, throw an error.
    if (_anoncreds == null)
      throw new Error(
        `Failed to create a new ${libraryName} instance, the native initializer function does not exist. Are you trying to use ${libraryName} from different JS Runtimes?`
      )
  }

  return _anoncreds
}
