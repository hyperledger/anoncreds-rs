import type { NativeCredentialRevocationConfig } from '../Anoncreds'
import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { RevocationRegistryDefinitionPrivate } from './RevocationRegistryDefinitionPrivate'

export type CredentialRevocationConfigOptions = {
  registryDefinition: RevocationRegistryDefinition
  registryDefinitionPrivate: RevocationRegistryDefinitionPrivate
  registryIndex: number
  tailsPath: string
}

export class CredentialRevocationConfig {
  private registryDefinition: RevocationRegistryDefinition
  private registryDefinitionPrivate: RevocationRegistryDefinitionPrivate
  private registryIndex: number
  private tailsPath: string

  public constructor(options: CredentialRevocationConfigOptions) {
    this.registryDefinition = options.registryDefinition
    this.registryDefinitionPrivate = options.registryDefinitionPrivate
    this.registryIndex = options.registryIndex
    this.tailsPath = options.tailsPath
  }

  public clear() {
    this.registryDefinition.handle.clear()
    this.registryDefinitionPrivate.handle.clear()
  }

  public get native(): NativeCredentialRevocationConfig {
    return {
      revocationRegistryDefinition: this.registryDefinition.handle,
      revocationRegistryDefinitionPrivate: this.registryDefinitionPrivate.handle,
      registryIndex: this.registryIndex,
      tailsPath: this.tailsPath,
    }
  }
}
