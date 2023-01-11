import type { NativeCredentialRevocationConfig } from '../IndyCredx'
import type { RevocationRegistry } from './RevocationRegistry'
import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { RevocationRegistryDefinitionPrivate } from './RevocationRegistryDefinitionPrivate'

export type CredentialRevocationConfigOptions = {
  registryDefinition: RevocationRegistryDefinition
  registryDefinitionPrivate: RevocationRegistryDefinitionPrivate
  registry: RevocationRegistry
  registryIndex: number
  registryUsed?: number[] | undefined
  tailsPath: string
}

export class CredentialRevocationConfig {
  private registryDefinition: RevocationRegistryDefinition
  private registryDefinitionPrivate: RevocationRegistryDefinitionPrivate
  private registry: RevocationRegistry
  private registryIndex: number
  private registryUsed?: number[]
  private tailsPath: string

  public constructor(options: CredentialRevocationConfigOptions) {
    this.registryDefinition = options.registryDefinition
    this.registryDefinitionPrivate = options.registryDefinitionPrivate
    this.registry = options.registry
    this.registryIndex = options.registryIndex
    this.registryUsed = options.registryUsed
    this.tailsPath = options.tailsPath
  }

  public get native(): NativeCredentialRevocationConfig {
    return {
      registry: this.registry.handle,
      registryDefinition: this.registryDefinition.handle,
      registryDefinitionPrivate: this.registryDefinitionPrivate.handle,
      registryIndex: this.registryIndex,
      registryUsed: this.registryUsed,
      tailsPath: this.tailsPath,
    }
  }
}
