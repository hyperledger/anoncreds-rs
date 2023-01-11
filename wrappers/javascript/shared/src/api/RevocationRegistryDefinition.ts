import type { CredentialDefinition } from './CredentialDefinition'

import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

import { RevocationRegistry } from './RevocationRegistry'
import { RevocationRegistryDefinitionPrivate } from './RevocationRegistryDefinitionPrivate'
import { RevocationRegistryDelta } from './RevocationRegistryDelta'

export type CreateRevocationRegistryDefinitionOptions = {
  originDid: string
  credentialDefinition: CredentialDefinition
  tag: string
  revocationRegistryType: string
  issuanceType?: string
  maximumCredentialNumber: number
  tailsDirectoryPath?: string
}

export class RevocationRegistryDefinition extends IndyObject {
  public static create(options: CreateRevocationRegistryDefinitionOptions) {
    const { registryDefinition, registryDefinitionPrivate, registryEntry, registryInitDelta } =
      indyCredx.createRevocationRegistry({
        originDid: options.originDid,
        credentialDefinition: options.credentialDefinition.handle,
        tag: options.tag,
        revocationRegistryType: options.revocationRegistryType,
        issuanceType: options.issuanceType,
        maximumCredentialNumber: options.maximumCredentialNumber,
        tailsDirectoryPath: options.tailsDirectoryPath,
      })

    return {
      revocationRegistryDefinition: new RevocationRegistryDefinition(registryDefinition.handle),
      revocationRegistryDefinitionPrivate: new RevocationRegistryDefinitionPrivate(registryDefinitionPrivate.handle),
      revocationRegistry: new RevocationRegistry(registryEntry.handle),
      revocationRegistryDelta: new RevocationRegistryDelta(registryInitDelta.handle),
    }
  }

  public static load(json: string) {
    indyCredx.credentialFromJson({ json })
  }

  public getId() {
    return indyCredx.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'id' })
  }

  public getMaximumCredentialNumber() {
    return Number(
      indyCredx.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'max_cred_num' })
    )
  }

  public getTailsHash() {
    return indyCredx.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'tails_hash' })
  }

  public getTailsLocation() {
    return indyCredx.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'tails_location' })
  }
}
