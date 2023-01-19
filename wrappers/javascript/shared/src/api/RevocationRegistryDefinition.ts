import type { CredentialDefinition } from './CredentialDefinition'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { RevocationRegistry } from './RevocationRegistry'
import { RevocationRegistryDefinitionPrivate } from './RevocationRegistryDefinitionPrivate'
import { RevocationRegistryDelta } from './RevocationRegistryDelta'

export type CreateRevocationRegistryDefinitionOptions = {
  originDid: string
  credentialDefinition: CredentialDefinition
  credentialDefinitionId: string
  tag: string
  revocationRegistryType: string
  issuanceType?: string
  maximumCredentialNumber: number
  tailsDirectoryPath?: string
}

export class RevocationRegistryDefinition extends AnoncredsObject {
  public static create(options: CreateRevocationRegistryDefinitionOptions) {
    const { registryDefinition, registryDefinitionPrivate, registryEntry, registryInitDelta } =
      anoncreds.createRevocationRegistry({
        credentialDefinition: options.credentialDefinition.handle,
        credentialDefinitionId: options.credentialDefinitionId,
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
    anoncreds.credentialFromJson({ json })
  }

  public getId() {
    return anoncreds.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'id' })
  }

  public getMaximumCredentialNumber() {
    return Number(
      anoncreds.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'max_cred_num' })
    )
  }

  public getTailsHash() {
    return anoncreds.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'tails_hash' })
  }

  public getTailsLocation() {
    return anoncreds.revocationRegistryDefinitionGetAttribute({ objectHandle: this.handle, name: 'tails_location' })
  }
}
