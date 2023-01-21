import type { CredentialDefinition } from './CredentialDefinition'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { RevocationRegistryDefinitionPrivate } from './RevocationRegistryDefinitionPrivate'

export type CreateRevocationRegistryDefinitionOptions = {
  originDid: string
  credentialDefinition: CredentialDefinition
  credentialDefinitionId: string
  tag: string
  issuerId: string
  revocationRegistryType: string
  maximumCredentialNumber: number
  tailsDirectoryPath?: string
}

export class RevocationRegistryDefinition extends AnoncredsObject {
  public static create(options: CreateRevocationRegistryDefinitionOptions) {
    const { registryDefinition, registryDefinitionPrivate } = anoncreds.createRevocationRegistry({
      ...options,
      credentialDefinition: options.credentialDefinition.handle,
    })

    return {
      revocationRegistryDefinition: new RevocationRegistryDefinition(registryDefinition.handle),
      revocationRegistryDefinitionPrivate: new RevocationRegistryDefinitionPrivate(registryDefinitionPrivate.handle),
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
