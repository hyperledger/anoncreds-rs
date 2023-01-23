import type { CredentialDefinition } from './CredentialDefinition'
import type { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import type { CredentialOffer } from './CredentialOffer'
import type { CredentialRequest } from './CredentialRequest'
import type { CredentialRequestMetadata } from './CredentialRequestMetadata'
import type { CredentialRevocationConfig } from './CredentialRevocationConfig'
import type { MasterSecret } from './MasterSecret'
import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateCredentialOptions = {
  credentialDefinition: CredentialDefinition
  credentialDefinitionPrivate: CredentialDefinitionPrivate
  credentialOffer: CredentialOffer
  credentialRequest: CredentialRequest
  attributeRawValues: Record<string, string>
  attributeEncodedValues?: Record<string, string>
  revocationRegistryId?: string
  revocationConfiguration?: CredentialRevocationConfig
}

export type ProcessCredentialOptions = {
  credentialRequestMetadata: CredentialRequestMetadata
  masterSecret: MasterSecret
  credentialDefinition: CredentialDefinition
  revocationRegistryDefinition?: RevocationRegistryDefinition
}

export class Credential extends AnoncredsObject {
  public static create(options: CreateCredentialOptions) {
    const credential = anoncreds.createCredential({
      credentialDefinition: options.credentialDefinition.handle,
      credentialDefinitionPrivate: options.credentialDefinitionPrivate.handle,
      credentialOffer: options.credentialOffer.handle,
      credentialRequest: options.credentialRequest.handle,
      attributeRawValues: options.attributeRawValues,
      attributeEncodedValues: options.attributeEncodedValues,
      revocationRegistryId: options.revocationRegistryId,
      revocationConfiguration: options.revocationConfiguration?.native,
    })

    return new Credential(credential.handle)
  }

  public static load(json: string) {
    return new Credential(anoncreds.credentialFromJson({ json }).handle)
  }

  public process(options: ProcessCredentialOptions) {
    const credential = anoncreds.processCredential({
      credential: this.handle,
      credentialDefinition: options.credentialDefinition.handle,
      credentialRequestMetadata: options.credentialRequestMetadata.handle,
      masterSecret: options.masterSecret.handle,
      revocationRegistryDefinition: options.revocationRegistryDefinition?.handle,
    })

    return new Credential(credential.handle)
  }

  public get schemaId() {
    return anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'schema_id' })
  }

  public get credentialDefinitionId() {
    return anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'cred_def_id' })
  }

  public get revocationRegistryId() {
    return anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'rev_reg_id' })
  }

  public get revocationRegistryIndex() {
    const index = anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'rev_reg_index' })
    return index ? Number(index) : undefined
  }
}
