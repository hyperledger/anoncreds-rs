#pragma once

#include <jsi/jsi.h>

#include "include/libanoncreds.h"
#include "turboModuleUtility.h"

using namespace facebook;

namespace anoncreds {

struct CredentialDefinitionReturn {
  ObjectHandle credentialDefinition;
  ObjectHandle credentialDefinitionPrivate;
  ObjectHandle keyCorrectnessProof;
};

struct CredentialRequestReturn {
  ObjectHandle credentialRequest;
  ObjectHandle credentialRequestMetadata;
};

struct W3cCredentialRequestReturn {
  ObjectHandle credentialRequest;
  ObjectHandle credentialRequestMetadata;
};

struct RevocationRegistryDefinitionReturn {
  ObjectHandle revocationRegistryDefinition;
  ObjectHandle revocationRegistryDefinitionPrivate;
};

// General
jsi::Value version(jsi::Runtime &rt, jsi::Object options);
jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options);
jsi::Value getJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value getTypeName(jsi::Runtime &rt, jsi::Object options);
jsi::Value setDefaultLogger(jsi::Runtime &rt, jsi::Object options);
jsi::Value objectFree(jsi::Runtime &rt, jsi::Object options);

// Meta
jsi::Value createLinkSecret(jsi::Runtime &rt, jsi::Object options);
jsi::Value generateNonce(jsi::Runtime &rt, jsi::Object options);

// Anoncreds Objects
jsi::Value createSchema(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialDefinition(jsi::Runtime &rt, jsi::Object options);

// Anoncreds Objects from JSON
jsi::Value revocationRegistryDefinitionFromJson(jsi::Runtime &rt,
                                                jsi::Object options);
jsi::Value revocationRegistryFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value revocationStatusListFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value presentationFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value presentationRequestFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialOfferFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value schemaFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialRequestFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialRequestMetadataFromJson(jsi::Runtime &rt,
                                             jsi::Object options);
jsi::Value credentialFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value revocationRegistryDefinitionPrivateFromJson(jsi::Runtime &rt,
                                                       jsi::Object options);
jsi::Value revocationStateFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialDefinitionFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialDefinitionPrivateFromJson(jsi::Runtime &rt,
                                               jsi::Object options);
jsi::Value keyCorrectnessProofFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialOfferFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialRequestFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialFromJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cPresentationFromJson(jsi::Runtime &rt, jsi::Object options);

// Proofs
jsi::Value createPresentation(jsi::Runtime &rt, jsi::Object options);
jsi::Value verifyPresentation(jsi::Runtime &rt, jsi::Object options);
jsi::Value createW3cPresentation(jsi::Runtime &rt, jsi::Object options);
jsi::Value verifyW3cPresentation(jsi::Runtime &rt, jsi::Object options);

// Credentials
jsi::Value createCredential(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialOffer(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialRequest(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialGetAttribute(jsi::Runtime &rt, jsi::Object options);
jsi::Value encodeCredentialAttributes(jsi::Runtime &rt, jsi::Object options);
jsi::Value processCredential(jsi::Runtime &rt, jsi::Object options);

jsi::Value createW3cCredential(jsi::Runtime &rt, jsi::Object options);
jsi::Value createW3cCredentialOffer(jsi::Runtime &rt, jsi::Object options);
jsi::Value createW3cCredentialRequest(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialGetAttribute(jsi::Runtime &rt, jsi::Object options);
jsi::Value processW3cCredential(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialAddNonAnonCredsIntegrityProof(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialSetId(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialSetSubjectId(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialAddContext(jsi::Runtime &rt, jsi::Object options);
jsi::Value w3cCredentialAddType(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialToW3c(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialFromW3c(jsi::Runtime &rt, jsi::Object options);

// Revocation
jsi::Value createOrUpdateRevocationState(jsi::Runtime &rt, jsi::Object options);
jsi::Value createRevocationStatusList(jsi::Runtime &rt, jsi::Object options);
jsi::Value updateRevocationStatusList(jsi::Runtime &rt, jsi::Object options);
jsi::Value updateRevocationStatusListTimestampOnly(jsi::Runtime &rt,
                                                   jsi::Object options);
jsi::Value createRevocationRegistryDefinition(jsi::Runtime &rt,
                                              jsi::Object options);
jsi::Value revocationRegistryDefinitionGetAttribute(jsi::Runtime &rt,
                                                    jsi::Object options);

} // namespace anoncreds
