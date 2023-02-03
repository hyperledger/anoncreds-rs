#pragma once

#include <include/libanoncreds.h>
#include <jsi/jsi.h>
#include <turboModuleUtility.h>

using namespace facebook;

namespace anoncreds {

// General
jsi::Value version(jsi::Runtime &rt, jsi::Object options);
jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options);
jsi::Value getJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value getTypeName(jsi::Runtime &rt, jsi::Object options);
jsi::Value setDefaultLogger(jsi::Runtime &rt, jsi::Object options);
jsi::Value objectFree(jsi::Runtime &rt, jsi::Object options);

// Meta
jsi::Value createMasterSecret(jsi::Runtime &rt, jsi::Object options);
jsi::Value generateNonce(jsi::Runtime &rt, jsi::Object options);

// Anoncreds Objects
jsi::Value createSchema(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialDefinition(jsi::Runtime &rt, jsi::Object options);

// Proofs
jsi::Value createPresentation(jsi::Runtime &rt, jsi::Object options);
jsi::Value verifyPresentation(jsi::Runtime &rt, jsi::Object options);

// Credentials
jsi::Value createCredential(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialOffer(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialRequest(jsi::Runtime &rt, jsi::Object options);
jsi::Value credentialGetAttribute(jsi::Runtime &rt, jsi::Object options);
jsi::Value encodeCredentialAttributes(jsi::Runtime &rt, jsi::Object options);
jsi::Value processCredential(jsi::Runtime &rt, jsi::Object options);

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
