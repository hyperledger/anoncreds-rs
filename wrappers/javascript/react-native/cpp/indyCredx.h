#pragma once

#include <include/libindy_credx.h>
#include <jsi/jsi.h>
#include <turboModuleUtility.h>

using namespace facebook;

namespace indyCredx {

jsi::Value version(jsi::Runtime &rt, jsi::Object options);
jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options);

jsi::Value createCredential(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialDefinition(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialOffer(jsi::Runtime &rt, jsi::Object options);
jsi::Value createCredentialRequest(jsi::Runtime &rt, jsi::Object options);
jsi::Value createMasterSecret(jsi::Runtime &rt, jsi::Object options);
jsi::Value createOrUpdateRevocationState(jsi::Runtime &rt, jsi::Object options);
jsi::Value createPresentation(jsi::Runtime &rt, jsi::Object options);
jsi::Value createRevocationRegistry(jsi::Runtime &rt, jsi::Object options);
jsi::Value createSchema(jsi::Runtime &rt, jsi::Object options);

jsi::Value credentialDefinitionGetAttribute(jsi::Runtime &rt,
                                            jsi::Object options);
jsi::Value credentialGetAttribute(jsi::Runtime &rt, jsi::Object options);
jsi::Value encodeCredentialAttributes(jsi::Runtime &rt, jsi::Object options);
jsi::Value generateNonce(jsi::Runtime &rt, jsi::Object options);
jsi::Value mergeRevocationRegistryDeltas(jsi::Runtime &rt, jsi::Object options);
jsi::Value getJson(jsi::Runtime &rt, jsi::Object options);
jsi::Value getTypeName(jsi::Runtime &rt, jsi::Object options);
jsi::Value processCredential(jsi::Runtime &rt, jsi::Object options);
jsi::Value revocationRegistryDefinitionGetAttribute(jsi::Runtime &rt,
                                                    jsi::Object options);
jsi::Value revokeCredential(jsi::Runtime &rt, jsi::Object options);
jsi::Value schemaGetAttribute(jsi::Runtime &rt, jsi::Object options);
jsi::Value setDefaultLogger(jsi::Runtime &rt, jsi::Object options);
jsi::Value verifyPresentation(jsi::Runtime &rt, jsi::Object options);
jsi::Value updateRevocationRegistry(jsi::Runtime &rt, jsi::Object options);
jsi::Value objectFree(jsi::Runtime &rt, jsi::Object options);

} // namespace indyCredx
