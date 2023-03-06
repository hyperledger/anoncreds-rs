#include <anoncreds.h>

#include <include/libanoncreds.h>

using namespace anoncredsTurboModuleUtility;

namespace anoncreds {

// ===== GENERAL =====

jsi::Value version(jsi::Runtime &rt, jsi::Object options) {
  return jsi::String::createFromAscii(rt, anoncreds_version());
};

jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options) {
  const char *errorJsonP;

  anoncreds_get_current_error(&errorJsonP);

  return jsi::String::createFromAscii(rt, errorJsonP);
};

jsi::Value getJson(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  ByteBuffer resultP;

  ErrorCode code = anoncreds_object_get_json(handle, &resultP);
  handleError(rt, code);

  return jsi::String::createFromUtf8(rt, resultP.data, resultP.len);
};

jsi::Value getTypeName(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  const char *resultP;

  ErrorCode code = anoncreds_object_get_type_name(handle, &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value setDefaultLogger(jsi::Runtime &rt, jsi::Object options) {
  anoncreds_set_default_logger();
  return jsi::Value::null();
};

jsi::Value objectFree(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  anoncreds_object_free(handle);

  return jsi::Value::null();
};

// ===== META =====

jsi::Value createMasterSecret(jsi::Runtime &rt, jsi::Object options) {
  ObjectHandle masterSecretP;

  ErrorCode code = anoncreds_create_master_secret(&masterSecretP);
  handleError(rt, code);

  return jsi::Value(int(masterSecretP));
};

jsi::Value generateNonce(jsi::Runtime &rt, jsi::Object options) {
  const char *nonceP;

  ErrorCode code = anoncreds_generate_nonce(&nonceP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, nonceP);
};

// ===== Anoncreds Objects =====

jsi::Value createSchema(jsi::Runtime &rt, jsi::Object options) {
  auto name = jsiToValue<std::string>(rt, options, "name");
  auto version = jsiToValue<std::string>(rt, options, "version");
  auto issuerId = jsiToValue<std::string>(rt, options, "issuerId");
  auto attributeNames = jsiToValue<FfiStrList>(rt, options, "attributeNames");

  ObjectHandle resultP;

  ErrorCode code =
      anoncreds_create_schema(name.c_str(), version.c_str(), issuerId.c_str(),
                              attributeNames, &resultP);
  handleError(rt, code);

  return jsi::Value(int(resultP));
};

jsi::Value createCredentialDefinition(jsi::Runtime &rt, jsi::Object options) {
  auto schemaId = jsiToValue<std::string>(rt, options, "schemaId");
  auto schema = jsiToValue<ObjectHandle>(rt, options, "schema");
  auto tag = jsiToValue<std::string>(rt, options, "tag");
  auto issuerId = jsiToValue<std::string>(rt, options, "issuerId");
  auto signatureType = jsiToValue<std::string>(rt, options, "signatureType");
  auto supportRevocation = jsiToValue<int8_t>(rt, options, "supportRevocation");

  ObjectHandle credentialDefinitionP;
  ObjectHandle credentialDefinitionPrivateP;
  ObjectHandle keyCorrectnessProofP;

  ErrorCode code = anoncreds_create_credential_definition(
      schemaId.c_str(), schema, tag.c_str(), issuerId.c_str(),
      signatureType.c_str(), supportRevocation, &credentialDefinitionP,
      &credentialDefinitionPrivateP, &keyCorrectnessProofP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "credentialDefinition", int(credentialDefinitionP));
  object.setProperty(rt, "credentialDefinitionPrivate",
                     int(credentialDefinitionPrivateP));
  object.setProperty(rt, "keyCorrectnessProof", int(keyCorrectnessProofP));
  return object;
};

// ===== PROOFS =====

jsi::Value createPresentation(jsi::Runtime &rt, jsi::Object options) {
  auto presentationRequest =
      jsiToValue<ObjectHandle>(rt, options, "presentationRequest");
  auto credentials =
      jsiToValue<FfiList_FfiCredentialEntry>(rt, options, "credentials");
  auto credentialsProve =
      jsiToValue<FfiList_FfiCredentialProve>(rt, options, "credentialsProve");
  auto selfAttestedNames =
      jsiToValue<FfiStrList>(rt, options, "selfAttestedNames");
  auto selfAttestedValues =
      jsiToValue<FfiStrList>(rt, options, "selfAttestedValues");
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSercet");
  auto schemas = jsiToValue<FfiList_ObjectHandle>(rt, options, "schemas");
  auto schemaIds = jsiToValue<FfiList_FfiStr>(rt, options, "schemaIds");
  auto credentialDefinitions =
      jsiToValue<FfiList_ObjectHandle>(rt, options, "credentialDefinitions");
  auto credentialDefinitionids =
      jsiToValue<FfiList_FfiStr>(rt, options, "credentialDefinitionIds");

  ObjectHandle presentationP;

  ErrorCode code = anoncreds_create_presentation(
      presentationRequest, credentials, credentialsProve, selfAttestedNames,
      selfAttestedValues, masterSecret, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionids, &presentationP);
  handleError(rt, code);

  return jsi::Value(int(presentationP));
};

jsi::Value verifyPresentation(jsi::Runtime &rt, jsi::Object options) {
  auto presentation = jsiToValue<ObjectHandle>(rt, options, "presentation");
  auto presentationRequest =
      jsiToValue<ObjectHandle>(rt, options, "presentationRequest");
  auto schemas = jsiToValue<FfiList_ObjectHandle>(rt, options, "schemas");
  auto schemaIds = jsiToValue<FfiList_FfiStr>(rt, options, "schemaIds");
  auto credentialDefinitions =
      jsiToValue<FfiList_ObjectHandle>(rt, options, "credentialDefinitions");
  auto credentialDefinitionIds =
      jsiToValue<FfiList_FfiStr>(rt, options, "credentialDefinitionIds");
  auto revocationRegistryDefinitions = jsiToValue<FfiList_ObjectHandle>(
      rt, options, "revocationRegistryDefinitions");
  auto revocationRegistryDefinitionIds = jsiToValue<FfiList_FfiStr>(
      rt, options, "revocationRegistryDefinitionIds");
  auto revocationStatusLists =
      jsiToValue<FfiList_ObjectHandle>(rt, options, "revocationStatusLists");

  int8_t resultP;

  ErrorCode code = anoncreds_verify_presentation(
      presentation, presentationRequest, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionIds,
      revocationRegistryDefinitions, revocationRegistryDefinitionIds,
      revocationStatusLists, &resultP);
  handleError(rt, code);

  return jsi::Value(int(resultP));
};

// ===== CREDENTIALS =====

jsi::Value createCredential(jsi::Runtime &rt, jsi::Object options) {
  auto credentialDefinition =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinition");
  auto credentialDefinitionPrivate =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinitionPrivate");
  auto credentialOffer =
      jsiToValue<ObjectHandle>(rt, options, "credentialOffer");
  auto credentialRequest =
      jsiToValue<ObjectHandle>(rt, options, "credentialRequest");
  auto attributeNames = jsiToValue<FfiStrList>(rt, options, "attributeNames");
  auto attributeRawValues =
      jsiToValue<FfiStrList>(rt, options, "attributeRawValues");
  auto attributeEncodedValues =
      jsiToValue<FfiStrList>(rt, options, "attributeEncodedValues");
  auto revocationRegistryId =
      jsiToValue<std::string>(rt, options, "revocationRegistryId");
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList");
  auto revocation = jsiToValue<FfiCredRevInfo>(rt, options, "revocation");

  ObjectHandle credP;

  ErrorCode code = anoncreds_create_credential(
      credentialDefinition, credentialDefinitionPrivate, credentialOffer,
      credentialRequest, attributeNames, attributeRawValues,
      attributeEncodedValues, revocationRegistryId.c_str(),
      revocationStatusList, &revocation, &credP);
  handleError(rt, code);

  return jsi::Value(int(credP));
};

jsi::Value createCredentialOffer(jsi::Runtime &rt, jsi::Object options) {
  auto schemaId = jsiToValue<std::string>(rt, options, "schemaId");
  auto credentialDefinitionId =
      jsiToValue<std::string>(rt, options, "credentialDefinitionId");
  auto keyCorrectnessProof = jsiToValue<ObjectHandle>(rt, options, "keyCorrectnessProof");

  ObjectHandle credOfferP;

  ErrorCode code = anoncreds_create_credential_offer(
      schemaId.c_str(), credentialDefinitionId.c_str(), keyCorrectnessProof, &credOfferP);
  handleError(rt, code);

  return jsi::Value(int(credOfferP));
};

jsi::Value createCredentialRequest(jsi::Runtime &rt, jsi::Object options) {
  auto entropy = jsiToValue<std::string>(rt, options, "entropy", true);
  auto proverDid = jsiToValue<std::string>(rt, options, "proverDid", true);
  auto credentialDefinition =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinition");
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSecret");
  auto masterSecretId = jsiToValue<std::string>(rt, options, "masterSecretId");
  auto credentialOffer =
      jsiToValue<ObjectHandle>(rt, options, "credentialOffer");

  ObjectHandle credReqP;
  ObjectHandle credReqMetaP;

  ErrorCode code = anoncreds_create_credential_request(
      entropy.c_str(), prover_did.c_str(), credentialDefinition, masterSecret,
      masterSecretId.c_str(), credentialOffer, &credReqP, &credReqMetaP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "credReq", int(credReqP));
  object.setProperty(rt, "credReqMeta", int(credReqMetaP));
  return object;
};

jsi::Value credentialGetAttribute(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *resultP;

  ErrorCode code =
      anoncreds_credential_get_attribute(handle, name.c_str(), &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value encodeCredentialAttributes(jsi::Runtime &rt, jsi::Object options) {
  auto attributeRawValues =
      jsiToValue<FfiList_FfiStr>(rt, options, "attributeRawValues");

  const char *resultP;

  ErrorCode code =
      anoncreds_encode_credential_attributes(attributeRawValues, &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value processCredential(jsi::Runtime &rt, jsi::Object options) {
  auto credential = jsiToValue<ObjectHandle>(rt, options, "credential");
  auto credentialRequestMetadata =
      jsiToValue<ObjectHandle>(rt, options, "credentialRequestMetadata");
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSercet");
  auto credentialDefinition =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinition");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");

  ObjectHandle credentialP;

  ErrorCode code = anoncreds_process_credential(
      credential, credentialRequestMetadata, masterSecret, credentialDefinition,
      revocationRegistryDefinition, &credentialP);
  handleError(rt, code);

  return jsi::Value(int(credentialP));
};

// ===== REVOCATION =====

jsi::Value createOrUpdateRevocationState(jsi::Runtime &rt,
                                         jsi::Object options) {
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList");
  auto revocationRegistryIndex =
      jsiToValue<int64_t>(rt, options, "revocationRegistryIndex");
  auto tailsPath = jsiToValue<std::string>(rt, options, "tailsPath");
  auto revocationState =
      jsiToValue<ObjectHandle>(rt, options, "revocationState");
  auto oldRevocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "oldRevocationStatusList");

  ObjectHandle revocationStateP;

  ErrorCode code = anoncreds_create_or_update_revocation_state(
      revocationRegistryDefinition, revocationStatusList,
      revocationRegistryIndex, tailsPath.c_str(), revocationState,
      oldRevocationStatusList, &revocationStateP);
  handleError(rt, code);

  return jsi::Value(int(revocationStateP));
};

jsi::Value createRevocationStatusList(jsi::Runtime &rt, jsi::Object options) {
  auto revocationRegistryDefinitionId =
      jsiToValue<std::string>(rt, options, "revocationRegistryDefinitionId");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto issuanceByDefault = jsiToValue<int8_t>(rt, options, "issuanceByDefault");

  ObjectHandle revocationStatusListP;

  ErrorCode code = anoncreds_create_revocation_status_list(
      revocationRegistryDefinitionId.c_str(), revocationRegistryDefinition,
      timestamp, issuanceByDefault, &revocationStatusListP);
  handleError(rt, code);

  return jsi::Value(int(revocationStatusListP));
}

jsi::Value updateRevocationStatusList(jsi::Runtime &rt, jsi::Object options) {
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto issued = jsiToValue<FfiList_i32>(rt, options, "issued");
  auto revoked = jsiToValue<FfiList_i32>(rt, options, "revoked");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList");

  ObjectHandle newRevocationStatusListP;

  ErrorCode code = anoncreds_update_revocation_status_list(
      timestamp, issued, revoked, revocationRegistryDefinition,
      revocationStatusList, &newRevocationStatusListP);
  handleError(rt, code);

  return jsi::Value(int(newRevocationStatusListP));
}

jsi::Value updateRevocationStatusListTimestampOnly(jsi::Runtime &rt,
                                                   jsi::Object options) {
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList");

  ObjectHandle newRevocationStatusListP;

  ErrorCode code = anoncreds_update_revocation_status_list_timestamp_only(
      timestamp, revocationStatusList, &newRevocationStatusListP);
  handleError(rt, code);

  return jsi::Value(int(newRevocationStatusListP));
}

jsi::Value createRevocationRegistryDefinition(jsi::Runtime &rt,
                                              jsi::Object options) {
  auto credentialDefinition =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinition");
  auto credentialDefinitionId =
      jsiToValue<std::string>(rt, options, "credentialDefinitionId");
  auto issuerId = jsiToValue<std::string>(rt, options, "issuerId");
  auto tag = jsiToValue<std::string>(rt, options, "tag");
  auto revocationRegistryType =
      jsiToValue<std::string>(rt, options, "revocationRegistryType");
  auto maxCredNum = jsiToValue<int64_t>(rt, options, "maxCredNum");
  auto tailsDirPath = jsiToValue<std::string>(rt, options, "tailsDirPath");

  ObjectHandle regDefP;
  ObjectHandle regDefPrivateP;

  ErrorCode code = anoncreds_create_revocation_registry_def(
      credentialDefinition, credentialDefinitionId.c_str(), issuerId.c_str(),
      tag.c_str(), revocationRegistryType.c_str(), maxCredNum,
      tailsDirPath.c_str(), &regDefP, &regDefPrivateP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "regDef", int(regDefP));
  object.setProperty(rt, "regDefPrivate", int(regDefPrivateP));
  return object;
};

jsi::Value revocationRegistryDefinitionGetAttribute(jsi::Runtime &rt,
                                                    jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *resultP;

  ErrorCode code = anoncreds_revocation_registry_definition_get_attribute(
      handle, name.c_str(), &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

} // namespace anoncreds
