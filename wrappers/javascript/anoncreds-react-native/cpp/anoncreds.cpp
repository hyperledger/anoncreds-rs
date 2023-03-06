#include <anoncreds.h>

#include <include/libanoncreds.h>

using namespace anoncredsTurboModuleUtility;

namespace anoncreds {

// ===== GENERAL =====

jsi::Value version(jsi::Runtime &rt, jsi::Object options) {
  return jsi::String::createFromAscii(rt, anoncreds_version());
};

jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options) {
  const char *out;

  anoncreds_get_current_error(&out);

  return jsi::String::createFromAscii(rt, out);
};

jsi::Value getJson(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  ByteBuffer out;

  ErrorCode code = anoncreds_object_get_json(handle, &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value getTypeName(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  const char *out;

  ErrorCode code = anoncreds_object_get_type_name(handle, &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value setDefaultLogger(jsi::Runtime &rt, jsi::Object options) {
  anoncreds_set_default_logger();
  return createReturnValue(rt, ErrorCode::Success, nullptr);
};

jsi::Value objectFree(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  anoncreds_object_free(handle);

  return createReturnValue(rt, ErrorCode::Success, nullptr);
};

// ===== META =====

jsi::Value createMasterSecret(jsi::Runtime &rt, jsi::Object options) {
  ObjectHandle out;

  ErrorCode code = anoncreds_create_master_secret(&out);

  return createReturnValue(rt, code, &out);
};

jsi::Value generateNonce(jsi::Runtime &rt, jsi::Object options) {
  const char *out;

  ErrorCode code = anoncreds_generate_nonce(&out);

  return createReturnValue(rt, code, &out);
};

// ===== Anoncreds Objects =====

jsi::Value createSchema(jsi::Runtime &rt, jsi::Object options) {
  auto name = jsiToValue<std::string>(rt, options, "name");
  auto version = jsiToValue<std::string>(rt, options, "version");
  auto issuerId = jsiToValue<std::string>(rt, options, "issuerId");
  auto attributeNames = jsiToValue<FfiStrList>(rt, options, "attributeNames");

  ObjectHandle out;

  ErrorCode code = anoncreds_create_schema(
      name.c_str(), version.c_str(), issuerId.c_str(), attributeNames, &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value createCredentialDefinition(jsi::Runtime &rt, jsi::Object options) {
  auto schemaId = jsiToValue<std::string>(rt, options, "schemaId");
  auto schema = jsiToValue<ObjectHandle>(rt, options, "schema");
  auto credentialDefinitionId =
      jsiToValue<std::string>(rt, options, "credentialDefinintionId");
  auto tag = jsiToValue<std::string>(rt, options, "tag");
  auto issuerId = jsiToValue<std::string>(rt, options, "issuerId");
  auto signatureType = jsiToValue<std::string>(rt, options, "signatureType");
  auto supportRevocation = jsiToValue<int8_t>(rt, options, "supportRevocation");

  CredentialDefinitionReturn out;

  ErrorCode code = anoncreds_create_credential_definition(
      schemaId.c_str(), schema, tag.c_str(), issuerId.c_str(),
      signatureType.c_str(), supportRevocation, &out.credentialDefinition,
      &out.credentialDefinitionPrivate, &out.keyCorrectnessProof);

  return createReturnValue(rt, code, &out);
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

  ObjectHandle out;

  ErrorCode code = anoncreds_create_presentation(
      presentationRequest, credentials, credentialsProve, selfAttestedNames,
      selfAttestedValues, masterSecret, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionids, &out);

  return createReturnValue(rt, code, &out);
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

  int8_t out;

  ErrorCode code = anoncreds_verify_presentation(
      presentation, presentationRequest, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionIds,
      revocationRegistryDefinitions, revocationRegistryDefinitionIds,
      revocationStatusLists, &out);

  return createReturnValue(rt, code, &out);
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

  ObjectHandle out;

  ErrorCode code = anoncreds_create_credential(
      credentialDefinition, credentialDefinitionPrivate, credentialOffer,
      credentialRequest, attributeNames, attributeRawValues,
      attributeEncodedValues, revocationRegistryId.c_str(),
      revocationStatusList, &revocation, &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value createCredentialOffer(jsi::Runtime &rt, jsi::Object options) {
  auto schemaId = jsiToValue<std::string>(rt, options, "schemaId");
  auto credentialDefinitionId =
      jsiToValue<std::string>(rt, options, "credentialDefinitionId");
  auto keyProof = jsiToValue<ObjectHandle>(rt, options, "keyProof");

  ObjectHandle out;

  ErrorCode code = anoncreds_create_credential_offer(
      schemaId.c_str(), credentialDefinitionId.c_str(), keyProof, &out);

  return createReturnValue(rt, code, &out);
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

  CredentialRequestReturn out;

  ErrorCode code = anoncreds_create_credential_request(
      entropy.length() ? entropy.c_str() : nullptr,
      proverDid.length() ? proverDid.c_str() : nullptr, credentialDefinition,
      masterSecret, masterSecretId.c_str(), credentialOffer,
      &out.credentialRequest, &out.credentialRequestMetadata);

  return createReturnValue(rt, code, &out);
};

jsi::Value credentialGetAttribute(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *out;

  ErrorCode code =
      anoncreds_credential_get_attribute(handle, name.c_str(), &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value encodeCredentialAttributes(jsi::Runtime &rt, jsi::Object options) {
  auto attributeRawValues =
      jsiToValue<FfiList_FfiStr>(rt, options, "attributeRawValues");

  const char *out;

  ErrorCode code =
      anoncreds_encode_credential_attributes(attributeRawValues, &out);

  return createReturnValue(rt, code, &out);
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

  ObjectHandle out;

  ErrorCode code = anoncreds_process_credential(
      credential, credentialRequestMetadata, masterSecret, credentialDefinition,
      revocationRegistryDefinition, &out);

  return createReturnValue(rt, code, &out);
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

  ObjectHandle out;

  ErrorCode code = anoncreds_create_or_update_revocation_state(
      revocationRegistryDefinition, revocationStatusList,
      revocationRegistryIndex, tailsPath.c_str(), revocationState,
      oldRevocationStatusList, &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value createRevocationStatusList(jsi::Runtime &rt, jsi::Object options) {
  auto revocationRegistryDefinitionId =
      jsiToValue<std::string>(rt, options, "revocationRegistryDefinitionId");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto issuanceByDefault = jsiToValue<int8_t>(rt, options, "issuanceByDefault");

  ObjectHandle out;

  ErrorCode code = anoncreds_create_revocation_status_list(
      revocationRegistryDefinitionId.c_str(), revocationRegistryDefinition,
      timestamp, issuanceByDefault, &out);

  return createReturnValue(rt, code, &out);
}

jsi::Value updateRevocationStatusList(jsi::Runtime &rt, jsi::Object options) {
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto issued = jsiToValue<FfiList_i32>(rt, options, "issued");
  auto revoked = jsiToValue<FfiList_i32>(rt, options, "revoked");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList");

  ObjectHandle out;

  ErrorCode code = anoncreds_update_revocation_status_list(
      timestamp, issued, revoked, revocationRegistryDefinition,
      revocationStatusList, &out);

  return createReturnValue(rt, code, &out);
}

jsi::Value updateRevocationStatusListTimestampOnly(jsi::Runtime &rt,
                                                   jsi::Object options) {
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList");

  ObjectHandle out;

  ErrorCode code = anoncreds_update_revocation_status_list_timestamp_only(
      timestamp, revocationStatusList, &out);

  return createReturnValue(rt, code, &out);
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
  auto maxCredNum = jsiToValue<int64_t>(rt, options, "maximumCredentialnumber");
  auto tailsDirPath =
      jsiToValue<std::string>(rt, options, "tailsDirPath", true);

  RevocationRegistryDefinition out;

  ErrorCode code = anoncreds_create_revocation_registry_def(
      credentialDefinition, credentialDefinitionId.c_str(), issuerId.c_str(),
      tag.c_str(), revocationRegistryType.c_str(), maxCredNum,
      tailsDirPath ? nullptr : tailsDirPath.c_str(),
      &out.revocationRegistryDefinition,
      &out.revocationRegistryDefinitionPrivate);

  return createReturnValue(rt, code, &out);
};

jsi::Value revocationRegistryDefinitionGetAttribute(jsi::Runtime &rt,
                                                    jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *out;

  ErrorCode code = anoncreds_revocation_registry_definition_get_attribute(
      handle, name.c_str(), &out);

  return createReturnValue(rt, code, &out);
};

} // namespace anoncreds
