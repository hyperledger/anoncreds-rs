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

jsi::Value createLinkSecret(jsi::Runtime &rt, jsi::Object options) {
  ObjectHandle out;

  ErrorCode code = anoncreds_create_link_secret(&out);

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

// ===== AnonCreds Objects from JSON =====

ByteBuffer stringToByteBuffer(std::string str) {
  ByteBuffer b;
  size_t len = str.size();
  uint8_t *c = new uint8_t[len + 1];
  std::copy(str.begin(), str.end(), c);
  c[len] = '\0';
  b.data = c;
  b.len = len;

  return b;
}

jsi::Value revocationRegistryDefinitionFromJson(jsi::Runtime &rt,
                                                jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;

  ByteBuffer b = stringToByteBuffer(json);
  ErrorCode code = anoncreds_revocation_registry_definition_from_json(b, &out);

  auto returnValue = createReturnValue(rt, code, &out);

  // free data
  delete[] b.data;

  return returnValue;
};

jsi::Value revocationRegistryFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_registry_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value presentationFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_presentation_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value presentationRequestFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_presentation_request_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value credentialOfferFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_offer_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value schemaFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_schema_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value credentialRequestFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_request_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value credentialRequestMetadataFromJson(jsi::Runtime &rt,
                                             jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_request_metadata_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value credentialFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value revocationRegistryDefinitionPrivateFromJson(jsi::Runtime &rt,
                                                       jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code =
      anoncreds_revocation_registry_definition_private_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value revocationStateFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_state_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value revocationRegistryDeltaFromJson(jsi::Runtime &rt,
                                           jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_registry_delta_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value credentialDefinitionFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_definition_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value credentialDefinitionPrivateFromJson(jsi::Runtime &rt,
                                               jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_definition_private_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
};

jsi::Value keyCorrectnessProofFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle out;
  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_key_correctness_proof_from_json(b, &out);
  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] b.data;

  return returnValue;
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
      jsiToValue<FfiStrList>(rt, options, "selfAttestNames");
  auto selfAttestedValues =
      jsiToValue<FfiStrList>(rt, options, "selfAttestValues");
  auto linkSecret = jsiToValue<ObjectHandle>(rt, options, "linkSecret");
  auto schemas = jsiToValue<FfiList_ObjectHandle>(rt, options, "schemas");
  auto schemaIds = jsiToValue<FfiList_FfiStr>(rt, options, "schemaIds");
  auto credentialDefinitions =
      jsiToValue<FfiList_ObjectHandle>(rt, options, "credentialDefinitions");
  auto credentialDefinitionIds =
      jsiToValue<FfiList_FfiStr>(rt, options, "credentialDefinitionIds");

  ObjectHandle out;

  ErrorCode code = anoncreds_create_presentation(
      presentationRequest, credentials, credentialsProve, selfAttestedNames,
      selfAttestedValues, linkSecret, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionIds, &out);

  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  delete[] credentials.data;
  for (int i = 0; i < credentialsProve.count; i++) {
    delete[] credentialsProve.data[i].referent;
  }
  for (int i = 0; i < schemaIds.count; i++) {
    delete[] schemaIds.data[i];
  }
  delete[] schemas.data;
  for (int i = 0; i < credentialDefinitionIds.count; i++) {
    delete[] credentialDefinitionIds.data[i];
  }
  delete[] credentialDefinitions.data;
  for (int i = 0; i < selfAttestedNames.count; i++) {
    delete[] selfAttestedNames.data[i];
  }
  for (int i = 0; i < selfAttestedValues.count; i++) {
    delete[] selfAttestedValues.data[i];
  }

  return returnValue;
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
      rt, options, "revocationRegistryDefinitions", true);
  auto revocationRegistryDefinitionIds = jsiToValue<FfiList_FfiStr>(
      rt, options, "revocationRegistryDefinitionIds", true);
  auto revocationStatusLists = jsiToValue<FfiList_ObjectHandle>(
      rt, options, "revocationStatusLists", true);
  auto nonRevokedIntervalOverrides =
      jsiToValue<FfiList_FfiNonrevokedIntervalOverride>(
          rt, options, "nonRevokedIntervalOverrides", true);

  int8_t out;

  ErrorCode code = anoncreds_verify_presentation(
      presentation, presentationRequest, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionIds,
      revocationRegistryDefinitions, revocationRegistryDefinitionIds,
      revocationStatusLists, nonRevokedIntervalOverrides, &out);

  auto returnValue = createReturnValue(rt, code, &out);

  // Free memory
  for (int i = 0; i < schemaIds.count; i++) {
    delete[] schemaIds.data[i];
  }
  delete[] schemas.data;
  for (int i = 0; i < credentialDefinitionIds.count; i++) {
    delete[] credentialDefinitionIds.data[i];
  }
  delete[] credentialDefinitions.data;

  return returnValue;
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
      jsiToValue<FfiStrList>(rt, options, "attributeEncodedValues", true);
  auto revocationRegistryId =
      jsiToValue<std::string>(rt, options, "revocationRegistryId", true);
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList", true);
  auto revocation =
      jsiToValue<FfiCredRevInfo>(rt, options, "revocationConfiguration", true);

  ObjectHandle out;

  ErrorCode code = anoncreds_create_credential(
      credentialDefinition, credentialDefinitionPrivate, credentialOffer,
      credentialRequest, attributeNames, attributeRawValues,
      attributeEncodedValues,
      revocationRegistryId.length() > 0 ? revocationRegistryId.c_str()
                                        : nullptr,
      revocationStatusList, revocation.reg_def ? &revocation : 0, &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value createCredentialOffer(jsi::Runtime &rt, jsi::Object options) {
  auto schemaId = jsiToValue<std::string>(rt, options, "schemaId");
  auto credentialDefinitionId =
      jsiToValue<std::string>(rt, options, "credentialDefinitionId");
  auto keyCorrectnessProof =
      jsiToValue<ObjectHandle>(rt, options, "keyCorrectnessProof");

  ObjectHandle out;

  ErrorCode code = anoncreds_create_credential_offer(
      schemaId.c_str(), credentialDefinitionId.c_str(), keyCorrectnessProof,
      &out);

  return createReturnValue(rt, code, &out);
};

jsi::Value createCredentialRequest(jsi::Runtime &rt, jsi::Object options) {
  auto entropy = jsiToValue<std::string>(rt, options, "entropy", true);
  auto proverDid = jsiToValue<std::string>(rt, options, "proverDid", true);
  auto credentialDefinition =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinition");
  auto linkSecret = jsiToValue<ObjectHandle>(rt, options, "linkSecret");
  auto linkSecretId = jsiToValue<std::string>(rt, options, "linkSecretId");
  auto credentialOffer =
      jsiToValue<ObjectHandle>(rt, options, "credentialOffer");

  CredentialRequestReturn out;

  ErrorCode code = anoncreds_create_credential_request(
      entropy.length() ? entropy.c_str() : nullptr,
      proverDid.length() ? proverDid.c_str() : nullptr, credentialDefinition,
      linkSecret, linkSecretId.c_str(), credentialOffer,
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
  auto linkSecret = jsiToValue<ObjectHandle>(rt, options, "linkSecret");
  auto credentialDefinition =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinition");
  auto revocationRegistryDefinition = jsiToValue<ObjectHandle>(
      rt, options, "revocationRegistryDefinition", true);

  ObjectHandle out;

  ErrorCode code = anoncreds_process_credential(
      credential, credentialRequestMetadata, linkSecret, credentialDefinition,
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
  auto issuerId = jsiToValue<std::string>(rt, options, "issuerId");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto issuanceByDefault = jsiToValue<int8_t>(rt, options, "issuanceByDefault");

  ObjectHandle out;

  ErrorCode code = anoncreds_create_revocation_status_list(
      revocationRegistryDefinitionId.c_str(), revocationRegistryDefinition,
      issuerId.c_str(), timestamp, issuanceByDefault, &out);

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
  auto maxCredNum = jsiToValue<int64_t>(rt, options, "maximumCredentialNumber");
  auto tailsDirPath =
      jsiToValue<std::string>(rt, options, "tailsDirectoryPath", true);

  RevocationRegistryDefinitionReturn out;

  ErrorCode code = anoncreds_create_revocation_registry_def(
      credentialDefinition, credentialDefinitionId.c_str(), issuerId.c_str(),
      tag.c_str(), revocationRegistryType.c_str(), maxCredNum,
      tailsDirPath.length() > 0 ? tailsDirPath.c_str() : nullptr,
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
