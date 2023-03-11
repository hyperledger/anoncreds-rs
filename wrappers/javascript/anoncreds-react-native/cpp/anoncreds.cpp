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

jsi::Value revocationRegistryDefinitionFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle revocationRegistryDefinitionP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_registry_definition_from_json(b, &revocationRegistryDefinitionP);
    
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(revocationRegistryDefinitionP));
};

jsi::Value revocationRegistryFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle revocationRegistryP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_registry_from_json(b, &revocationRegistryP);
  
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(revocationRegistryP));
};

jsi::Value presentationFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle presentationP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_presentation_from_json(b, &presentationP);

  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(presentationP));
};

jsi::Value presentationRequestFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle presentationRequestP;

  ByteBuffer b = stringToByteBuffer(json);
    
  ErrorCode code = anoncreds_presentation_request_from_json(b, &presentationRequestP);

  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(presentationRequestP));
};

jsi::Value credentialOfferFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle credentialOfferP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_offer_from_json(b, &credentialOfferP);
  
  delete[] b.data;
  handleError(rt, code);

  return jsi::Value(int(credentialOfferP));
};

jsi::Value schemaFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle schemaP;

  ByteBuffer b = stringToByteBuffer(json);
  
  ErrorCode code = anoncreds_schema_from_json(b, &schemaP);
  
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(schemaP));
};

jsi::Value masterSecretFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle masterSecretP;

  ByteBuffer b = stringToByteBuffer(json);
  
  ErrorCode code = anoncreds_master_secret_from_json(b, &masterSecretP);

  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(masterSecretP));
};

jsi::Value credentialRequestFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle credentialRequestP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_request_from_json(b, &credentialRequestP);
  
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(credentialRequestP));
};

jsi::Value credentialRequestMetadataFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle credentialRequestMetadataP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_request_metadata_from_json(b, &credentialRequestMetadataP);

  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(credentialRequestMetadataP));
};

jsi::Value credentialFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle credentialP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_from_json(b, &credentialP);
  
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(credentialP));
};

jsi::Value revocationRegistryDefinitionPrivateFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle revocationRegistryDefinitionPrivateP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_registry_definition_private_from_json(b, &revocationRegistryDefinitionPrivateP);
  
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(revocationRegistryDefinitionPrivateP));
};

jsi::Value revocationStateFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle revocationStateP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_state_from_json(b, &revocationStateP);
  
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(revocationStateP));
};

jsi::Value revocationRegistryDeltaFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle revocationRegistryDeltaP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_revocation_registry_delta_from_json(b, &revocationRegistryDeltaP);
  
  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(revocationRegistryDeltaP));
};

jsi::Value credentialDefinitionFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle credentialDefinitionP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_definition_from_json(b, &credentialDefinitionP);

  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(credentialDefinitionP));
};

jsi::Value credentialDefinitionPrivateFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle credentialDefinitionPrivateP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_credential_definition_private_from_json(b, &credentialDefinitionPrivateP);

  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(credentialDefinitionPrivateP));
};

jsi::Value keyCorrectnessProofFromJson(jsi::Runtime &rt, jsi::Object options) {
  auto json = jsiToValue<std::string>(rt, options, "json");

  ObjectHandle keyCorrectnessProofP;

  ByteBuffer b = stringToByteBuffer(json);

  ErrorCode code = anoncreds_key_correctness_proof_from_json(b, &keyCorrectnessProofP);

  handleError(rt, code);
  delete[] b.data;

  return jsi::Value(int(keyCorrectnessProofP));
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
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSecret");
  auto schemas = jsiToValue<FfiList_ObjectHandle>(rt, options, "schemas");
  auto schemaIds = jsiToValue<FfiList_FfiStr>(rt, options, "schemaIds");
  auto credentialDefinitions =
      jsiToValue<FfiList_ObjectHandle>(rt, options, "credentialDefinitions");
  auto credentialDefinitionIds =
      jsiToValue<FfiList_FfiStr>(rt, options, "credentialDefinitionIds");

  ObjectHandle presentationP;

  ErrorCode code = anoncreds_create_presentation(
      presentationRequest, credentials, credentialsProve, selfAttestedNames,
      selfAttestedValues, masterSecret, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionIds, &presentationP);
  handleError(rt, code);

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
      rt, options, "revocationRegistryDefinitions", true);
  auto revocationRegistryDefinitionIds = jsiToValue<FfiList_FfiStr>(
      rt, options, "revocationRegistryDefinitionIds", true);
  auto revocationStatusLists =
      jsiToValue<FfiList_ObjectHandle>(rt, options, "revocationStatusLists", true);
  auto nonRevokedIntervalOverrides =
      jsiToValue<FfiList_FfiNonrevokedIntervalOverride>(rt, options, "nonRevokedIntervalOverrides", true);

  int8_t resultP;

  ErrorCode code = anoncreds_verify_presentation(
      presentation, presentationRequest, schemas, schemaIds,
      credentialDefinitions, credentialDefinitionIds,
      revocationRegistryDefinitions, revocationRegistryDefinitionIds,
      revocationStatusLists, nonRevokedIntervalOverrides, &resultP);
  handleError(rt, code);

  // Free memory
  for (int i = 0; i < schemaIds.count; i++) {
    delete[] schemaIds.data[i];
  }
  delete[] schemas.data;
  for (int i = 0; i < credentialDefinitionIds.count; i++) {
    delete[] credentialDefinitionIds.data[i];
  }
  delete[] credentialDefinitions.data;
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
      jsiToValue<FfiStrList>(rt, options, "attributeEncodedValues", true);
  auto revocationRegistryId =
      jsiToValue<std::string>(rt, options, "revocationRegistryId", true);
  auto revocationStatusList =
      jsiToValue<ObjectHandle>(rt, options, "revocationStatusList", true);
  auto revocation = jsiToValue<FfiCredRevInfo>(rt, options, "revocationConfiguration", true);

  ObjectHandle credP;

  ErrorCode code = anoncreds_create_credential(
      credentialDefinition, credentialDefinitionPrivate, credentialOffer,
      credentialRequest, attributeNames, attributeRawValues,
      attributeEncodedValues, revocationRegistryId.length() > 0 ? revocationRegistryId.c_str() : nullptr,
      revocationStatusList, revocation.reg_def ? &revocation : 0, &credP);
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

  ErrorCode code = anoncreds_create_credential_request(entropy.length() ? entropy.c_str() : nullptr,
      proverDid.length() ? proverDid.c_str() : nullptr, credentialDefinition, masterSecret,
      masterSecretId.c_str(), credentialOffer, &credReqP, &credReqMetaP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "credentialRequest", int(credReqP));
  object.setProperty(rt, "credentialRequestMetadata", int(credReqMetaP));
  return object;
};

jsi::Value credentialGetAttribute(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *resultP;

  ErrorCode code =
      anoncreds_credential_get_attribute(handle, name.c_str(), &resultP);
  handleError(rt, code);

  return resultP != nullptr ? jsi::String::createFromAscii(rt, resultP) : jsi::Value::null();
};

jsi::Value encodeCredentialAttributes(jsi::Runtime &rt, jsi::Object options) {
  auto attributeRawValues =
      jsiToValue<FfiList_FfiStr>(rt, options, "attributeRawValues");

  const char *resultP;

  ErrorCode code =
      anoncreds_encode_credential_attributes(attributeRawValues, &resultP);
  handleError(rt, code);

  return resultP != nullptr ? jsi::String::createFromAscii(rt, resultP) : jsi::Value::null();
};

jsi::Value processCredential(jsi::Runtime &rt, jsi::Object options) {
  auto credential = jsiToValue<ObjectHandle>(rt, options, "credential");
  auto credentialRequestMetadata =
      jsiToValue<ObjectHandle>(rt, options, "credentialRequestMetadata");
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSecret");
  auto credentialDefinition =
      jsiToValue<ObjectHandle>(rt, options, "credentialDefinition");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition", true);

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
  auto issuerId =
      jsiToValue<std::string>(rt, options, "issuerId");
  auto revocationRegistryDefinition =
      jsiToValue<ObjectHandle>(rt, options, "revocationRegistryDefinition");
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto issuanceByDefault = jsiToValue<int8_t>(rt, options, "issuanceByDefault");

  ObjectHandle revocationStatusListP;

  ErrorCode code = anoncreds_create_revocation_status_list(
      revocationRegistryDefinitionId.c_str(), revocationRegistryDefinition,
      issuerId.c_str(), timestamp, issuanceByDefault, &revocationStatusListP);
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
  auto maxCredNum = jsiToValue<int64_t>(rt, options, "maximumCredentialNumber");
  auto tailsDirPath = jsiToValue<std::string>(rt, options, "tailsDirectoryPath", true);

  ObjectHandle regDefP;
  ObjectHandle regDefPrivateP;

  ErrorCode code = anoncreds_create_revocation_registry_def(
      credentialDefinition, credentialDefinitionId.c_str(), issuerId.c_str(),
      tag.c_str(), revocationRegistryType.c_str(), maxCredNum,
      tailsDirPath.c_str(), &regDefP, &regDefPrivateP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "revocationRegistryDefinition", int(regDefP));
  object.setProperty(rt, "revocationRegistryDefinitionPrivate", int(regDefPrivateP));
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

  return resultP != nullptr ? jsi::String::createFromAscii(rt, resultP) : jsi::Value::null();
};

} // namespace anoncreds
