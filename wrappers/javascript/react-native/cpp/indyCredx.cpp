#include <indyCredx.h>

#include <include/libindy_credx.h>

using namespace turboModuleUtility;

namespace indyCredx {

jsi::Value version(jsi::Runtime &rt, jsi::Object options) {
  return jsi::String::createFromAscii(rt, credx_version());
};

jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options) {
  const char *errorJsonP;

  credx_get_current_error(&errorJsonP);

  return jsi::String::createFromAscii(rt, errorJsonP);
};

jsi::Value createCredential(jsi::Runtime &rt, jsi::Object options) {
  auto credDef = jsiToValue<ObjectHandle>(rt, options, "credDef");
  auto credDefPrivate = jsiToValue<ObjectHandle>(rt, options, "credDefPrivate");
  auto credOffer = jsiToValue<ObjectHandle>(rt, options, "credOffer");
  auto credRequest = jsiToValue<ObjectHandle>(rt, options, "credRequest");
  auto attrNames = jsiToValue<FfiStrList>(rt, options, "attrNames");
  auto attributeRawValues = jsiToValue<FfiStrList>(rt, options, "attributeRawValues");
  auto attrEncValues = jsiToValue<FfiStrList>(rt, options, "attrEncValues");
  auto revocation = jsiToValue<FfiCredRevInfo>(rt, options, "revocation");

  ObjectHandle credP;
  ObjectHandle revRegP;
  ObjectHandle revDeltaP;

  ErrorCode code = credx_create_credential(
      credDef, credDefPrivate, credOffer, credRequest, attrNames, attributeRawValues,
      attrEncValues, &revocation, &credP, &revRegP, &revDeltaP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "cred", int(credP));
  object.setProperty(rt, "revReg", int(revRegP));
  object.setProperty(rt, "revDelta", int(revDeltaP));
  return object;
};

jsi::Value createCredentialDefinition(jsi::Runtime &rt, jsi::Object options) {
  auto originDid = jsiToValue<std::string>(rt, options, "originDid");
  auto schema = jsiToValue<ObjectHandle>(rt, options, "schema");
  auto tag = jsiToValue<std::string>(rt, options, "tag");
  auto signatureType = jsiToValue<std::string>(rt, options, "signatureType");
  auto supportRevocation = jsiToValue<int8_t>(rt, options, "supportRevocation");

  ObjectHandle credDefP;
  ObjectHandle credDefPvtP;
  ObjectHandle keyProofP;

  ErrorCode code = credx_create_credential_definition(
      originDid.c_str(), schema, tag.c_str(), signatureType.c_str(),
      supportRevocation, &credDefP, &credDefPvtP, &keyProofP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "credentialDefinition", int(credDefP));
  object.setProperty(rt, "credentialDefinitionPrivate", int(credDefPvtP));
  object.setProperty(rt, "keyProof", int(keyProofP));
  return object;
};

jsi::Value createCredentialOffer(jsi::Runtime &rt, jsi::Object options) {
  auto schemaId = jsiToValue<std::string>(rt, options, "schemaId");
  auto credDef = jsiToValue<ObjectHandle>(rt, options, "credDef");
  auto keyProof = jsiToValue<ObjectHandle>(rt, options, "keyProof");

  ObjectHandle credOfferP;

  ErrorCode code = credx_create_credential_offer(schemaId.c_str(), credDef,
                                                 keyProof, &credOfferP);
  handleError(rt, code);

  return jsi::Value(int(credOfferP));
};

jsi::Value createCredentialRequest(jsi::Runtime &rt, jsi::Object options) {
  auto proverDid = jsiToValue<std::string>(rt, options, "proverDid");
  auto credDef = jsiToValue<ObjectHandle>(rt, options, "credDef");
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSecret");
  auto masterSecretId = jsiToValue<std::string>(rt, options, "masterSecretId");
  auto credOffer = jsiToValue<ObjectHandle>(rt, options, "credOffer");

  ObjectHandle credReqP;
  ObjectHandle credReqMetaP;

  ErrorCode code = credx_create_credential_request(
      proverDid.c_str(), credDef, masterSecret, masterSecretId.c_str(),
      credOffer, &credReqP, &credReqMetaP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "credReq", int(credReqP));
  object.setProperty(rt, "credReqMeta", int(credReqMetaP));
  return object;
};

jsi::Value createMasterSecret(jsi::Runtime &rt, jsi::Object options) {
  ObjectHandle masterSecretP;

  ErrorCode code = credx_create_master_secret(&masterSecretP);
  handleError(rt, code);

  return jsi::Value(int(masterSecretP));
};

jsi::Value createOrUpdateRevocationState(jsi::Runtime &rt,
                                         jsi::Object options) {
  auto revRegDef = jsiToValue<ObjectHandle>(rt, options, "revRegDef");
  auto revRegDelta = jsiToValue<ObjectHandle>(rt, options, "revRegDelta");
  auto revRegIndex = jsiToValue<int64_t>(rt, options, "revRegIndex");
  auto timestamp = jsiToValue<int64_t>(rt, options, "timestamp");
  auto tailsPath = jsiToValue<std::string>(rt, options, "tailsPath");
  auto revState = jsiToValue<ObjectHandle>(rt, options, "revState");

  ObjectHandle revStateP;

  ErrorCode code = credx_create_or_update_revocation_state(
      revRegDef, revRegDelta, revRegIndex, timestamp, tailsPath.c_str(),
      revState, &revStateP);
  handleError(rt, code);

  return jsi::Value(int(revStateP));
};

jsi::Value createPresentation(jsi::Runtime &rt, jsi::Object options) {
  auto presReq = jsiToValue<ObjectHandle>(rt, options, "presReq");
  auto credentials =
      jsiToValue<FfiList_FfiCredentialEntry>(rt, options, "credentials");
  auto credentialsProve =
      jsiToValue<FfiList_FfiCredentialProve>(rt, options, "credentialsProve");
  auto selfAttestNames = jsiToValue<FfiStrList>(rt, options, "selfAttestNames");
  auto selfAttestValues =
      jsiToValue<FfiStrList>(rt, options, "selfAttestValues");
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSercet");
  auto schemas = jsiToValue<FfiList_ObjectHandle>(rt, options, "schemas");
  auto credDefs = jsiToValue<FfiList_ObjectHandle>(rt, options, "credDefs");

  ObjectHandle presentationP;

  ErrorCode code = credx_create_presentation(
      presReq, credentials, credentialsProve, selfAttestNames, selfAttestValues,
      masterSecret, schemas, credDefs, &presentationP);
  handleError(rt, code);

  return jsi::Value(int(presentationP));
};

jsi::Value createRevocationRegistry(jsi::Runtime &rt, jsi::Object options) {
  auto originDid = jsiToValue<std::string>(rt, options, "originDid");
  auto credDef = jsiToValue<ObjectHandle>(rt, options, "credDef");
  auto tag = jsiToValue<std::string>(rt, options, "tag");
  auto revRegType = jsiToValue<std::string>(rt, options, "revRegType");
  auto issuanceType = jsiToValue<std::string>(rt, options, "issuanceType");
  auto maxCredNum = jsiToValue<int64_t>(rt, options, "maxCredNum");
  auto tailsDirPath = jsiToValue<std::string>(rt, options, "tailsDirPath");

  ObjectHandle regDefP;
  ObjectHandle regDefPrivateP;
  ObjectHandle regEntryP;
  ObjectHandle regInitDeltaP;

  ErrorCode code = credx_create_revocation_registry(
      originDid.c_str(), credDef, tag.c_str(), revRegType.c_str(),
      issuanceType.c_str(), maxCredNum, tailsDirPath.c_str(), &regDefP,
      &regDefPrivateP, &regEntryP, &regInitDeltaP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "regDef", int(regDefP));
  object.setProperty(rt, "regDefPrivate", int(regDefPrivateP));
  object.setProperty(rt, "regEntry", int(regEntryP));
  object.setProperty(rt, "regInitDelta", int(regInitDeltaP));
  return object;
};

jsi::Value createSchema(jsi::Runtime &rt, jsi::Object options) {
  auto originDid = jsiToValue<std::string>(rt, options, "originDid");
  auto schemaName = jsiToValue<std::string>(rt, options, "name");
  auto schemaVersion = jsiToValue<std::string>(rt, options, "version");
  auto attrNames = jsiToValue<FfiStrList>(rt, options, "attributeNames");
  auto seqNo = jsiToValue<int64_t>(rt, options, "sequenceNumber");

  ObjectHandle resultP;

  ErrorCode code =
      credx_create_schema(originDid.c_str(), schemaName.c_str(),
                          schemaVersion.c_str(), attrNames, seqNo, &resultP);
  handleError(rt, code);

  return jsi::Value(int(resultP));
};

jsi::Value credentialDefinitionGetAttribute(jsi::Runtime &rt,
                                            jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *resultP;

  ErrorCode code =
      credx_credential_definition_get_attribute(handle, name.c_str(), &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value credentialGetAttribute(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *resultP;

  ErrorCode code =
      credx_credential_get_attribute(handle, name.c_str(), &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value encodeCredentialAttributes(jsi::Runtime &rt, jsi::Object options) {
  auto attributeRawValues = jsiToValue<FfiList_FfiStr>(rt, options, "attributeRawValues");

  const char* resultP;

  ErrorCode code = credx_encode_credential_attributes(attributeRawValues, &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value generateNonce(jsi::Runtime &rt, jsi::Object options) {
  const char *nonceP;

  ErrorCode code = credx_generate_nonce(&nonceP);
  handleError(rt, code);

    return jsi::String::createFromAscii(rt, nonceP);
};


jsi::Value mergeRevocationRegistryDeltas(jsi::Runtime &rt,
                                         jsi::Object options) {
  auto revRegDelta1 = jsiToValue<ObjectHandle>(rt, options, "revRegDelta1");
  auto revRegDelta2 = jsiToValue<ObjectHandle>(rt, options, "revRegDelta2");

  ObjectHandle revRegDeltaP;

  ErrorCode code = credx_merge_revocation_registry_deltas(
      revRegDelta1, revRegDelta2, &revRegDeltaP);
  handleError(rt, code);

  return jsi::Value(int(revRegDeltaP));
};

jsi::Value getJson(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  ByteBuffer resultP;

  ErrorCode code = credx_object_get_json(handle, &resultP);
  handleError(rt, code);

  return jsi::String::createFromUtf8(rt, resultP.data, resultP.len);
};

jsi::Value getTypeName(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  const char *resultP;

  ErrorCode code = credx_object_get_type_name(handle, &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value processCredential(jsi::Runtime &rt, jsi::Object options) {
  auto cred = jsiToValue<ObjectHandle>(rt, options, "cred");
  auto credReqMetadata =
      jsiToValue<ObjectHandle>(rt, options, "credReqMetadata");
  auto masterSecret = jsiToValue<ObjectHandle>(rt, options, "masterSercet");
  auto credDef = jsiToValue<ObjectHandle>(rt, options, "credDef");
  auto revRegDef = jsiToValue<ObjectHandle>(rt, options, "revRegDef");

  ObjectHandle credP;

  ErrorCode code = credx_process_credential(cred, credReqMetadata, masterSecret,
                                            credDef, revRegDef, &credP);
  handleError(rt, code);

  return jsi::Value(int(credP));
};

jsi::Value revocationRegistryDefinitionGetAttribute(jsi::Runtime &rt,
                                                    jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *resultP;

  ErrorCode code =
      credx_revocation_registry_definition_get_attribute(handle, name.c_str(), &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value revokeCredential(jsi::Runtime &rt, jsi::Object options) {
  auto revRegDef = jsiToValue<ObjectHandle>(rt, options, "revRegDef");
  auto revReg = jsiToValue<ObjectHandle>(rt, options, "revReg");
  auto credRevIdx = jsiToValue<int64_t>(rt, options, "credRevIdx");
  auto tailsPath = jsiToValue<std::string>(rt, options, "tailsPath");

  ObjectHandle revRegP;
  ObjectHandle revRegDeltaP;

  ErrorCode code = credx_revoke_credential(revRegDef, revReg, credRevIdx,
                                           tailsPath.c_str(), &revRegP, &revRegDeltaP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "revReg", int(revRegP));
  object.setProperty(rt, "revRegDelta", int(revRegDeltaP));
  return object;
};

jsi::Value schemaGetAttribute(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  const char *resultP;

  ErrorCode code = credx_schema_get_attribute(handle, name.c_str(), &resultP);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, resultP);
};

jsi::Value setDefaultLogger(jsi::Runtime &rt, jsi::Object options) {
  credx_set_default_logger();
  return jsi::Value::null();
};

jsi::Value updateRevocationRegistry(jsi::Runtime &rt, jsi::Object options) {
  auto revRegDef = jsiToValue<ObjectHandle>(rt, options, "revRegDef");
  auto revReg = jsiToValue<ObjectHandle>(rt, options, "revReg");
  auto issued = jsiToValue<FfiList_i64>(rt, options, "issued");
  auto revoked = jsiToValue<FfiList_i64>(rt, options, "revoked");
  auto tailsPath = jsiToValue<std::string>(rt, options, "tailsPath");

  ObjectHandle revRegP;
  ObjectHandle revRegDeltaP;

  ErrorCode code = credx_update_revocation_registry(
      revRegDef, revReg, issued, revoked, tailsPath.c_str(), &revRegP, &revRegDeltaP);
  handleError(rt, code);

  jsi::Object object = jsi::Object(rt);
  object.setProperty(rt, "revReg", int(revRegP));
  object.setProperty(rt, "revRegDelta", int(revRegDeltaP));
  return object;
}

jsi::Value verifyPresentation(jsi::Runtime &rt, jsi::Object options) {
  auto presentation = jsiToValue<ObjectHandle>(rt, options, "presentation");
  auto presReq = jsiToValue<ObjectHandle>(rt, options, "presReq");
  auto schemas = jsiToValue<FfiList_ObjectHandle>(rt, options, "schemas");
  auto credDefs = jsiToValue<FfiList_ObjectHandle>(rt, options, "credDefs");
  auto revRegDefs = jsiToValue<FfiList_ObjectHandle>(rt, options, "revRegDefs");
  auto revRegEntries =
      jsiToValue<FfiList_FfiRevocationEntry>(rt, options, "revRegEntries");

  int8_t resultP;

  ErrorCode code =
      credx_verify_presentation(presentation, presReq, schemas, credDefs,
                                revRegDefs, revRegEntries, &resultP);
  handleError(rt, code);

  return jsi::Value(int(resultP));
};

jsi::Value objectFree(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<ObjectHandle>(rt, options, "objectHandle");

  credx_object_free(handle);

  return jsi::Value::null();
};

} // namespace indyCredx
