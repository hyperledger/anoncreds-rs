#include <HostObject.h>
#include <algorithm>
#include <vector>

TurboModuleHostObject::TurboModuleHostObject(jsi::Runtime &rt) { return; }

FunctionMap TurboModuleHostObject::functionMapping(jsi::Runtime &rt) {
  FunctionMap fMap;

  fMap.insert(std::make_tuple("version", &indyCredx::version));
  fMap.insert(std::make_tuple("getCurrentError", &indyCredx::getCurrentError));
  fMap.insert(
      std::make_tuple("createCredential", &indyCredx::createCredential));
  fMap.insert(std::make_tuple("createCredentialDefinition",
                              &indyCredx::createCredentialDefinition));
  fMap.insert(std::make_tuple("createCredentialOffer",
                              &indyCredx::createCredentialOffer));
  fMap.insert(std::make_tuple("createCredentialRequest",
                              &indyCredx::createCredentialRequest));
  fMap.insert(
      std::make_tuple("createMasterSecret", &indyCredx::createMasterSecret));
  fMap.insert(std::make_tuple("createOrUpdateRevocationState",
                              &indyCredx::createOrUpdateRevocationState));
  fMap.insert(
      std::make_tuple("createPresentation", &indyCredx::createPresentation));
  fMap.insert(std::make_tuple("createRevocationRegistry",
                              &indyCredx::createRevocationRegistry));
  fMap.insert(std::make_tuple("createSchema", &indyCredx::createSchema));
  fMap.insert(std::make_tuple("credentialDefinitionGetAttribute",
                              &indyCredx::credentialDefinitionGetAttribute));
  fMap.insert(std::make_tuple("credentialGetAttribute",
                                &indyCredx::credentialGetAttribute));
  fMap.insert(std::make_tuple("encodeCredentialAttributes",
                              &indyCredx::encodeCredentialAttributes));
  fMap.insert(std::make_tuple("generateNonce", &indyCredx::generateNonce));
  fMap.insert(std::make_tuple("mergeRevocationRegistryDeltas",
                              &indyCredx::mergeRevocationRegistryDeltas));
  fMap.insert(std::make_tuple("getJson", &indyCredx::getJson));
  fMap.insert(
      std::make_tuple("getTypeName", &indyCredx::getTypeName));
  fMap.insert(
      std::make_tuple("processCredential", &indyCredx::processCredential));
  fMap.insert(
      std::make_tuple("revocationRegistryDefinitionGetAttribute",
                      &indyCredx::revocationRegistryDefinitionGetAttribute));
  fMap.insert(
      std::make_tuple("revokeCredential", &indyCredx::revokeCredential));
  fMap.insert(
      std::make_tuple("schemaGetAttribute", &indyCredx::schemaGetAttribute));
  fMap.insert(
      std::make_tuple("setDefaultLogger", &indyCredx::setDefaultLogger));
  fMap.insert(
      std::make_tuple("verifyPresentation", &indyCredx::verifyPresentation));
  fMap.insert(std::make_tuple("updateRevocationRegistry",
                              &indyCredx::updateRevocationRegistry));
  fMap.insert(std::make_tuple("objectFree", &indyCredx::objectFree));

  return fMap;
}

jsi::Function TurboModuleHostObject::call(jsi::Runtime &rt, const char *name,
                                          Cb cb) {
  return jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, name), 1,
      [this, cb](jsi::Runtime &rt, const jsi::Value &thisValue,
                 const jsi::Value *arguments, size_t count) -> jsi::Value {
        const jsi::Value *val = &arguments[0];
        turboModuleUtility::assertValueIsObject(rt, val);
        return (*cb)(rt, val->getObject(rt));
      });
};

std::vector<jsi::PropNameID>
TurboModuleHostObject::getPropertyNames(jsi::Runtime &rt) {
  auto fMap = TurboModuleHostObject::functionMapping(rt);
  std::vector<jsi::PropNameID> result;
  for (FunctionMap::iterator it = fMap.begin(); it != fMap.end(); ++it) {
    result.push_back(jsi::PropNameID::forUtf8(rt, it->first));
  }

  return result;
}

jsi::Value TurboModuleHostObject::get(jsi::Runtime &rt,
                                      const jsi::PropNameID &propNameId) {
  auto propName = propNameId.utf8(rt);
  auto fMap = TurboModuleHostObject::functionMapping(rt);
  for (FunctionMap::iterator it = fMap.begin(); it != fMap.end(); ++it) {
    if (it->first == propName) {
      return TurboModuleHostObject::call(rt, it->first, it->second);
    }
  }

  /*
   * https://overreacted.io/why-do-react-elements-have-typeof-property/
   *
   * This is a special React key on the object that `React.createElement()`
   * returns.
   *
   * This function is called under-the-hood to see if this React element is
   * renderable.
   *
   * When we return undefined, instead of `Symbol.for('react.element'), we tell
   * React that this element is not renderable.
   *
   */
  if (propName == "$$typeof")
    return jsi::Value::undefined();

  throw jsi::JSError(rt, "Function: " + propName + " is not defined");
}
