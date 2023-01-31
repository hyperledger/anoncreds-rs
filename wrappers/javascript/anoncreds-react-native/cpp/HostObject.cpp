#include <HostObject.h>
#include <algorithm>
#include <vector>

TurboModuleHostObject::TurboModuleHostObject(jsi::Runtime &rt) { return; }

FunctionMap TurboModuleHostObject::functionMapping(jsi::Runtime &rt) {
  FunctionMap fMap;

  fMap.insert(std::make_tuple("version", &anoncreds::version));
  fMap.insert(std::make_tuple("getCurrentError", &anoncreds::getCurrentError));
  fMap.insert(
      std::make_tuple("createCredential", &anoncreds::createCredential));
  fMap.insert(std::make_tuple("createCredentialDefinition",
                              &anoncreds::createCredentialDefinition));
  fMap.insert(std::make_tuple("createCredentialOffer",
                              &anoncreds::createCredentialOffer));
  fMap.insert(std::make_tuple("createCredentialRequest",
                              &anoncreds::createCredentialRequest));
  fMap.insert(
      std::make_tuple("createMasterSecret", &anoncreds::createMasterSecret));
  fMap.insert(std::make_tuple("createOrUpdateRevocationState",
                              &anoncreds::createOrUpdateRevocationState));
  fMap.insert(
      std::make_tuple("createPresentation", &anoncreds::createPresentation));
  fMap.insert(std::make_tuple("createRevocationRegistryDefinition",
                              &anoncreds::createRevocationRegistryDefinition));
  fMap.insert(std::make_tuple("createSchema", &anoncreds::createSchema));
  fMap.insert(std::make_tuple("credentialGetAttribute",
                              &anoncreds::credentialGetAttribute));
  fMap.insert(std::make_tuple("encodeCredentialAttributes",
                              &anoncreds::encodeCredentialAttributes));
  fMap.insert(std::make_tuple("generateNonce", &anoncreds::generateNonce));
  fMap.insert(std::make_tuple("getJson", &anoncreds::getJson));
  fMap.insert(std::make_tuple("getTypeName", &anoncreds::getTypeName));
  fMap.insert(
      std::make_tuple("processCredential", &anoncreds::processCredential));
  fMap.insert(
      std::make_tuple("revocationRegistryDefinitionGetAttribute",
                      &anoncreds::revocationRegistryDefinitionGetAttribute));
  fMap.insert(
      std::make_tuple("setDefaultLogger", &anoncreds::setDefaultLogger));
  fMap.insert(
      std::make_tuple("verifyPresentation", &anoncreds::verifyPresentation));
  fMap.insert(std::make_tuple("updateRevocationStatusList",
                              &anoncreds::updateRevocationStatusList));
  fMap.insert(std::make_tuple("objectFree", &anoncreds::objectFree));

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
