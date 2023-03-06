#include <vector>

#include <turboModuleUtility.h>

namespace anoncredsTurboModuleUtility {

using byteVector = std::vector<uint8_t>;

std::shared_ptr<react::CallInvoker> invoker;

void registerTurboModule(jsi::Runtime &rt,
                         std::shared_ptr<react::CallInvoker> jsCallInvoker) {
  // Setting the callInvoker for async code
  invoker = jsCallInvoker;
  // Create a TurboModuleRustHostObject
  auto instance = std::make_shared<AnoncredsTurboModuleHostObject>(rt);
  // Create a JS equivalent object of the instance
  jsi::Object jsInstance = jsi::Object::createFromHostObject(rt, instance);
  // Register the object on global
  rt.global().setProperty(rt, "_anoncreds", std::move(jsInstance));
}

void assertValueIsObject(jsi::Runtime &rt, const jsi::Value *val) {
  val->asObject(rt);
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code,
                             nullptr_t value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    object.setProperty(rt, "value", jsi::Value::null());
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code,
                             const char **value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    auto isNullptr = value == nullptr || *value == nullptr;
    auto valueWithoutNullptr = isNullptr
                                   ? jsi::Value::null()
                                   : jsi::String::createFromAscii(rt, *value);
    object.setProperty(rt, "value", valueWithoutNullptr);
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code, int8_t *value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    auto valueWithoutNullptr =
        value == nullptr ? jsi::Value::null() : jsi::Value(rt, int(*value));
    object.setProperty(rt, "value", valueWithoutNullptr);
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code,
                             uint32_t *value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    auto valueWithoutNullptr =
        value == nullptr ? jsi::Value::null() : jsi::Value(rt, int(*value));
    object.setProperty(rt, "value", valueWithoutNullptr);
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code,
                             ObjectHandle *value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    auto valueWithoutNullptr =
        value == nullptr ? jsi::Value::null() : jsi::Value(rt, int(*value));
    object.setProperty(rt, "value", valueWithoutNullptr);
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code,
                             ByteBuffer *value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    auto valueWithoutNullptr =
        value == nullptr
            ? jsi::Value::null()
            : jsi::String::createFromUtf8(rt, value->data, value->len);
    object.setProperty(rt, "value", valueWithoutNullptr);
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code,
                             anoncreds::CredentialDefinitionReturn *value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    if (value == nullptr) {
      object.setProperty(rt, "value", jsi::Value::null());
    } else {
      object.setProperty(rt, "credentialDefinition",
                         int(value->credentialDefinition));
      object.setProperty(rt, "credentialDefinitionPrivate",
                         int(value->credentialDefinitionPrivate));
      object.setProperty(rt, "keyCorrectnessProof",
                         int(value->keyCorrectnessProof));
    }
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value createReturnValue(jsi::Runtime &rt, ErrorCode code,
                             anoncreds::CredentialRequestReturn *value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    if (value == nullptr) {
      object.setProperty(rt, "value", jsi::Value::null());
    } else {
      object.setProperty(rt, "credentialRequest",
                         int(value->credentialRequest));
      object.setProperty(rt, "credentialRequestMetadata",
                         int(value->credentialRequestMetadata));
    }
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
jsi::Value
createReturnValue(jsi::Runtime &rt, ErrorCode code,
                  anoncreds::RevocationRegistryDefinitionReturn *value) {
  auto object = jsi::Object(rt);

  if (code == ErrorCode::Success) {
    if (value == nullptr) {
      object.setProperty(rt, "value", jsi::Value::null());
    } else {
      object.setProperty(rt, "revocationRegistryDefinition",
                         int(value->revocationRegistryDefinition));
      object.setProperty(rt, "revocationRegistryDefinitionPrivate",
                         int(value->revocationRegistryDefinitionPrivate));
    }
  }

  object.setProperty(rt, "errorCode", int(code));

  return object;
}

template <>
uint8_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                   bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
int8_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                  bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
std::string jsiToValue<std::string>(jsi::Runtime &rt, jsi::Object &options,
                                    const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if ((value.isNull() || value.isUndefined()) && optional)
    return std::string();

  if (value.isString()) {
    auto x = value.asString(rt).utf8(rt);
    return x;
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "string");
}

template <>
int64_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                   bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
int32_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                   bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
std::vector<int32_t>
jsiToValue<std::vector<int32_t>>(jsi::Runtime &rt, jsi::Object &options,
                                 const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    std::vector<int32_t> vec = {};
    jsi::Array arr = value.asObject(rt).asArray(rt);
    size_t length = arr.length(rt);
    for (int i = 0; i < length; i++) {
      jsi::Value element = arr.getValueAtIndex(rt, i);
      if (element.isNumber()) {
        vec.push_back(element.asNumber());
      } else {
        throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
      }
    }
    return vec;
  }

  if (optional)
    return {};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
ObjectHandle jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                        const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt,
                     errorPrefix + name + errorInfix + "ObjectHandle.handle");
};

template <>
FfiCredentialEntry jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                              const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return FfiCredentialEntry{};

  if (value.isObject()) {
    jsi::Object valueAsObject = value.asObject(rt);
    auto credential = jsiToValue<ObjectHandle>(rt, valueAsObject, "credential");
    auto timestamp = jsiToValue<int32_t>(rt, valueAsObject, "timestamp");
    auto revocationState =
        jsiToValue<ObjectHandle>(rt, valueAsObject, "revocationState");

    return FfiCredentialEntry{.credential = credential,
                              .timestamp = timestamp,
                              .rev_state = revocationState};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "CredentialEntry");
};

template <>
FfiCredentialProve jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                              const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return FfiCredentialProve{};

  if (value.isObject()) {
    jsi::Object valueAsObject = value.asObject(rt);
    auto entryIndex = jsiToValue<int64_t>(rt, valueAsObject, "entryIndex");
    auto referent = jsiToValue<std::string>(rt, valueAsObject, "referent");
    auto isPredicate = jsiToValue<int8_t>(rt, valueAsObject, "isPredicate");
    auto reveal = jsiToValue<int8_t>(rt, valueAsObject, "reveal");

    return FfiCredentialProve{.entry_idx = entryIndex,
                              .is_predicate = isPredicate,
                              .referent = referent.c_str(),
                              .reveal = reveal};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "CredentialProve");
};

template <>
FfiList_FfiCredentialEntry
jsiToValue<FfiList_FfiCredentialEntry>(jsi::Runtime &rt, jsi::Object &options,
                                       const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto credentialEntry = new FfiCredentialEntry[arrayMaxSize];

    // TODO: error Handling
    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsObject = element.asObject(rt);

      auto credential =
          jsiToValue<ObjectHandle>(rt, valueAsObject, "credential");
      auto timestamp = jsiToValue<int32_t>(rt, valueAsObject, "timestamp");
      auto revocationState =
          jsiToValue<ObjectHandle>(rt, valueAsObject, "revocationState");

      credentialEntry[i] = *new FfiCredentialEntry[sizeof(FfiCredentialEntry)];
      credentialEntry[i] = FfiCredentialEntry{.credential = credential,
                                              .timestamp = timestamp,
                                              .rev_state = revocationState};
    }

    return FfiList_FfiCredentialEntry{.count = len, .data = credentialEntry};
  }

  if (optional)
    return FfiList_FfiCredentialEntry{};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiList_FfiCredentialProve
jsiToValue<FfiList_FfiCredentialProve>(jsi::Runtime &rt, jsi::Object &options,
                                       const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto credentialProve = new FfiCredentialProve[len];

    // TODO: error Handling
    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsObject = element.asObject(rt);

      auto entryIndex = jsiToValue<int64_t>(rt, valueAsObject, "entryIndex");
      auto referent = jsiToValue<std::string>(rt, valueAsObject, "referent");
      auto isPredicate = jsiToValue<int8_t>(rt, valueAsObject, "isPredicate");
      auto reveal = jsiToValue<int8_t>(rt, valueAsObject, "reveal");

      credentialProve[i] = *new FfiCredentialProve[sizeof(FfiCredentialProve)];
      credentialProve[i] = FfiCredentialProve{.entry_idx = entryIndex,
                                              .is_predicate = isPredicate,
                                              .referent = referent.c_str(),
                                              .reveal = reveal};
    }
    return FfiList_FfiCredentialProve{.count = len, .data = credentialProve};
  }

  if (optional)
    return FfiList_FfiCredentialProve{};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiList_ObjectHandle
jsiToValue<FfiList_ObjectHandle>(jsi::Runtime &rt, jsi::Object &options,
                                 const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto objectHandle = new ObjectHandle[arrayMaxSize];

    // TODO: error Handling
    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsNumber = element.asNumber();

      objectHandle[i] = *new size_t[sizeof(valueAsNumber)];
      objectHandle[i] = size_t(valueAsNumber);
    }
    return FfiList_ObjectHandle{.count = len, .data = objectHandle};
  }

  if (optional)
    return FfiList_ObjectHandle{};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiList_FfiStr jsiToValue<FfiList_FfiStr>(jsi::Runtime &rt,
                                          jsi::Object &options,
                                          const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    char **ffiStr = new char *[len];

    for (int i = 0; i < len; i++) {
      // TODO: check if string first
      jsi::Value element = arr.getValueAtIndex(rt, i);
      std::string s = element.asString(rt).utf8(rt);
      ffiStr[i] = new char[sizeof(s)];
      strcpy(ffiStr[i], s.c_str());
    }

    return FfiList_FfiStr{.count = len, .data = ffiStr};
  }

  if (optional) {
    return FfiList_FfiStr{};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<string>");
}

template <>
FfiList_i32 jsiToValue<FfiList_i32>(jsi::Runtime &rt, jsi::Object &options,
                                    const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto num = new int32_t[arrayMaxSize];

    // TODO: error Handling
    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsNumber = element.asNumber();

      num[i] = *new int32_t[sizeof(valueAsNumber)];
      num[i] = int32_t(valueAsNumber);
    }

    return FfiList_i32{.count = len, .data = num};
  }

  if (optional)
    return FfiList_i32{};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiCredRevInfo jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                          const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return FfiCredRevInfo{};

  if (value.isObject()) {
    jsi::Object valueAsObject = value.asObject(rt);
    auto registryDefinition =
        jsiToValue<ObjectHandle>(rt, valueAsObject, "registryDefinition");
    auto registryDefinitionPrivate = jsiToValue<ObjectHandle>(
        rt, valueAsObject, "registryDefinitionPrivate");
    auto registryIndex =
        jsiToValue<int64_t>(rt, valueAsObject, "registryIndex");
    auto tailsPath = jsiToValue<std::string>(rt, valueAsObject, "tailsPath");

    return FfiCredRevInfo{.reg_def = registryDefinition,
                          .reg_def_private = registryDefinitionPrivate,
                          .reg_idx = registryIndex,
                          .tails_path = tailsPath.c_str()};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix +
                             "CredentialRevocationConfig");
};

template <>
FfiList_FfiNonrevokedIntervalOverride
jsiToValue<FfiList_FfiNonrevokedIntervalOverride>(jsi::Runtime &rt,
                                                  jsi::Object &options,
                                                  const char *name,
                                                  bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto nonRevokedIntervalOverride = new FfiNonrevokedIntervalOverride[len];

    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsObject = element.asObject(rt);

      auto revocationRegistryDefinitionId = jsiToValue<std::string>(
          rt, valueAsObject, "revocationRegistryDefinitionId");
      auto requestedFromTimestamp =
          jsiToValue<int32_t>(rt, valueAsObject, "requestedFromTimestamp");
      auto overrideRevocationStatusListTimestamp = jsiToValue<int32_t>(
          rt, valueAsObject, "overrideRevocationStatusListTimestamp");

      nonRevokedIntervalOverride[i] = *new FfiNonrevokedIntervalOverride[sizeof(
          FfiNonrevokedIntervalOverride)];
      nonRevokedIntervalOverride[i] = FfiNonrevokedIntervalOverride{
          .rev_reg_def_id = revocationRegistryDefinitionId.c_str(),
          .requested_from_ts = requestedFromTimestamp,
          .override_rev_status_list_ts = overrideRevocationStatusListTimestamp};
    }
    return FfiList_FfiNonrevokedIntervalOverride{
        .count = len, .data = nonRevokedIntervalOverride};
  }

  if (optional)
    return FfiList_FfiNonrevokedIntervalOverride{};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix +
                             "Array<NonRevokedIntervalOverride>");
}

} // namespace anoncredsTurboModuleUtility
