#include <vector>

#include <turboModuleUtility.h>



namespace turboModuleUtility {

using byteVector = std::vector<uint8_t>;

std::shared_ptr<react::CallInvoker> invoker;

void registerTurboModule(jsi::Runtime &rt,
                         std::shared_ptr<react::CallInvoker> jsCallInvoker) {
  // Setting the callInvoker for async code
  invoker = jsCallInvoker;
  // Create a TurboModuleRustHostObject
  auto instance = std::make_shared<TurboModuleHostObject>(rt);
  // Create a JS equivalent object of the instance
  jsi::Object jsInstance = jsi::Object::createFromHostObject(rt, instance);
  // Register the object on global
  rt.global().setProperty(rt, "_indy_credx", std::move(jsInstance));
}

void assertValueIsObject(jsi::Runtime &rt, const jsi::Value *val) {
  val->asObject(rt);
}
void handleError(jsi::Runtime &rt, ErrorCode code) {
  if (code == ErrorCode::Success)
    return;

  jsi::Value errorMessage = indyCredx::getCurrentError(rt, jsi::Object(rt));

  jsi::Object JSON = rt.global().getPropertyAsObject(rt, "JSON");
  jsi::Function JSONParse = JSON.getPropertyAsFunction(rt, "parse");
  jsi::Object parsedErrorObject =
      JSONParse.call(rt, errorMessage).getObject(rt);
  jsi::Value message = parsedErrorObject.getProperty(rt, "message");
  if (message.isString()) {
    throw jsi::JSError(rt, message.getString(rt).utf8(rt));
  }
  throw jsi::JSError(rt, "Could not get message with code: " +
                             std::to_string(code));
};

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
uint64_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
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
uint32_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
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
FfiRevocationEntry jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                              const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return FfiRevocationEntry{};

  if (value.isObject()) {
    jsi::Object valueAsObject = value.asObject(rt);
    auto revocationRegistryDefinitionIndex = jsiToValue<int64_t>(
        rt, valueAsObject, "revocationRegistryDefinitionIndex");
    auto entry = jsiToValue<ObjectHandle>(rt, valueAsObject, "entry");
    auto timestamp = jsiToValue<int64_t>(rt, valueAsObject, "timestamp");

    return FfiRevocationEntry{.timestamp = timestamp,
                              .def_entry_idx =
                                  revocationRegistryDefinitionIndex,
                              .entry = entry};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "RevocationEntry");
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
    auto timestamp = jsiToValue<int64_t>(rt, valueAsObject, "timestamp");
    auto revocationState =
        jsiToValue<ObjectHandle>(rt, valueAsObject, "revocationState");

    return FfiCredentialEntry{.credential = credential,
                              .timestamp = timestamp,
                              .rev_state = revocationState};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix +
                             "CredentialEntry");
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

  throw jsi::JSError(rt, errorPrefix + name + errorInfix +
                             "CredentialProve");
};

template <>
FfiList_FfiRevocationEntry
jsiToValue<FfiList_FfiRevocationEntry>(jsi::Runtime &rt, jsi::Object &options, const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto revocationEntry = new FfiRevocationEntry[arrayMaxSize];
      
    // TODO: error Handling
    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsObject = element.asObject(rt);
        
      auto revocationRegistryDefinitionIndex = jsiToValue<int64_t>(rt, valueAsObject, "revocationRegistryDefinitionIndex");
      auto entry = jsiToValue<ObjectHandle>(rt, valueAsObject, "entry");
      auto timestamp = jsiToValue<int64_t>(rt, valueAsObject, "timestamp");
        
      revocationEntry[i] = *new FfiRevocationEntry[sizeof(FfiRevocationEntry)];
      revocationEntry[i] = FfiRevocationEntry {.timestamp=timestamp, .entry=entry, .def_entry_idx=revocationRegistryDefinitionIndex};
    }
    return FfiList_FfiRevocationEntry {.count=len, .data=revocationEntry};
  }

  if (optional)
      return FfiList_FfiRevocationEntry {};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiList_FfiCredentialEntry
jsiToValue<FfiList_FfiCredentialEntry>(jsi::Runtime &rt, jsi::Object &options, const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto credentialEntry = new FfiCredentialEntry[arrayMaxSize];
      
    // TODO: error Handling
    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsObject = element.asObject(rt);
        
        auto credential = jsiToValue<ObjectHandle>(rt, valueAsObject, "credential");
        auto timestamp = jsiToValue<int64_t>(rt, valueAsObject, "timestamp");
        auto revocationState =
            jsiToValue<ObjectHandle>(rt, valueAsObject, "revocationState");

        credentialEntry[i] = *new FfiCredentialEntry[sizeof(FfiCredentialEntry)];
        credentialEntry[i] =  FfiCredentialEntry{.credential = credential,
                                  .timestamp = timestamp,
                                  .rev_state = revocationState};
    }
    
      return FfiList_FfiCredentialEntry {.count=len, .data=credentialEntry};
  }

  if (optional)
      return FfiList_FfiCredentialEntry {};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiList_FfiCredentialProve
jsiToValue<FfiList_FfiCredentialProve>(jsi::Runtime &rt, jsi::Object &options, const char *name, bool optional) {
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
    return FfiList_FfiCredentialProve {.count=len, .data=credentialProve};
  }

  if (optional)
      return FfiList_FfiCredentialProve {};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiList_ObjectHandle
jsiToValue<FfiList_ObjectHandle>(jsi::Runtime &rt, jsi::Object &options, const char *name, bool optional) {
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
      return FfiList_ObjectHandle {.count=len, .data=objectHandle};
  }

  if (optional)
      return FfiList_ObjectHandle {};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
FfiList_FfiStr
jsiToValue<FfiList_FfiStr>(jsi::Runtime &rt, jsi::Object &options, const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    char** ffiStr = new char*[len];
    
    for (int i = 0; i < len; i++) {
      // TODO: check if string first
      jsi::Value element = arr.getValueAtIndex(rt, i);
      std::string s = element.asString(rt).utf8(rt);
      ffiStr[i] = new char[sizeof(s)];
      strcpy(ffiStr[i], s.c_str());
    }
    
    return FfiList_FfiStr {.count=len, .data=ffiStr};
  }

  if (optional) {
      return FfiList_FfiStr {};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<string>");
}

template <>
FfiList_i64
jsiToValue<FfiList_i64>(jsi::Runtime &rt, jsi::Object &options, const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    auto arr = value.asObject(rt).asArray(rt);
    auto len = arr.length(rt);

    auto num = new int64_t[arrayMaxSize];
      
    // TODO: error Handling
    for (int i = 0; i < len; i++) {
      auto element = arr.getValueAtIndex(rt, i);
      auto valueAsNumber = element.asNumber();

      num[i] = *new int64_t[sizeof(valueAsNumber)];
      num[i] = int64_t(valueAsNumber);
    }
      
    return FfiList_i64 {.count=len, .data=num};
  }

  if (optional)
      return FfiList_i64 {};

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
    auto registry = jsiToValue<ObjectHandle>(rt, valueAsObject, "registry");
    auto registryIndex =
        jsiToValue<int64_t>(rt, valueAsObject, "registryIndex");
    auto registryUsed =
        jsiToValue<FfiList_i64>(rt, valueAsObject, "registryUsed", true);
    auto tailsPath = jsiToValue<std::string>(rt, valueAsObject, "tailsPath");

    return FfiCredRevInfo{.reg_def = registryDefinition,
                          .reg_def_private = registryDefinitionPrivate,
                          .registry = registry,
                          .reg_idx = registryIndex,
                          .tails_path = tailsPath.c_str(),
                          .reg_used = registryUsed};
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix +
                             "CredentialRevocationConfig");
};

} // namespace turboModuleUtility
