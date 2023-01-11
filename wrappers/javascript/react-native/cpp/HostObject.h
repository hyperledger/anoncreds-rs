#pragma once

#include <jsi/jsi.h>

#include <map>

#include <indyCredx.h>
#include <turboModuleUtility.h>

using namespace facebook;

typedef jsi::Value (*Cb)(jsi::Runtime &rt, jsi::Object options);
typedef std::map<const char *, Cb> FunctionMap;

class JSI_EXPORT TurboModuleHostObject : public jsi::HostObject {
public:
  TurboModuleHostObject(jsi::Runtime &rt);
  jsi::Function call(jsi::Runtime &rt, const char *name, Cb cb);
  FunctionMap functionMapping(jsi::Runtime &rt);

public:
  jsi::Value get(jsi::Runtime &rt, const jsi::PropNameID &name) override;
  std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime &rt) override;
};
