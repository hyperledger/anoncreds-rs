#import <React/RCTBridge+Private.h>
#import <jsi/jsi.h>
#import <React/RCTUtils.h>
#import <ReactCommon/RCTTurboModule.h>

#import "turboModuleUtility.h"
#import "Anoncreds.h"

using namespace facebook;

@implementation Anoncreds

RCT_EXPORT_MODULE()

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install)
{
    RCTBridge* bridge = [RCTBridge currentBridge];
    RCTCxxBridge* cxxBridge = (RCTCxxBridge*)bridge;
    if (cxxBridge == nil) {
        return @false;
    }
    
    jsi::Runtime* jsiRuntime = (jsi::Runtime*) cxxBridge.runtime;
    if (jsiRuntime == nil) {
        return @false;
    }
    
    auto callInvoker = bridge.jsCallInvoker;
    anoncredsTurboModuleUtility::registerTurboModule(*jsiRuntime, callInvoker);
    return @true;
}

@end
