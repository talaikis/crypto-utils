#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(Utils, NSObject)

// sha256 method
RCT_EXTERN_METHOD(sha256:(NSString *)input
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

// generateKeyPair method
RCT_EXTERN_METHOD(generateKeyPair:(nonnull NSNumber *)length
                  algo:(NSString *)algo
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

// signData method
RCT_EXTERN_METHOD(signData:(NSString *)data
                  privateKeyString:(NSString *)privateKeyString
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
