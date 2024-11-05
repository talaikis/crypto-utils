#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RnCryptoUtils, NSObject)

// sha256 method
RCT_EXTERN_METHOD(sha256:(NSString *)input
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

// generateAESKey
RCT_EXTERN_METHOD(generateAESKey:(NSNumber *)keySize
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

// aesEncrypt
RCT_EXTERN_METHOD(aesEncrypt:(nonnull NSString *)plaintext
                  encryptionKey:(NSString *)encryptionKey
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

// aesDecrypt
RCT_EXTERN_METHOD(aesDecrypt:(nonnull NSString *)encryptedData
                  encryptionKey:(NSString *)encryptionKey
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

RCT_EXTERN_METHOD(getSecurityStatus:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
