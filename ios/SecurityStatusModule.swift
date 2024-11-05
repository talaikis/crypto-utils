import Foundation
import LocalAuthentication
import React

@objc(SecurityStatus)
class SecurityStatus: NSObject, RCTBridgeModule {
  
  static func moduleName() -> String {
    return "SecurityStatus"
  }
  
  @objc
  func getSecurityStatus(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    let context = LAContext()
    var authError: NSError?
    
    // Check if device has a passcode set
    let passcodeSet = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError)
    
    // Check biometrics
    let biometricsEnabled: Bool
    switch context.biometryType {
    case .faceID, .touchID:
      biometricsEnabled = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError)
    default:
      biometricsEnabled = false
    }
    
    let status: [String: Any] = [
      "isPasscodeEnabled": passcodeSet,
      "isBiometricsEnabled": biometricsEnabled
    ]
    
    resolve(status)
  }
  
  @objc
  static func requiresMainQueueSetup() -> Bool {
    return true
  }
}
