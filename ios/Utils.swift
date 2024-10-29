import Foundation
import React
import Security

@objc(Utils)
class Utils: NSObject {

  @objc(sha256:withResolver:withRejecter:)
  func sha256(a: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
    let msg = a.data(using: .utf8)!
    let result = msg.sha256().toHexString()
    resolve(result)
  }

  @objc
    func generateKeyPair(_ length: NSNumber, algo: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        do {
            // Determine the key type based on the algo string
            guard let keyType = keyType(from: algo) else {
                reject("INVALID_ALGORITHM", "Unsupported algorithm: \(algo)", nil)
                return
            }

            // Define key pair generation parameters
            let keyPairAttr: [String: Any] = [
                kSecAttrKeyType as String: keyType,
                kSecAttrKeySizeInBits as String: length.intValue,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false
                ],
                kSecPublicKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false
                ]
            ]

            // Generate the key pair
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(keyPairAttr as CFDictionary, &error) else {
                let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error during key generation."
                reject("KEY_GENERATION_FAILED", errorMessage, error?.takeRetainedValue())
                return
            }

            // Extract the public key from the private key
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                reject("PUBLIC_KEY_EXTRACTION_FAILED", "Failed to extract public key from the private key.", nil)
                return
            }

            // Export keys to DER-encoded Data
            guard let privateKeyData = exportPrivateKey(privateKey) else {
                reject("PRIVATE_KEY_EXPORT_FAILED", "Failed to export the private key.", nil)
                return
            }

            guard let publicKeyData = exportPublicKey(publicKey) else {
                reject("PUBLIC_KEY_EXPORT_FAILED", "Failed to export the public key.", nil)
                return
            }

            // Encode keys to Base64
            let privateKeyBase64 = privateKeyData.base64EncodedString()
            let publicKeyBase64 = publicKeyData.base64EncodedString()

            // Create JSON object with keys
            let json: [String: String] = [
                "privateKey": privateKeyBase64,
                "publicKey": publicKeyBase64
            ]

            // Serialize JSON to string
            let jsonData = try JSONSerialization.data(withJSONObject: json, options: [])
            guard let jsonString = String(data: jsonData, encoding: .utf8) else {
                reject("JSON_SERIALIZATION_FAILED", "Failed to serialize JSON.", nil)
                return
            }

            // Resolve the promise with the JSON string
            resolve(jsonString)
        } catch let error {
            // Reject the promise with the error
            reject("GENERATE_KEYPAIR_ERROR", error.localizedDescription, error)
        }
    }

    // Helper method to map algorithm string to SecKeyType
    private func keyType(from algo: String) -> CFString? {
        switch algo.uppercased() {
        case "RSA":
            return kSecAttrKeyTypeRSA
        case "EC", "ECDSA":
            return kSecAttrKeyTypeECSECPrimeRandom
        default:
            return nil
        }
    }

    // Helper method to export private key to DER-encoded Data
    private func exportPrivateKey(_ privateKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            print("Error exporting private key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return nil
        }
        return privateKeyData
    }

    // Helper method to export public key to DER-encoded Data
    private func exportPublicKey(_ publicKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            print("Error exporting public key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return nil
        }
        return publicKeyData
    }

  @objc
  func signData(_ data: String, privateKeyString: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
        // Convert data string to Data
        guard let dataToSign = data.data(using: .utf8) else {
            reject("INVALID_DATA", "Failed to convert data to UTF-8.", nil)
            return
        }

        // Reconstruct the Private Key
        guard let privateKey = try reconstructPrivateKey(from: privateKeyString) else {
            reject("INVALID_PRIVATE_KEY", "Failed to reconstruct the private key.", nil)
            return
        }

        // Sign the data
        guard let signature = try sign(data: dataToSign, with: privateKey) else {
            reject("SIGNING_FAILED", "Failed to sign the data.", nil)
            return
        }

        // Encode signature to Base64
        let signatureBase64 = signature.base64EncodedString()

        // Resolve the promise with the signature
        resolve(signatureBase64)
    } catch let error {
        // Reject the promise with the error
        reject("SIGN_DATA_ERROR", error.localizedDescription, error)
    }
  }

  // Helper method to reconstruct Private Key from Base64 string
    private func reconstructPrivateKey(from base64Key: String) throws -> SecKey? {
        // Remove PEM headers/footers if present
        let keyString = base64Key
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")

        // Decode the Base64 string to Data
        guard let keyData = Data(base64Encoded: keyString) else {
            throw NSError(domain: "INVALID_KEY_ENCODING", code: -1, userInfo: nil)
        }

        // Define the key attributes
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:            kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String:           kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String:      2048,
            kSecReturnPersistentRef as String:    true
        ]

        // Create the SecKey from the key data
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                               attributes as CFDictionary,
                                               &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "SEC_KEY_CREATION_FAILED", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMessage])
        }

        return secKey
    }

    // Helper method to sign data using the private key
    private func sign(data: Data, with privateKey: SecKey) throws -> Data? {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256

        // Check if the algorithm is supported
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw NSError(domain: "UNSUPPORTED_ALGORITHM", code: -1, userInfo: nil)
        }

        var error: Unmanaged<CFError>?

        // Perform the signing
        guard let signature = SecKeyCreateSignature(privateKey,
                                                    algorithm,
                                                    data as CFData,
                                                    &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown signing error"
            throw NSError(domain: "SIGNING_FAILED", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMessage])
        }

        return signature
    }

}
