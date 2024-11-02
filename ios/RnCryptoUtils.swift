import Foundation
import React
import Security
import CommonCrypto

@objc(RnCryptoUtils)
class RnCryptoUtils: NSObject {

  @objc(sha256:withResolver:withRejecter:)
  func sha256(a: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
    let msg = a.data(using: .utf8)!
    let result = msg.sha256().toHexString()
    resolve(result)
  }

  @objc(generateAESKey:resolver:rejecter:)
    func generateAESKey(keySize: NSNumber = 256, resolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
        let keySizeInt = keySize.intValue
        guard keySizeInt == 128 || keySizeInt == 192 || keySizeInt == 256 else {
            rejecter("INVALID_KEY_SIZE", "Key size must be 128, 192, or 256 bits.", nil)
            return
        }

        var keyData = Data(count: keySizeInt / 8)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, keyData.count, $0.baseAddress!)
        }

        if result == errSecSuccess {
            let base64Key = keyData.base64EncodedString()
            resolver(base64Key)
        } else {
            rejecter("KEY_GENERATION_FAILED", "Failed to generate AES key.", nil)
        }
    }

    // MARK: - AES Encryption

    @objc(aesEncrypt:encryptionKey:resolver:rejecter:)
    func aesEncrypt(plaintext: String, encryptionKey: String, resolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
        guard let keyData = Data(base64Encoded: encryptionKey) else {
            rejecter("INVALID_KEY", "Encryption key is not valid Base64.", nil)
            return
        }

        let ivSize = kCCBlockSizeAES128
        var iv = Data(count: ivSize)
        let ivResult = iv.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, ivSize, $0.baseAddress!)
        }

        if ivResult != errSecSuccess {
            rejecter("IV_GENERATION_FAILED", "Failed to generate IV.", nil)
            return
        }

        guard let plaintextData = plaintext.data(using: .utf8) else {
            rejecter("INVALID_PLAINTEXT", "Plaintext is not valid UTF-8.", nil)
            return
        }

        let encryptedData = crypt(operation: CCOperation(kCCEncrypt),
                                  data: plaintextData,
                                  key: keyData,
                                  iv: iv)

        switch encryptedData {
        case .success(let cipherData):
            let ivBase64 = iv.base64EncodedString()
            let encryptedBase64 = cipherData.base64EncodedString()
            let combined = "\(ivBase64):\(encryptedBase64)"
            resolver(combined)
        case .failure(let error):
            rejecter("ENCRYPTION_FAILED", error.localizedDescription, error)
        }
    }

    // MARK: - AES Decryption

    @objc(aesDecrypt:encryptionKey:resolver:rejecter:)
    func aesDecrypt(encryptedData: String, encryptionKey: String, resolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
        let components = encryptedData.split(separator: ":").map { String($0) }
        guard components.count == 2 else {
            rejecter("INVALID_FORMAT", "Invalid encrypted data format. Expected 'IV:ciphertext'", nil)
            return
        }

        let ivBase64 = components[0]
        let encryptedBase64 = components[1]

        guard let iv = Data(base64Encoded: ivBase64),
              let cipherData = Data(base64Encoded: encryptedBase64) else {
            rejecter("INVALID_BASE64", "IV or ciphertext is not valid Base64.", nil)
            return
        }

        guard let keyData = Data(base64Encoded: encryptionKey) else {
            rejecter("INVALID_KEY", "Encryption key is not valid Base64.", nil)
            return
        }

        let decryptedData = crypt(operation: CCOperation(kCCDecrypt),
                                  data: cipherData,
                                  key: keyData,
                                  iv: iv)

        switch decryptedData {
        case .success(let plainData):
            if let decryptedString = String(data: plainData, encoding: .utf8) {
                resolver(decryptedString)
            } else {
                rejecter("DECRYPTION_FAILED", "Failed to convert decrypted data to string.", nil)
            }
        case .failure(let error):
            rejecter("DECRYPTION_FAILED", error.localizedDescription, error)
        }
    }

    // MARK: - Helper Methods

    private enum CryptoError: Error {
        case cryptFailed(status: CCCryptorStatus)
    }

    private func crypt(operation: CCOperation, data: Data, key: Data, iv: Data) -> Result<Data, Error> {
        let keyLength = key.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        guard validKeyLengths.contains(keyLength) else {
            return .failure(CryptoError.cryptFailed(status: CCCryptorStatus(kCCParamError)))
        }

        let dataLength = data.count
        let cryptLength = dataLength + kCCBlockSizeAES128
        var cryptData = Data(count: cryptLength)

        var bytesProcessed: size_t = 0

        let status = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                iv.withUnsafeBytes { ivBytes in
                    key.withUnsafeBytes { keyBytes in
                        CCCrypt(operation,
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress, keyLength,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress, dataLength,
                                cryptBytes.baseAddress, cryptLength,
                                &bytesProcessed)
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            return .failure(CryptoError.cryptFailed(status: status))
        }

        cryptData.removeSubrange(bytesProcessed..<cryptData.count)
        return .success(cryptData)
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
