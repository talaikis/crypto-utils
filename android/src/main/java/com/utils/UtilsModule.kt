package com.talaikis.utils

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import java.security.MessageDigest
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import org.json.JSONObject
import java.util.Base64
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

class UtilsModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String {
        return NAME
    }

    @ReactMethod
    fun sha256(input: String, promise: Promise) {
        try {
            val byteArray = input.toByteArray()
            val digest = MessageDigest.getInstance("SHA-256")
            val hashBytes = digest.digest(byteArray)
            val hashHexString = hashBytes.joinToString("") { "%02x".format(it) }
            promise.resolve(hashHexString)
        } catch (e: Exception) {
            promise.reject("SHA256_ERROR", e)
        }
    }

    private fun reconstructPrivateKey(keyStr: String): PrivateKey {
        val keyBytes = Base64.getDecoder().decode(keyStr)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = java.security.KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec)
    }

    private fun reconstructPublicKey(keyStr: String): PublicKey {
        val keyBytes = Base64.getDecoder().decode(keyStr)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = java.security.KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec)
    }

    /*
    Supported Algorithms:
    - RSA
    * Other algorithms like Ed25519, DSA, DH, EC are listed but not implemented.
    */
    @ReactMethod
    fun generateKeyPair(length: Int, algo: String, promise: Promise) {
        try {
            val keyPairGen = KeyPairGenerator.getInstance(algo)
            keyPairGen.initialize(length)
            val pair: KeyPair = keyPairGen.generateKeyPair()
            val privateKey: PrivateKey = pair.private
            val publicKey: PublicKey = pair.public

            val privateKeyBase64: String = Base64.getEncoder().encodeToString(privateKey.encoded)
            val publicKeyBase64: String = Base64.getEncoder().encodeToString(publicKey.encoded)

            val json = JSONObject().apply {
                put("privateKey", privateKeyBase64)
                put("publicKey", publicKeyBase64)
            }

            promise.resolve(json.toString())
        } catch (e: Exception) {
            promise.reject("GENERATE_KEYPAIR_ERROR", e)
        }
    }

    // Only RSA is supported for signing
    @ReactMethod
    fun signData(data: String, privateKeyString: String, promise: Promise) {
        try {
            val byteArray = data.toByteArray()
            val signature = Signature.getInstance("SHA256withRSA")
            val privateKey = reconstructPrivateKey(privateKeyString)
            signature.initSign(privateKey)
            signature.update(byteArray)
            val digitalSignature = signature.sign()
            val digitalSignatureBase64 = Base64.getEncoder().encodeToString(digitalSignature)
            promise.resolve(digitalSignatureBase64)
        } catch (e: Exception) {
            promise.reject("SIGN_DATA_ERROR", e)
        }
    }

    @ReactMethod
    fun generateAESKey(keySize: Int = 256, promise: Promise): String {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(keySize, SecureRandom())
        return promise.resolve(encodeKeyToBase64(keyGen.generateKey()))
    }

    private fun encodeKeyToBase64(key: SecretKey): String {
        return Base64.getEncoder().encodeToString(key.encoded)
    }

    private fun decodeKeyFromBase64(base64Key: String): SecretKey {
        val decodedKey = Base64.getDecoder().decode(base64Key)
        return javax.crypto.spec.SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")
    }

    @ReactMethod
    fun aesEncrypt(plaintext: String, encryptionKey: String, promise: Promise) {
        val key = decodeKeyFromBase64(encryptionKey)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = ByteArray(cipher.blockSize)
        SecureRandom().nextBytes(iv)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val ivBase64 = Base64.getEncoder().encodeToString(iv)
        val encryptedBase64 = Base64.getEncoder().encodeToString(encrypted)
        return promise.resolve("$ivBase64:$encryptedBase64"))
    }

    @ReactMethod
    fun aesDecrypt(encryptedData: String, encryptionKey: String, promise: Promise) {
        val key = decodeKeyFromBase64(encryptionKey)
        val parts = encryptedData.split(":")
        if (parts.size != 2) {
            throw IllegalArgumentException("Invalid encrypted data format. Expected 'IV:ciphertext'")
        }

        val ivBase64 = parts[0]
        val encryptedBase64 = parts[1]
        val iv = Base64.getDecoder().decode(ivBase64)
        val encryptedBytes = Base64.getDecoder().decode(encryptedBase64)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return promise.resolve(String(decryptedBytes, Charsets.UTF_8))
    }

    companion object {
        const val NAME = "Utils"
    }
}
