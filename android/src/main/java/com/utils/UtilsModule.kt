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

    companion object {
        const val NAME = "Utils"
    }
}
