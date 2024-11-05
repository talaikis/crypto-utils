"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.aesDecrypt = aesDecrypt;
exports.aesEncrypt = aesEncrypt;
exports.generateAESKey = generateAESKey;
exports.generateKeyPair = generateKeyPair;
exports.sha256 = sha256;
exports.signData = signData;
var _reactNative = require("react-native");
const LINKING_ERROR = `The package 'rn-crypto-utils' doesn't seem to be linked. Make sure: \n\n` + _reactNative.Platform.select({
  ios: "- You have run 'pod install'\n",
  default: ''
}) + '- You rebuilt the app after installing the package\n' + '- You are not using Expo Go\n';
const RnCryptoUtils = _reactNative.NativeModules.RnCryptoUtils ? _reactNative.NativeModules.RnCryptoUtils : new Proxy({}, {
  get() {
    throw new Error(LINKING_ERROR);
  }
});
async function sha256(a) {
  return await RnCryptoUtils.sha256(a);
}
async function generateKeyPair(length, algorithm) {
  const result = await RnCryptoUtils.generateKeyPair(length, algorithm);
  return JSON.parse(result);
}
async function signData(data, privateKey) {
  return await RnCryptoUtils.signData(data, privateKey);
}
async function generateAESKey(keySize) {
  return await RnCryptoUtils.generateAESKey(keySize);
}
async function aesEncrypt(plaintext, key) {
  return await RnCryptoUtils.aesEncrypt(plaintext, key);
}
async function aesDecrypt(encryptedData, key) {
  return await RnCryptoUtils.aesDecrypt(encryptedData, key);
}
//# sourceMappingURL=index.js.map