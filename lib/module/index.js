"use strict";

import { NativeModules, Platform } from 'react-native';
const LINKING_ERROR = `The package 'rn-crypto-utils' doesn't seem to be linked. Make sure: \n\n` + Platform.select({
  ios: "- You have run 'pod install'\n",
  default: ''
}) + '- You rebuilt the app after installing the package\n' + '- You are not using Expo Go\n';
const RnCryptoUtils = NativeModules.RnCryptoUtils ? NativeModules.RnCryptoUtils : new Proxy({}, {
  get() {
    throw new Error(LINKING_ERROR);
  }
});
export async function clearCache() {
  if (Platform.OS === 'android') {
    await RnCryptoUtils.clearInternalCache();
  }
}
export async function sha256(a) {
  return await RnCryptoUtils.sha256(a);
}
export async function generateKeyPair(length, algorithm) {
  const result = await RnCryptoUtils.generateKeyPair(length, algorithm);
  return JSON.parse(result);
}
export async function signData(data, privateKey) {
  return await RnCryptoUtils.signData(data, privateKey);
}
export async function generateAESKey(keySize) {
  return await RnCryptoUtils.generateAESKey(keySize);
}
export async function aesEncrypt(plaintext, key) {
  return await RnCryptoUtils.aesEncrypt(plaintext, key);
}
export async function aesDecrypt(encryptedData, key) {
  return await RnCryptoUtils.aesDecrypt(encryptedData, key);
}
//# sourceMappingURL=index.js.map