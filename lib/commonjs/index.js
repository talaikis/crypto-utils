"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.aesDecrypt = aesDecrypt;
exports.aesEncrypt = aesEncrypt;
exports.clearCache = clearCache;
exports.generateAESKey = generateAESKey;
exports.generateKeyPair = generateKeyPair;
exports.getSecurityStatus = getSecurityStatus;
exports.sha256 = sha256;
exports.signData = signData;
var _reactNative = require("react-native");
const LINKING_ERROR = 'The package \'react-native-utils\' doesn\'t seem to be linked. Make sure: \n\n' + _reactNative.Platform.select({
  ios: "- You have run 'pod install'\n",
  default: ''
}) + '- You rebuilt the app after installing the package\n' + '- You are not using Expo Go\n';
const Utils = _reactNative.NativeModules.Utils ? _reactNative.NativeModules.Utils : new Proxy({}, {
  get() {
    throw new Error(LINKING_ERROR);
  }
});
async function sha256(a) {
  return await Utils.sha256(a);
}
async function generateKeyPair(length, algorithm) {
  const result = await Utils.generateKeyPair(length, algorithm);
  return JSON.parse(result);
}
async function signData(data, privateKey) {
  return await Utils.signData(data, privateKey);
}
async function generateAESKey(keySize) {
  return await Utils.generateAESKey(keySize);
}
async function aesEncrypt(plaintext, key) {
  return await Utils.aesEncrypt(plaintext, key);
}
async function aesDecrypt(encryptedData, key) {
  return await Utils.aesDecrypt(encryptedData, key);
}
async function getSecurityStatus() {
  return await Utils.getSecurityStatus();
}
async function clearCache() {
  if (_reactNative.Platform.OS === 'android') {
    await Utils.clearInternalCache();
  }
}
//# sourceMappingURL=index.js.map