"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generateKeyPair = generateKeyPair;
exports.sha256 = sha256;
exports.signData = signData;
var _reactNative = require("react-native");
const LINKING_ERROR = `The package 'react-native-utils' doesn't seem to be linked. Make sure: \n\n` + _reactNative.Platform.select({
  ios: "- You have run 'pod install'\n",
  default: ''
}) + '- You rebuilt the app after installing the package\n' + '- You are not using Expo Go\n';
const Utils = _reactNative.NativeModules.Utils ? _reactNative.NativeModules.Utils : new Proxy({}, {
  get() {
    throw new Error(LINKING_ERROR);
  }
});
function sha256(a) {
  return Utils.sha256(a);
}
function generateKeyPair(length, algo) {
  return Utils.generateKeyPair(length, algo);
}
function signData(data, privateKey) {
  return Utils.signData(data, privateKey);
}
//# sourceMappingURL=index.js.map