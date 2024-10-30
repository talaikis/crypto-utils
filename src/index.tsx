import { NativeModules, Platform } from 'react-native'

const LINKING_ERROR =
  'The package \'react-native-utils\' doesn\'t seem to be linked. Make sure: \n\n' +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n'

const Utils = NativeModules.Utils
  ? NativeModules.Utils
  : new Proxy(
    {},
    {
      get () {
        throw new Error(LINKING_ERROR)
      }
    }
  )

export function sha256 (a: string): Promise<string> {
  return Utils.sha256(a)
}

export function generateKeyPair (length: number, algorithm: string): Promise<string> {
  return JSON.parse(Utils.generateKeyPair(length, algorithm))
}

export function signData (data: string, privateKey: string): Promise<string> {
  return Utils.signData(data, privateKey)
}
