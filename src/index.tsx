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

export async function sha256 (a: string): Promise<string> {
  return await Utils.sha256(a)
}

export async function generateKeyPair (length: number, algorithm: string): Promise<any> {
  const result = await Utils.generateKeyPair(length, algorithm)
  return JSON.parse(result)
}

export async function signData (data: string, privateKey: string): Promise<string> {
  return await Utils.signData(data, privateKey)
}

export async function generateAESKey (keySize: Number): Promise<string> {
  return await Utils.generateAESKey(keySize)
}

export async function aesEncrypt (plaintext: String, key: String): Promise<string> {
  return await Utils.aesEncrypt(plaintext, key)
}

export async function aesDecrypt (encryptedData: String, key: String): Promise<string> {
  return await Utils.aesDecrypt(encryptedData, key)
}

export async function getSecurityStatus () {
  return await Utils.getSecurityStatus()
}

export async function clearCache (): Promise<any> {
  if (Platform.OS === 'android') {
    await Utils.clearInternalCache()
  }
}

export const fileExists = async (path: String): Promise<any> => {
  if (Platform.OS === 'android') {
    const exists = await Utils.fileExists(path)
    return exists
  }
}
