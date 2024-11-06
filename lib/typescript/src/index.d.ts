export declare function sha256(a: string): Promise<string>;
export declare function generateKeyPair(length: number, algorithm: string): Promise<any>;
export declare function signData(data: string, privateKey: string): Promise<string>;
export declare function generateAESKey(keySize: Number): Promise<string>;
export declare function aesEncrypt(plaintext: String, key: String): Promise<string>;
export declare function aesDecrypt(encryptedData: String, key: String): Promise<string>;
export declare function getSecurityStatus(): Promise<any>;
export declare function clearCache(): Promise<any>;
//# sourceMappingURL=index.d.ts.map