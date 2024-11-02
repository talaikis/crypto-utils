import { useEffect } from 'react';
import { sha256, generateKeyPair, signData, generateAESKey, aesEncrypt, aesDecrypt } from 'rn-crypto-utils';

export default function App() {
  useEffect(() => {
    const serve = async () => {
      const result = await sha256("string");
      console.info('result', result)
      if (!result) throw new Error('Failed sha256')
      const keys = await generateKeyPair(2048, 'RSA');
      console.info('keys', keys)
      if (!keys) throw new Error('Failed generateKeyPair')
      const signed = await signData('string', keys.privateKey);
      console.info('signed', signed)
      if (!signed) throw new Error('Failed signData')
      const aesKey = await generateAESKey(256)
      const encrypted = await aesEncrypt('test', aesKey)
      console.info('encrypted', encrypted)
      const decrypted = await aesDecrypt(encrypted, aesKey)
      console.info('decrypted', decrypted)
      if (decrypted !== 'test') throw new Error('Failed AES')
    }

    serve()
  }, []);

  return null
}
