# rn-crypto-utils

React Native Crypto, etc. utils

## Installation

```sh
yarn add rn-crypto-utils
```

## Usage

```js
import { sha256, generateKeyPair, signData, generateAESKey, aesEncrypt, aesDecrypt, ... } from 'rn-crypto-utils';

// ...

const result = await sha256("string");
const { privateKey, publicKey } = await generateKeyPair(2048, 'RSA');
const signed = await signData('string', privateKey);
const key = await generateAESKey(256);
const encrypted = await aesEncrypt('test string', key);
const decrypted = await aesDecrypt(encrypted, key);

// andoird methods
await clearCache()
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
