# @talaikis/crypto-utils

React Native Crypto, etc. utils

## Installation

```sh
yarn add @talaikis/crypto-utils
```

## Usage

```js
import { sha256, generateKeyPair } from '@talaikis/crypto-utils';

// ...

const result = await sha256("string");
const { privateKey, publicKey } = await generateKeyPair(2048, 'RSA');
const signed = await signData('string', privateKey);
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
