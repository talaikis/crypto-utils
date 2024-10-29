module.exports = {
  env: {
    browser: true,
    es2021: true,
    mocha: true,
    jest: true
  },
  settings: {
    react: {
      version: 'detect'
    }
  },
  extends: [
    'plugin:react/recommended',
    'plugin:react-hooks/recommended',
    'plugin:react-perf/recommended',
    'standard',
    'plugin:import/recommended',
    'plugin:mocha/recommended'
  ],
  parser: '@babel/eslint-parser',
  parserOptions: {
    ecmaFeatures: {
      jsx: true
    },
    babelOptions: {
      presets: ['@babel/preset-react']
    },
    requireConfigFile: false,
    ecmaVersion: 'latest'
  },
  plugins: [
    'react',
    'react-hooks',
    'react-perf',
    'spellcheck',
    'mocha',
    'security',
    'import',
    'react-props-in-state'
  ],
  overrides: [{
    files: ['*.json'],
    parser: 'eslint-plugin-json-es',
    extends: 'plugin:eslint-plugin-json-es/recommended'
  }],
  rules: {
    'import/no-unresolved': [0, 'always'],
    'import/namespace': [0, 'always'],
    'import/named': [0, 'always'],
    'import/no-cycle': [2, { maxDepth: 8 }],
    'import/no-self-import': 2,
    'security/detect-buffer-noassert': 'warn',
    'security/detect-child-process': 'warn',
    'security/detect-disable-mustache-escape': 'warn',
    'security/detect-eval-with-expression': 'warn',
    'security/detect-new-buffer': 'warn',
    'security/detect-no-csrf-before-method-override': 'warn',
    'security/detect-non-literal-fs-filename': 'warn',
    'security/detect-non-literal-regexp': 0,
    'security/detect-non-literal-require': 'warn',
    'security/detect-object-injection': 0,
    'security/detect-possible-timing-attacks': 'warn',
    'security/detect-pseudoRandomBytes': 'warn',
    'security/detect-unsafe-regex': 'warn',
    'security/detect-bidi-characters': 'warn',
    'react-hooks/exhaustive-deps': 0,
    'react-perf/jsx-no-new-array-as-prop': 0,
    'react-perf/jsx-no-new-object-as-prop': 0,
    'react-perf/jsx-no-new-function-as-prop': 0,
    'spellcheck/spell-checker': [1,
      {
        comments: false,
        strings: false,
        identifiers: true,
        templates: false,
        lang: 'en_US',
        skipWords: [
          'utils',
          'ssr',
          'ctx',
          'mmkv',
          'revalidate',
          'persistor',
          'Idb',
          'jsx',
          'Exts',
          'deduplicated',
          'rbac',
          'Worklets',
          'classnames',
          'fnames',
          'Aes',
          'madge',
          'deprecations',
          'Rehydrate',
          'errored',
          'passcode',
          'realpath',
          'Mui',
          'Firebase',
          'breakpoint',
          'Mundial',
          'Cobane',
          'Moz',
          'Osx',
          'Majeure',
          'immer',
          'zustand',
          'Webkit',
          'subheader',
          'overline',
          'automock',
          'kyc',
          'graphql',
          'Urls',
          'Reactotron',
          'jitter',
          'backoff',
          'rimraf',
          'medialibrary',
          'Sdk',
          'rtn',
          'Codec',
          'mtime',
          'ecma',
          'Cnpj',
          'Cpf',
          'lang',
          'uint',
          'enum',
          'Kpi',
          'requeue',
          'lstat',
          'Dexie',
          'Presigned',
          'unlink',
          'readdir',
          'svg',
          'execute',
          'executer',
          'executers',
          'enqueue',
          'sql',
          'canceled',
          'amazonaws',
          'integrations',
          'Profiler',
          'Promisified',
          'cognito',
          'mqtt',
          'Radians',
          'chai',
          'aws',
          'cmd',
          'wss',
          'stderr',
          'Pluggable',
          'pathname',
          'pdf',
          'Resize',
          'resize',
          'Bson',
          'cvc',
          'jsi',
          'stdout',
          'globby',
          'mdx',
          'nda',
          'xml',
          'Xml',
          'bool',
          'jpg',
          'jpeg',
          'gif',
          'xhr',
          'redux',
          'uri',
          'scp',
          'comlink',
          'mailto',
          'formik',
          'debounce',
          'mapbox',
          'comparables',
          'func',
          'decrypted',
          'Blowfish',
          'transferables',
          'Paginator',
          'switzerland',
          'singapore',
          'Uint8Array',
          'arn',
          'sig',
          'Unregister',
          'nid',
          'tid',
          'Calendly',
          'scr',
          'tos',
          'llp',
          'req',
          'tooltip',
          'treemap',
          'href',
          'multiline',
          'datalist',
          'Rect',
          'loc',
          'debounced',
          'Checkbox',
          'elementpath',
          'directionality',
          'Linkedin',
          'textarea',
          'geo',
          'uid',
          'unmount',
          'Renderer',
          'invoker',
          'ontimeout',
          'onreadystatechange',
          'sitemap',
          'dequal',
          'pubsub',
          'mozjpeg',
          'avif',
          'jxl',
          'decrypt',
          'utf',
          'plaintext',
          'nsf',
          'Wjs',
          'unicode',
          'ascii',
          'uploader',
          'rgb',
          'memoized',
          'Comparer',
          'derivate',
          'deduplicate',
          'serializable',
          'Signin',
          'facebook',
          'isCanceled',
          'fcm',
          'Scrollable',
          'Defs',
          'Pressable',
          'Disabler',
          'uris',
          'iban',
          'mastercard',
          'Personalziation',
          'notifee',
          'bezier',
          'Faq',
          'dsn',
          'ttl',
          'Millis',
          'Responder',
          'evt',
          'accum',
          'syncable',
          'enums',
          'codegen',
          'Personalization',
          'weido',
          'promisify',
          'Iot',
          'onopen',
          'babylon',
          'semver',
          'Obfuscator',
          'ast',
          'minifier',
          'Globals',
          'upsert'
        ],
        minLength: 3
      }
    ]
  }
}
