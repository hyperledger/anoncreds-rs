# Anoncreds React Native

Wrapper for React Native around anoncreds

## Requirements

This module uses the new React Native Turbo Modules. These are faster than the
previous Native Modules, and can be completely synchronous. A React Native
version of `>= 0.66.0` is required for this package to work.

## Installation

```sh
yarn add @hyperledger/anoncreds-react-native
```

## Usage

You can import all types and classes from the `@hyperledger/anoncreds-react-native` library:

```typescript
import { Schema } from '@hyperledger/anoncreds-react-native'

const schema = Schema.create({
  name: 'test',
  version: '1.0',
  issuerId: 'mock:uri',
  attributeNames: ['name', 'age', 'address'],
})

// JSON representation
const schemaJson = schema.toJson()

// This can be used as a deconstructor to clear the internal reference to
// the anoncreds object
schema.handle.clear()
```

> **Note**: If you want to use this library in a cross-platform environment you need to import methods from the `@hyperledger/anoncreds-shared` package instead. This is a platform independent package that allows to register the native bindings. The `@hyperledger/anoncreds-react-native` package uses this package under the hood. See the [Anoncreds Shared README](https://github.com/hyperledger/anoncreds/tree/main/wrappers/javascript/anoncreds-shared/README.md) for documentation on how to use this package.
