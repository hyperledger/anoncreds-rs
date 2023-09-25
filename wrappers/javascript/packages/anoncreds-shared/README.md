# Anoncreds Shared

This package does not contain any functionality, just the classes and types
that wrap around the native NodeJS / React Native functionality

## General setup

Every object can be created by calling `create` on the class as a static
method. This returns an instance of the class which contains a handle
to an internal object inside the `anoncreds-rs` library. This handle can
be turned into json by calling `toJson()` on the object.

```typescript
import { Schema } from '@hyperledger/anoncreds-nodejs'

const schema = Schema.create({
  name: 'test',
  version: '1.0',
  issuerId: 'mock:uri',
  attributeNames: ['name', 'age', 'address']
})

// JSON representation
const schemaJson = schema.toJson()

// This can be used as a deconstructor to clear the internal reference to
// the anoncreds object
schema.handle.clear()
```

## Platform independent setup

If you would like to leverage the anoncreds libraries for JavaScript in a platform independent way you need to add the `@hyperledger/anoncreds-shared` package to your project. This package exports all public methods.

Before calling any methods you then need to make sure you register the platform specific native bindings. You can do this by importing the platform specific package. You can do this by having separate files that register the package, which allows the React Native bundler to import a different package:

```typescript
// register.ts
import '@hyperledger/anoncreds-nodejs'
```

```typescript
// register.native.ts
import '@hyperledger/anoncreds-react-native'
```

An alterative approach is to first try to require the Node.JS package, and otherwise require the React Native package:

```typescript
try {
  require('@hyperledger/anoncreds-nodejs')
} catch (error) {
  try {
    require('@hyperledger/anoncreds-react-native')
  } catch (error) {
    throw new Error('Could not load anoncreds bindings')
  }
}
```

How you approach it is up to you, as long as the native binding are called
before any actions are performed on the anoncreds library.
