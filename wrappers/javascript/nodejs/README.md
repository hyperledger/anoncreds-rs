# anoncreds-nodejs

Wrapper for Nodejs around Anoncreds

## Requirements

This has been tested extensively with Nodejs version `16.11.0` and `16.15.0`.
Older and newer versions might also work, but they have not been tested.

## Installation

```sh
yarn add anoncreds-nodejs anoncreds-shared
```

## Setup

In order to work with this module a function from `anoncreds-shared` has to be
called to register the native module (anoncreds-nodejs)

```typescript
import { registerAnoncreds } from 'anoncreds-shared'
import { AnoncredsNodeJS } from 'anoncreds-nodejs'

registerAnoncreds({ anoncreds: AnoncredsNodeJS })
```
