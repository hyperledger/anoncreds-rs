# indy-credx-nodejs

Wrapper for Nodejs around Indy Credx

## Requirements

This has been tested extensively with Nodejs version `16.11.0` and `16.15.0`.
Older and newer versions might also work, but they have not been tested.

## Installation

```sh
yarn add indy-credx-nodejs indy-credx-shared
```

## Setup

In order to work with this module a function from `indy-credx-shared` has to be
called to register the native module (indy-credx-nodejs)

```typescript
import { registerIndyCredx } from 'indy-credx-shared'
import { indyCredxNodeJS } from 'indy-credx-nodejs'

registerIndyCredx({ credx: indyCredxNodeJS })
```
