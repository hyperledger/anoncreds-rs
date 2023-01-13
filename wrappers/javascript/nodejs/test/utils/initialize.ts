import { registerAnoncreds } from 'anoncreds-shared'

import { NodeJSAnoncreds } from '../../src/NodeJSAnoncreds'
import { nativeAnoncreds } from '../../src/library'

export const setup = () => {
  registerAnoncreds({ lib: new NodeJSAnoncreds() })
  nativeAnoncreds.anoncreds_set_default_logger()
}
