import { registerIndyCredx } from 'indy-credx-shared'

import { NodeJSIndyCredx } from '../../src/NodeJSIndyCredx'
import { nativeIndyCredx } from '../../src/library'

export const setup = () => {
  registerIndyCredx({ credx: new NodeJSIndyCredx() })
  nativeIndyCredx.credx_set_default_logger()
}
