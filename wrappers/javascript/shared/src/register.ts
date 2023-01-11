import type { IndyCredx } from './IndyCredx'

export let indyCredx: IndyCredx

export const registerIndyCredx = ({ credx }: { credx: IndyCredx }) => (indyCredx = credx)
