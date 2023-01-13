import type { Anoncreds } from './Anoncreds'

export let anoncreds: Anoncreds

export const registerAnoncreds = ({ lib }: { lib: Anoncreds }) => (anoncreds = lib)
