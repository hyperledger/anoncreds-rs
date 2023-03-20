import { anoncreds } from '../register'

export class LinkSecret {
  public static create(): string {
    return anoncreds.createLinkSecret()
  }
}
