type ByteBufferOptions = {
  len: number
  data: Uint8Array
}

export class ByteBuffer {
  public len: number
  public data: Uint8Array

  public constructor({ data, len }: ByteBufferOptions) {
    this.data = data
    this.len = len
  }

  public static fromUint8Array(data: Uint8Array): ByteBuffer {
    return new ByteBuffer({ data, len: data.length })
  }
}
