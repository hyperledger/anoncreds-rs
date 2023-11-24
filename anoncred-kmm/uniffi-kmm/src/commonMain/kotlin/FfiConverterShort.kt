import okio.Buffer

object FfiConverterShort : FfiConverter<Short, Short> {
    override fun lift(value: Short): Short = value

    override fun read(buf: Buffer): Short = buf.readShort()

    override fun lower(value: Short): Short = value

    override fun allocationSize(value: Short) = 2

    override fun write(value: Short, buf: Buffer) {
        buf.writeShort(value.toInt())
    }
}
