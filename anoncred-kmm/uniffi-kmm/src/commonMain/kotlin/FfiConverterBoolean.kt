import okio.Buffer

object FfiConverterBoolean : FfiConverter<Boolean, Byte> {
    override fun lift(value: Byte): Boolean = value.toInt() != 0

    override fun read(buf: Buffer): Boolean = lift(buf.readByte())

    override fun lower(value: Boolean): Byte = if (value) 1.toByte() else 0.toByte()

    override fun allocationSize(value: Boolean) = 1

    override fun write(value: Boolean, buf: Buffer) {
        buf.writeByte(lower(value).toInt())
    }
}
