import okio.Buffer

object FfiConverterUByte : FfiConverter<UByte, UByte> {
    override fun lift(value: UByte): UByte = value

    override fun read(buf: Buffer): UByte = lift(buf.readByte().toUByte())

    override fun lower(value: UByte): UByte = value

    override fun allocationSize(value: UByte) = 1

    override fun write(value: UByte, buf: Buffer) {
        buf.writeByte(value.toInt())
    }
}
