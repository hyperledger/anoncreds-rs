import okio.Buffer

object FfiConverterUShort : FfiConverter<UShort, UShort> {
    override fun lift(value: UShort): UShort = value

    override fun read(buf: Buffer): UShort = lift(buf.readShort().toUShort())

    override fun lower(value: UShort): UShort = value

    override fun allocationSize(value: UShort) = 2

    override fun write(value: UShort, buf: Buffer) {
        buf.writeShort(value.toInt())
    }
}
