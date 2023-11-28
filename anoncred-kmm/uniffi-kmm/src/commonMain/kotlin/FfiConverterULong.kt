import okio.Buffer

object FfiConverterULong : FfiConverter<ULong, ULong> {
    override fun lift(value: ULong): ULong = value

    override fun read(buf: Buffer): ULong = lift(buf.readLong().toULong())

    override fun lower(value: ULong): ULong = value

    override fun allocationSize(value: ULong) = 8

    override fun write(value: ULong, buf: Buffer) {
        buf.writeLong(value.toLong())
    }
}
