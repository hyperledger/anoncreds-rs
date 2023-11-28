import okio.Buffer

object FfiConverterUInt : FfiConverter<UInt, UInt> {
    override fun lift(value: UInt): UInt = value

    override fun read(buf: Buffer): UInt = lift(buf.readInt().toUInt())

    override fun lower(value: UInt): UInt = value

    override fun allocationSize(value: UInt) = 4

    override fun write(value: UInt, buf: Buffer) {
        buf.writeInt(value.toInt())
    }
}
