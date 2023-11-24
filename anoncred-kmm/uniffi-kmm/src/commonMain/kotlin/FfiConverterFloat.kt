import okio.Buffer

object FfiConverterFloat : FfiConverter<Float, Float> {
    override fun lift(value: Float): Float = value

    override fun read(buf: Buffer): Float = Float.fromBits(buf.readInt())

    override fun lower(value: Float): Float = value

    override fun allocationSize(value: Float) = 4

    override fun write(value: Float, buf: Buffer) {
        buf.writeInt(value.toRawBits())
    }
}
