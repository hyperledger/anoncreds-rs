import okio.Buffer

object FfiConverterDouble : FfiConverter<Double, Double> {
    override fun lift(value: Double): Double = value

    override fun read(buf: Buffer): Double = Double.fromBits(buf.readLong())

    override fun lower(value: Double): Double = value

    override fun allocationSize(value: Double) = 8

    override fun write(value: Double, buf: Buffer) {
        buf.writeLong(value.toRawBits())
    }
}
