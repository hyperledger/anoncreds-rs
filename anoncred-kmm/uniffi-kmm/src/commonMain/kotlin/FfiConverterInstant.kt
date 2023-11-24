import kotlinx.datetime.Instant
import okio.Buffer

object FfiConverterInstant : FfiConverterRustBuffer<Instant> {
    override fun read(buf: Buffer): Instant {
        val seconds = buf.readLong()
        val nanoseconds = buf.readInt()
        val instant = Instant.fromEpochSeconds(seconds, nanoseconds)
        if (nanoseconds < 0) {
            throw IllegalArgumentException("Instant nanoseconds exceed minimum or maximum supported by uniffi")
        }
        return instant
    }

    override fun allocationSize(value: Instant) = 12

    override fun write(value: Instant, buf: Buffer) {
        value.epochSeconds

        if (value.nanosecondsOfSecond < 0) {
            throw IllegalArgumentException("Invalid timestamp, nano value must be non-negative")
        }

        buf.writeLong(value.epochSeconds)
        buf.writeInt(value.nanosecondsOfSecond)
    }
}
