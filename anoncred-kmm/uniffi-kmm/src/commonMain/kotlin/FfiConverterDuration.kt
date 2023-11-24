import okio.Buffer
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

object FfiConverterDuration : FfiConverterRustBuffer<Duration> {
    override fun read(buf: Buffer): Duration {
        val seconds = buf.readLong().seconds
        val nanoseconds = buf.readInt().nanoseconds
        val duration = seconds + nanoseconds
        if (duration < 0.nanoseconds) {
            throw IllegalArgumentException("Duration nanoseconds exceed minimum or maximum supported by uniffi")
        }
        return duration
    }

    override fun allocationSize(value: Duration) = 12

    override fun write(value: Duration, buf: Buffer) {
        if (value < 0.nanoseconds) {
            throw IllegalArgumentException("Invalid duration, must be non-negative")
        }
        buf.writeLong(value.inWholeSeconds)
        buf.writeInt(value.inWholeNanoseconds.toInt())
    }
}
