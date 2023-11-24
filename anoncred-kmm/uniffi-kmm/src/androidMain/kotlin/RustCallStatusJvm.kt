import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure

@Structure.FieldOrder("code", "error_buf")
actual open class RustCallStatus : Structure() {
    @JvmField
    var code: Int = 0

    @JvmField
    var error_buf: RustBuffer = RustBuffer()
}

actual val RustCallStatus.statusCode: Int
    get() = code
actual val RustCallStatus.errorBuffer: RustBuffer
    get() = error_buf

actual fun <T> withRustCallStatus(block: (RustCallStatus) -> T): T {
    val rustCallStatus = RustCallStatus()
    return block(rustCallStatus)
}
