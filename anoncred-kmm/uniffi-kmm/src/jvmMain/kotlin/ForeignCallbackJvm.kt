import com.sun.jna.Callback

class NativeCallback(
    private val invokeImpl: (
        handle: Handle,
        method: Int,
        args: RustBuffer,
        outBuf: RustBufferPointer
    ) -> Int
) : Callback {
    fun invoke(
        handle: Handle,
        method: Int,
        args: RustBuffer,
        outBuf: RustBufferPointer
    ): Int = invokeImpl(handle, method, args, outBuf)
}

actual typealias ForeignCallback = NativeCallback
