actual typealias Pointer = com.sun.jna.Pointer

actual fun Long.toPointer() = com.sun.jna.Pointer(this)

actual fun Pointer.toLong(): Long = com.sun.jna.Pointer.nativeValue(this)
