import okio.Buffer

// TODO remove suppress when https://youtrack.jetbrains.com/issue/KT-29819/New-rules-for-expect-actual-declarations-in-MPP is solved
@Suppress("NO_ACTUAL_FOR_EXPECT")
expect class RustBuffer

@Suppress("NO_ACTUAL_FOR_EXPECT")
expect class RustBufferPointer

expect fun RustBuffer.toBuffer(): Buffer

expect val RustBuffer.dataSize: Int

expect fun RustBuffer.free()

expect fun allocRustBuffer(buffer: Buffer): RustBuffer

expect fun RustBufferPointer.setValue(value: RustBuffer)

expect fun emptyRustBuffer(): RustBuffer
