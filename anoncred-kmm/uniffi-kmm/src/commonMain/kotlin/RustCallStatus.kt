// TODO remove suppress when https://youtrack.jetbrains.com/issue/KT-29819/New-rules-for-expect-actual-declarations-in-MPP is solved
@Suppress("NO_ACTUAL_FOR_EXPECT")
expect class RustCallStatus

fun RustCallStatus.isSuccess(): Boolean = statusCode == 0

fun RustCallStatus.isError(): Boolean = statusCode == 1

fun RustCallStatus.isPanic(): Boolean = statusCode == 2

expect val RustCallStatus.statusCode: Int

expect val RustCallStatus.errorBuffer: RustBuffer

expect fun <T> withRustCallStatus(block: (RustCallStatus) -> T): T
