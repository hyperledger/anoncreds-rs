import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.toCPointer

// TODO remove suppress when https://youtrack.jetbrains.com/issue/KT-29819/New-rules-for-expect-actual-declarations-in-MPP is solved
@Suppress("ACTUAL_WITHOUT_EXPECT", "ACTUAL_TYPE_ALIAS_WITH_USE_SITE_VARIANCE")
actual typealias Pointer = CPointer<out CPointed>

actual fun Long.toPointer(): Pointer = requireNotNull(this.toCPointer())

actual fun Pointer.toLong(): Long = this.rawValue.toLong()
