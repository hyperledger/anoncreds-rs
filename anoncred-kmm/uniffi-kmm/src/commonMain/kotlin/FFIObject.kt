import kotlinx.atomicfu.*

abstract class FFIObject(
    protected val pointer: Pointer
) : Disposable {

    private val wasDestroyed = atomic(false)
    private val callCounter = atomic(1L)

    open protected fun freeRustArcPtr() {
        // To be overridden in subclasses.
    }

    override fun destroy() {
        if (this.wasDestroyed.compareAndSet(expect = false, update = true)) {
            if (this.callCounter.decrementAndGet() == 0L) {
                this.freeRustArcPtr()
            }
        }
    }

    internal inline fun <R> callWithPointer(block: (ptr: Pointer) -> R): R {
        do {
            val c = this.callCounter.value
            if (c == 0L) {
                throw IllegalStateException("${this::class.simpleName} object has already been destroyed")
            }
            if (c == Long.MAX_VALUE) {
                throw IllegalStateException("${this::class.simpleName} call counter would overflow")
            }
        } while (!this.callCounter.compareAndSet(expect = c, update = c + 1L))
        try {
            return block(this.pointer)
        } finally {
            if (this.callCounter.decrementAndGet() == 0L) {
                this.freeRustArcPtr()
            }
        }
    }
}
