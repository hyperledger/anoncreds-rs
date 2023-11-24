import kotlinx.atomicfu.atomic
import kotlinx.atomicfu.getAndUpdate
import kotlinx.atomicfu.locks.reentrantLock
import kotlinx.atomicfu.locks.withLock
import okio.Buffer

internal class ConcurrentHandleMap<T>(
    private val leftMap: MutableMap<Handle, T> = mutableMapOf(),
    private val rightMap: MutableMap<T, Handle> = mutableMapOf()
) {
    private val lock = reentrantLock()
    private val currentHandle = atomic(0L)

    fun insert(obj: T): Handle =
        lock.withLock {
            rightMap[obj] ?: currentHandle.getAndIncrement()
                .let { it.toULong() }
                .also { handle ->
                    leftMap[handle] = obj
                    rightMap[obj] = handle
                }
        }

    fun get(handle: Handle) = lock.withLock {
        leftMap[handle]
    }

    fun delete(handle: Handle) {
        this.remove(handle)
    }

    fun remove(handle: Handle): T? =
        lock.withLock {
            leftMap.remove(handle)?.let { obj ->
                rightMap.remove(obj)
                obj
            }
        }
}

// Magic number for the Rust proxy to call using the same mechanism as every other method,
// to free the callback once it's dropped by Rust.
internal const val IDX_CALLBACK_FREE = 0

abstract class FfiConverterCallbackInterface<CallbackInterface> : FfiConverter<CallbackInterface, Handle> {
    private val handleMap = ConcurrentHandleMap<CallbackInterface>()

    // Registers the foreign callback with the Rust side.
    // This method is generated for each callback interface.
    internal abstract fun register(lib: UniFFILib)

    fun drop(handle: Handle) {
        handleMap.remove(handle)
    }

    override fun lift(value: Handle): CallbackInterface {
        return handleMap.get(value) ?: throw InternalException("No callback in handlemap; this is a Uniffi bug")
    }

    override fun read(buf: Buffer) = lift(buf.readLong().toULong())

    override fun lower(value: CallbackInterface) =
        handleMap.insert(value).also {
            check(handleMap.get(it) === value) { "Handle map is not returning the object we just placed there. This is a bug in the HandleMap." }
        }

    override fun allocationSize(value: CallbackInterface) = 8

    override fun write(value: CallbackInterface, buf: Buffer) {
        buf.writeLong(lower(value).toLong())
    }
}
