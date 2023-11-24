internal inline fun <U, E : Exception> rustCallWithError(
    errorHandler: CallStatusErrorHandler<E>,
    crossinline callback: (RustCallStatus) -> U
): U = withRustCallStatus { status ->
    val returnValue = callback(status)
    if (status.isSuccess()) {
        returnValue
    } else if (status.isError()) {
        throw errorHandler.lift(status.errorBuffer)
    } else if (status.isPanic()) {
        if (status.errorBuffer.dataSize > 0) {
            throw InternalException(FfiConverterString.lift(status.errorBuffer))
        } else {
            throw InternalException("Rust panic")
        }
    } else {
        throw InternalException("Unknown rust call status: $status.code")
    }
}

interface CallStatusErrorHandler<E> {
    fun lift(error_buf: RustBuffer): E;
}

object NullCallStatusErrorHandler : CallStatusErrorHandler<InternalException> {
    override fun lift(error_buf: RustBuffer): InternalException {
        error_buf.free()
        return InternalException("Unexpected CALL_ERROR")
    }
}

internal inline fun <U> rustCall(crossinline callback: (RustCallStatus) -> U): U {
    return rustCallWithError(NullCallStatusErrorHandler, callback);
}
