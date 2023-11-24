import okio.Buffer

interface FfiConverterRustBuffer<KotlinType> : FfiConverter<KotlinType, RustBuffer> {
    override fun lift(value: RustBuffer) = liftFromRustBuffer(value)
    override fun lower(value: KotlinType) = lowerIntoRustBuffer(value)
}
