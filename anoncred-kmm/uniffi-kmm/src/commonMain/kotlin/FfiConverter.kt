import okio.Buffer

interface FfiConverter<KotlinType, FfiType> {

    fun lowerIntoRustBuffer(value: KotlinType): RustBuffer {
        val buffer = Buffer().apply { write(value, buffer) }
        return allocRustBuffer(buffer)
    }

    fun liftFromRustBuffer(rbuf: RustBuffer): KotlinType {
        val byteBuf = rbuf.toBuffer()
        try {
            val item = read(byteBuf)
            if (!byteBuf.exhausted()) {
                throw RuntimeException("junk remaining in buffer after lifting, something is very wrong!!")
            }
            return item
        } finally {
            rbuf.free()
        }
    }

    fun lift(value: FfiType): KotlinType
    fun lower(value: KotlinType): FfiType
    fun read(buf: Buffer): KotlinType
    fun allocationSize(value: KotlinType): Int
    fun write(value: KotlinType, buf: Buffer)
}
