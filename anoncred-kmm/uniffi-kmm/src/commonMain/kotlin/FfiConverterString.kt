import okio.Buffer

object FfiConverterString : FfiConverter<String, RustBuffer> {
    override fun lift(value: RustBuffer): String {
        try {
            val byteArr = value.toBuffer().readByteArray(value.dataSize.toLong())
            return byteArr.decodeToString()
        } finally {
            value.free()
        }
    }

    override fun read(buf: Buffer): String {
        val len = buf.readInt()
        val byteArr = buf.readByteArray(len.toLong())
        return byteArr.decodeToString()
    }

    override fun lower(value: String): RustBuffer {
        val buffer = Buffer().write(value.encodeToByteArray())
        return allocRustBuffer(buffer)
    }

    override fun allocationSize(value: String): Int {
        val sizeForLength = 4
        val sizeForString = value.length * 3
        return sizeForLength + sizeForString
    }

    override fun write(value: String, buf: Buffer) {
        val byteArr = value.encodeToByteArray()
        buf.writeInt(byteArr.size)
        buf.write(byteArr)
    }
}
