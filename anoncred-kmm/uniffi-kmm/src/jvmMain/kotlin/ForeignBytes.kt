import com.sun.jna.Pointer
import com.sun.jna.Structure

@Structure.FieldOrder("len", "data")
actual open class ForeignBytes : Structure() {
    @JvmField
    var len: Int = 0

    @JvmField
    var data: Pointer? = null
}
