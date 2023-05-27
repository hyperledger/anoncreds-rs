@file:OptIn(UnsafeNumber::class)

package anoncreds

import anoncreds.api.AnoncredsError
import anoncreds_rs.*
import kotlinx.cinterop.*
import kotlinx.serialization.json.Json

class Anoncreds {

    companion object {

        fun version(): String {
            return anoncreds_version()!!.toKString()
        }


        fun generateNonce(): String {
            memScoped {
                val noncePointer = alloc<CPointerVar<ByteVar>>()
                val errorCode = anoncreds_generate_nonce(noncePointer.ptr)
                val nonce = noncePointer.value

                assertNoError(errorCode)

                return nonce!!.toKString()
            }
        }

        fun byteBufferToString(byteBuffer: ByteBuffer): String {
            val buffer = ByteArray(byteBuffer.len.toInt()){
                byteBuffer.data?.get(it)?.toByte()!!
            }
            return buffer.toKString()
        }

        fun stringToByteBuffer(string: String, scope: MemScope): CValue<ByteBuffer> {
            val kBuffer = string.encodeToByteArray()
            val cArr = scope.allocArray<UByteVar>(kBuffer.size){
                this.value = kBuffer[it].toUByte()
            }
            val byteBuffer = cValue<ByteBuffer> {
                data = cArr
                len = kBuffer.size.toLong()
            }
            return byteBuffer
        }

        fun getErrorJson(): AnoncredsError {
            memScoped {
                val jsonPointer = alloc<FfiStrVar>()
                anoncreds_get_current_error(jsonPointer.ptr)
                val json = jsonPointer.value!!.toKString()
                return Json.decodeFromString<AnoncredsError>(json)
            }
        }

        fun assertNoError(errorCode: ErrorCode){
            if (errorCode > 0u) {
                throw getErrorJson()
            }
        }

    }
}