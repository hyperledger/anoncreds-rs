package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.FfiStrVar
import anoncreds_rs.anoncreds_create_link_secret
import kotlinx.cinterop.*

class LinkSecret {
    companion object {
        fun create(): String {
            memScoped {
                val secretPointer = alloc<FfiStrVar>()
                val errorCode = anoncreds_create_link_secret(
                    secretPointer.ptr
                )

                Anoncreds.assertNoError(errorCode)
                return secretPointer.value!!.toKString()
            }

        }
    }
}