package anoncreds.api

import anoncreds_rs.FfiCredRevInfo
import kotlinx.cinterop.AutofreeScope
import kotlinx.cinterop.CValue
import kotlinx.cinterop.cValue
import kotlinx.cinterop.cstr
import kotlinx.serialization.SerialName

class AnoncredsCredentialRevocationConfig(
    @SerialName("reg_def")
    val registryDefinition: RevocationRegistryDefinition,
    @SerialName("reg_def_private")
    val registryDefinitionPrivate: RevocationRegistryDefinitionPrivate,
    @SerialName("reg_idx")
    val registryIndex: Long,
    @SerialName("tails_path")
    val tailsPath: String
) {

    fun clear(){
        registryDefinition.clear()
        registryDefinitionPrivate.clear()
    }

    fun toFfi(scope: AutofreeScope): CValue<FfiCredRevInfo> {
        return cValue<FfiCredRevInfo>{
            this.reg_def = registryDefinition.handle
            this.reg_def_private = registryDefinitionPrivate.handle
            this.reg_idx = registryIndex
            this.tails_path = tailsPath.cstr.getPointer(scope)
        }
    }

}
