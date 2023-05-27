package anoncreds.api

import kotlinx.serialization.Serializable


@Serializable
class AnoncredsError(
    val code: Long,
    override val message: String
) : Exception(
    "Anoncreds Error: $code; $message"
)