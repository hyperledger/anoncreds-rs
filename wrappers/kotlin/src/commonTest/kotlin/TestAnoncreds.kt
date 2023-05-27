package tech.indicio.holdr

import anoncreds.Anoncreds
import anoncreds.api.*
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TestAnoncreds {

    @Test
    fun testAnoncredsVersion() {
        val anoncredsVersion = Anoncreds.version()
        println("ANONCREDS VERSION: $anoncredsVersion")
    }

    @Test
    fun testAnoncredsNonce() {
        println("TESTING NONCE GENERATION")
        var low: Int? = null
        var high: Int? = null
        for(i in 0 .. 100){
            val nonce = Anoncreds.generateNonce()
            val len = nonce.length
            if(low === null || high === null){
                low = len
                high = len
            }else{
                if(len < low)
                    low = len
                if(len > high)
                    high = len
            }
        }
        println("\tLOW NONCE LENGTH: $low")
        println("\tHIGH NONCE LENGTH: $high")
    }

    @Test fun testAnoncredsError() {
        println("TESTING ANONCREDS ERROR")
        try{
            PresentationRequest.fromJson("Broken JSON")
        }catch(e: AnoncredsError){
            println("\tASSERTING THAT ERROR CODE (${e.code}) IS 1")
            assertEquals(1, e.code)
            println("\t\tPASSED!")
        }

    }

    @Test
    fun createAndVerifyPresentation() {
        println("CREATE AND VERIFY PRESENTATION")

        val nonce = Anoncreds.generateNonce()
        println("\tGENERATE NONCE: $nonce")

        val prJson = buildJsonObject {
            put("nonce", nonce)
            put("name", "pres_req_1")
            put("version", "0.1")
            putJsonObject("requested_attributes"){
                putJsonObject("attr1_referent"){
                    put("name", "name")
                    put("issuer", "mock:uri")
                }
                putJsonObject("attr2_referent"){
                    put("name", "sex")
                }
                putJsonObject("attr3_referent"){
                    put("name", "phone")
                }
                putJsonObject("attr4_referent"){
                    putJsonArray("names"){
                        add("name")
                        add("height")
                    }
                }
            }
            putJsonObject("requested_predicates"){
                putJsonObject("predicate1_referent"){
                    put("name", "age")
                    put("p_type", ">=")
                    put("p_value", 18)
                }
            }
            putJsonObject("non_revoked"){
                put("from", 13)
                put("to", 200)
            }
        }

        println("\tBUILDING PRESENTATION REQUEST FROM JSON")
        val presentationRequest = PresentationRequest.fromJson(prJson.toString())
        println("\t\tPRESENTATION REQUEST HANDLE: ${presentationRequest.handle}")

        println("\tBUILDING SCHEMA FROM JSON")
        val schema = Schema.fromJson(buildJsonObject {
            put("name", "schema-1")
            put("issuerId", "mock:uri")
            put("version", "1")
            putJsonArray("attrNames"){
                add("name")
                add("age")
                add("sex")
                add("height")
            }
        }.toString())
        println("\t\tSCHEMA HANDLE: ${schema.handle}")

        println("\tCREATING CREDENTIAL DEFINITION")
        val credDefData = AnoncredsCredentialDefinition.create(
            "mock:uri",
            schema,
            "CL",
            "TAG",
            "mock:uri",
            true
        )

        val credentialDefinition = credDefData.credentialDefinition
        val keyCorrectnessProof = credDefData.keyCorrectnessProof
        val credentialDefinitionPrivate = credDefData.credentialDefinitionPrivate
        println("\t\tCREDENTIAL DEFINITION HANDLE: ${credentialDefinition.handle}")
        println("\t\tKEY CORRECTNESS PROOF HANDLE: ${keyCorrectnessProof.handle}")
        println("\t\tCREDENTIAL DEFINITION PRIVATE HANDLE: ${credentialDefinitionPrivate.handle}")


        println("\tCREATING REVOCATION REGISTRY DEFINITION")
        val revRegData = RevocationRegistryDefinition.create(
            credentialDefinition,
            "mock:uri",
            "some_tag",
            "mock:uri",
            "CL_ACCUM",
            10
        )

        val revocationRegistryDefinition = revRegData.revocationRegistryDefinition
        val revocationRegistryDefinitionPrivate = revRegData.revocationRegistryDefinitionPrivate
        println("\t\tREVOCATION REGISTRY DEFINITION HANDLE: ${revocationRegistryDefinition.handle}")
        println("\t\tREVOCATION REGISTRY DEFINITION PRIVATE HANDLE: ${revocationRegistryDefinitionPrivate.handle}")

        println("\tGETTING TAILS LOCATION")
        val tailsPath = revocationRegistryDefinition.getTailsLocation()
        println("\t\tTAILS LOCATION: $tailsPath")

        println("\tCREATING REVOCATION STATUS LIST")
        val timeCreateRevStatusList = 12L
        val revocationStatusList = RevocationStatusList.create(
            "mock:uri",
            revocationRegistryDefinition,
            "mock:uri",
            true,
            timeCreateRevStatusList
        )
        println("\t\tREVOCATION STATUS LIST HANDLE: ${revocationStatusList.handle}")

        println("\tCREATING CREDENTIAL OFFER")
        val credentialOffer = AnoncredsCredentialOffer.create(
            "mock:uri",
            "mock:uri",
            keyCorrectnessProof
        )
        println("\t\tCREDENTIAL OFFER HANDLE: ${credentialOffer.handle}")

        println("\tCREATING LINK SECRET")
        val linkSecret = LinkSecret.create()
        val linkSecretId = "link secret id"
        println("\t\tLINK SECRET: $linkSecret")

        println("\tCREATING CREDENTIAL REQUEST")
        val credReqData = AnoncredsCredentialRequest.create(
            credentialDefinition,
            linkSecret,
            linkSecretId,
            credentialOffer,
            "entropy"
        )

        val credentialRequest = credReqData.credentialRequest
        val credentialRequestMetadata = credReqData.credentialRequestMetadata
        println("\t\tCREDENTIAL REQUEST HANDLE: ${credentialRequest.handle}")
        println("\t\tCREDENTIAL REQUEST METADATA HANDLE: ${credentialRequestMetadata.handle}")

        println("\tCREATING CREDENTIAL")
        val credential = AnoncredsCredential.create(
            credentialDefinition,
            credentialDefinitionPrivate,
            credentialOffer,
            credentialRequest,
            mapOf(
                "name" to "Alex",
                "height" to "175",
                "age" to "28",
                "sex" to "male"
            ),
            listOf(),
            "mock:uri",
            AnoncredsCredentialRevocationConfig(
                revocationRegistryDefinition,
                revocationRegistryDefinitionPrivate,
                9,
                tailsPath
            ),
            revocationStatusList
        )
        println("\t\tCREDENTIAL HANDLE: ${credential.handle}")

        println("\tPROCESSING HANDLE")
        credential.process(
            credentialRequestMetadata,
            linkSecret,
            credentialDefinition,
            revocationRegistryDefinition
        )
        println("\t\tCREDENTIAL HANDLE: ${credential.handle}")

        println("\tGETTING REVOCATION REGISTRY INDEX")
        val revocationRegistryIndex = credential.getRevocationRegistryIndex()
        println("\t\tREVOCATION REGISTRY INDEX: $revocationRegistryIndex")

        println("\tCREATING REVOCATION STATE")
        val revocationState = AnoncredsCredentialRevocationState.create(
            revocationRegistryDefinition,
            revocationStatusList,
            revocationRegistryIndex,
            tailsPath
        )
        println("\t\tREVOCATION STATE HANDLE: ${revocationState.handle}")

        println("\tCREATING PRESENTATION")
        val presentation = Presentation.create(
            presentationRequest = presentationRequest,
            credentials = listOf(
                Presentation.CredentialEntry(
                    credential,
                    timeCreateRevStatusList.toInt(),
                    revocationState
            )),
            credentialsProve = listOf(
                Presentation.CredentialProve(
                    0,
                    "attr1_referent",
                    false,
                    reveal = true
                ),
                Presentation.CredentialProve(
                    0,
                    "attr2_referent",
                    isPredicate = false,
                    reveal = false
                ),
                Presentation.CredentialProve(
                    0,
                    "attr4_referent",
                    isPredicate = false,
                    reveal = true
                ),
                Presentation.CredentialProve(
                    0,
                    "predicate1_referent",
                    isPredicate = true,
                    reveal = true
                )
            ),
            selfAttest = mapOf("attr3_referent" to "8-800-300"),
            linkSecret = linkSecret,
            schemas = mapOf("mock:uri" to schema),
            credentialDefinitions = mapOf("mock:uri" to credentialDefinition),
        )
        println("\t\tPRESENTATION HANDLE: ${presentation.handle}")

        println("\tVERIFYING PRESENTATION")
        val verify = presentation.verify(
            presentationRequest = presentationRequest,
            schemas = mapOf("mock:uri" to schema),
            credentialDefinitions = mapOf("mock:uri" to credentialDefinition),
            revocationRegistryDefinitions = mapOf("mock:uri" to revocationRegistryDefinition),
            revocationStatusLists = listOf(revocationStatusList),
            nonRevokedIntervalOverrides = listOf(
                Presentation.NonRevokedIntervalOverride(
                    overrideRevocationStatusListTimestamp = 12,
                    requestedFromTimestamp = 13,
                    revocationRegistryDefinitionId = "mock:uri"
                )
            )
        )
        println("\t\tVERIFICATION RESULT: $verify")

        assertTrue(verify)
    }

}