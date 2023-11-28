package anoncred.wrapper

import anoncreds_wrapper.AttributeValues
import anoncreds_wrapper.CredentialDefinitionConfig
import anoncreds_wrapper.Issuer
import anoncreds_wrapper.Nonce
import anoncreds_wrapper.Prover
import anoncreds_wrapper.RegistryType
import anoncreds_wrapper.Schema
import anoncreds_wrapper.SignatureType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@AndroidIgnore
class IssuerTests {
    @Test
    fun test_Issuer_createSchema() {
        val expectedSchema = Schema("Moussa", "1.0", listOf("name", "age"), "sample:uri")
        val scheme: Schema = Issuer().createSchema("Moussa", "1.0", "sample:uri", listOf("name", "age"))
        assertEquals(expectedSchema, scheme, "scheme not equal")
        assertEquals(expectedSchema.name, scheme.name, "name not correct")
        assertEquals(expectedSchema.version, scheme.version, "version not correct")
        assertEquals(expectedSchema.issuerId, scheme.issuerId, "issuerId not correct")
        assertEquals(expectedSchema.attrNames.size, scheme.attrNames.size, "attrNames size is not correct")
        expectedSchema.attrNames.forEach {
            assertTrue(scheme.attrNames.contains(it))
        }
    }

    @Test
    fun test_Issuer_createCredentialDefinition() {
        val issuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema: Schema = issuer.createSchema("Moussa", "1.0", "sample:uri", attributeNames)
        val cred = issuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        println(cred.credentialDefinition.getJson())
        println(cred.credentialDefinitionPrivate.getJson())
        println(cred.credentialKeyCorrectnessProof.getJson())
        assertTrue(true)
    }

    @Test
    fun test_Issuer_createRevocationRegistryDef() {
        val issuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = issuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = issuer.createRevocationRegistryDef(
            cred.credentialDefinition,
            "did:web:xyz/resource/cred-def",
            "did:web:xyz",
            "default-tag",
            RegistryType.CL_ACCUM,
            1000u
        )
        println("regDef IssuerId: ${rev.regDef.getIssuerId()}")
        println("regDef CredDefId: ${rev.regDef.getCredDefId()}")
        println("regDefPrivate: ${rev.regDefPrivate.getJson()}")
        assertTrue(true)
    }

    @Test
    fun test_Issuer_createRevocationStatusList() {
        val issuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = issuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = issuer.createRevocationRegistryDef(
            cred.credentialDefinition,
            "did:web:xyz/resource/cred-def",
            "did:web:xyz",
            "default-tag",
            RegistryType.CL_ACCUM,
            1000u
        )
        val revStatusList = issuer.createRevocationStatusList(
            "did:web:xyz/resource/rev-reg-def",
            rev.regDef,
            "did:web:xyz",
            null,
            true
        )
        println(revStatusList.getJson())
        assertTrue(true)
    }

    @Test
    fun test_Issuer_updateRevocationStatusListTimestampOnly() {
        val issuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = issuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = issuer.createRevocationRegistryDef(
            cred.credentialDefinition,
            "did:web:xyz/resource/cred-def",
            "did:web:xyz",
            "default-tag",
            RegistryType.CL_ACCUM,
            1000u
        )
        val revStatusList = issuer.createRevocationStatusList(
            "did:web:xyz/resource/rev-reg-def",
            rev.regDef,
            "did:web:xyz",
            null,
            true
        )
        val updatedRevStatusList = issuer.updateRevocationStatusListTimestampOnly(1000u, revStatusList)
        println(updatedRevStatusList.getJson())
        assertTrue(true)
    }

    @Test
    fun test_Issuer_updateRevocationStatusList() {
        val issuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = issuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = issuer.createRevocationRegistryDef(
            cred.credentialDefinition,
            "did:web:xyz/resource/cred-def",
            "did:web:xyz",
            "default-tag",
            RegistryType.CL_ACCUM,
            1000u
        )
        val revStatusList = issuer.createRevocationStatusList(
            "did:web:xyz/resource/rev-reg-def",
            rev.regDef,
            "did:web:xyz",
            null,
            true
        )
        val updatedRevStatusList = issuer.updateRevocationStatusList(null, listOf(1u), null, rev.regDef, revStatusList)
        println(updatedRevStatusList.getJson())
        assertTrue(true)
        Nonce().toString()
        Nonce()
    }

    @Test
    fun test_Issuer_createCredentialOffer() {
        val issuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = issuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val credentialOffer = issuer.createCredentialOffer("did:web:xyz/resource/schema", "did:web:xyz/resource/cred-def", cred.credentialKeyCorrectnessProof)
        println(credentialOffer.getJson())
        assertTrue(true)
    }

    @Test
    fun test_Issuer_createCredential() {
        val issuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = issuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val credentialOffer = issuer.createCredentialOffer("did:web:xyz/resource/schema", "did:web:xyz/resource/cred-def", cred.credentialKeyCorrectnessProof)
        val Prover = Prover()
        val linkSecret = Prover.createLinkSecret()
        val credentialRequest = Prover.createCredentialRequest("entropy", null, cred.credentialDefinition, linkSecret, "my-secret-id", credentialOffer)
        val credentialValues = listOf(AttributeValues("name", "Moussa"))
        val credential = issuer.createCredential(
            cred.credentialDefinition,
            cred.credentialDefinitionPrivate,
            credentialOffer,
            credentialRequest.request,
            credentialValues,
            null,
            null,
            null
        )
        println(credential.getJson())
        assertTrue(true)
    }
}
