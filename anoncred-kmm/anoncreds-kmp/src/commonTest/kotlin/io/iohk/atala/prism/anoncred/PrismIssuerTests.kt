package io.iohk.atala.prism.anoncred

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
class PrismIssuerTests {
    @Test
    fun test_PrismIssuer_createSchema() {
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
    fun test_PrismIssuer_createCredentialDefinition() {
        val prismIssuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema: Schema = prismIssuer.createSchema("Moussa", "1.0", "sample:uri", attributeNames)
        val cred = prismIssuer.createCredentialDefinition(
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
    fun test_PrismIssuer_createRevocationRegistryDef() {
        val prismIssuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = prismIssuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = prismIssuer.createRevocationRegistryDef(
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
    fun test_PrismIssuer_createRevocationStatusList() {
        val prismIssuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = prismIssuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = prismIssuer.createRevocationRegistryDef(
            cred.credentialDefinition,
            "did:web:xyz/resource/cred-def",
            "did:web:xyz",
            "default-tag",
            RegistryType.CL_ACCUM,
            1000u
        )
        val revStatusList = prismIssuer.createRevocationStatusList(
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
    fun test_PrismIssuer_updateRevocationStatusListTimestampOnly() {
        val prismIssuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = prismIssuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = prismIssuer.createRevocationRegistryDef(
            cred.credentialDefinition,
            "did:web:xyz/resource/cred-def",
            "did:web:xyz",
            "default-tag",
            RegistryType.CL_ACCUM,
            1000u
        )
        val revStatusList = prismIssuer.createRevocationStatusList(
            "did:web:xyz/resource/rev-reg-def",
            rev.regDef,
            "did:web:xyz",
            null,
            true
        )
        val updatedRevStatusList = prismIssuer.updateRevocationStatusListTimestampOnly(1000u, revStatusList)
        println(updatedRevStatusList.getJson())
        assertTrue(true)
    }

    @Test
    fun test_PrismIssuer_updateRevocationStatusList() {
        val prismIssuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = prismIssuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val rev = prismIssuer.createRevocationRegistryDef(
            cred.credentialDefinition,
            "did:web:xyz/resource/cred-def",
            "did:web:xyz",
            "default-tag",
            RegistryType.CL_ACCUM,
            1000u
        )
        val revStatusList = prismIssuer.createRevocationStatusList(
            "did:web:xyz/resource/rev-reg-def",
            rev.regDef,
            "did:web:xyz",
            null,
            true
        )
        val updatedRevStatusList = prismIssuer.updateRevocationStatusList(null, listOf(1u), null, rev.regDef, revStatusList)
        println(updatedRevStatusList.getJson())
        assertTrue(true)
        Nonce().toString()
        Nonce()
    }

    @Test
    fun test_PrismIssuer_createCredentialOffer() {
        val prismIssuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = prismIssuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val credentialOffer = prismIssuer.createCredentialOffer("did:web:xyz/resource/schema", "did:web:xyz/resource/cred-def", cred.credentialKeyCorrectnessProof)
        println(credentialOffer.getJson())
        assertTrue(true)
    }

    @Test
    fun test_PrismIssuer_createCredential() {
        val prismIssuer = Issuer()
        val attributeNames = listOf("name", "age")
        val schema = Schema("Moussa", "1.0", attributeNames, "sample:uri")
        val cred = prismIssuer.createCredentialDefinition(
            "did:web:xyz/resource/schema",
            schema,
            "did:web:xyz",
            "default-tag",
            SignatureType.CL,
            CredentialDefinitionConfig(true)
        )
        val credentialOffer = prismIssuer.createCredentialOffer("did:web:xyz/resource/schema", "did:web:xyz/resource/cred-def", cred.credentialKeyCorrectnessProof)
        val prismProver = Prover()
        val linkSecret = prismProver.createLinkSecret()
        val credentialRequest = prismProver.createCredentialRequest("entropy", null, cred.credentialDefinition, linkSecret, "my-secret-id", credentialOffer)
        val credentialValues = listOf(AttributeValues("name", "Moussa"))
        val credential = prismIssuer.createCredential(
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
