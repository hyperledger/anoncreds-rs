package io.iohk.atala.prism.anoncred

import anoncreds_wrapper.CredentialDefinitionConfig
import anoncreds_wrapper.Issuer
import anoncreds_wrapper.Prover
import anoncreds_wrapper.Schema
import anoncreds_wrapper.SignatureType
import kotlin.test.Test
import kotlin.test.assertTrue

@AndroidIgnore
class PrismProverTests {
    @Test
    fun test_PrismProver_createLinkSecret() {
        val prismProver = Prover()
        val linkSecret = prismProver.createLinkSecret()
        println(linkSecret.getBigNumber())
        println(linkSecret.getValue())
        assertTrue(linkSecret.getBigNumber().length > 0)
    }

    @Test
    fun test_PrismProver_createCredentialRequest() {
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
        val credentialOffer = prismIssuer.createCredentialOffer(
            "did:web:xyz/resource/schema",
            "did:web:xyz/resource/cred-def",
            cred.credentialKeyCorrectnessProof
        )

        val prismProver = Prover()
        val linkSecret = prismProver.createLinkSecret()
        val credentialRequest = prismProver.createCredentialRequest(
            "entropy",
            null,
            cred.credentialDefinition,
            linkSecret,
            "my-secret-id",
            credentialOffer
        )
        println(credentialRequest)
        assertTrue(true)
    }
}
