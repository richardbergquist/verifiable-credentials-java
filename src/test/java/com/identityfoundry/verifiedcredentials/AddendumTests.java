package com.identityfoundry.verifiedcredentials;

import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.TestUtil;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.credentialstatus.StatusList2021Entry;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2020LdSigner;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Addendum tests added.
 * These do not add additional tests. They are used to explore and understand and
 * demonstrate the code base.
 */
public class AddendumTests {

    private static final Logger logger = LoggerFactory.getLogger(AddendumTests.class);

    @Test
    void testCreateVC() throws Throwable {

        String firstName = "Salty";
        String surname = "Fisher";
        List aliases = List.of("Fish", "Bait");
        String address = "7/37 Snapper Bay Rd, Takapuna, Auckland, NZ";

        VerifiableCredential.Builder<? extends VerifiableCredential.Builder<?>> verifiableCredentialBuilder = VerifiableCredential.builder()
                //.base(payloadVerifiableCredential)
                .defaultContexts(true)
                .defaultTypes(true)  //adds the default 'VerifiableCredential' type
                .types(List.of("NameCredential")); // adds further VC types

        //String[] defaultTypeArray = VerifiableCredential.DEFAULT_JSONLD_TYPES;
        //Add other credential types to the default type alread
        //verifiableCredentialBuilder.types(List.of("NameCredential"));

        String jwtId = "urn:uuid:a87bdfb8-a7df-4bd9-ae0d-d883133538fe";
        if (jwtId != null) {
            verifiableCredentialBuilder.id(URI.create(jwtId));
        }

        String issuer = "https://identityfoundry.com/issuers/565049";
        if (issuer != null) {
            verifiableCredentialBuilder.issuer(URI.create(issuer));
        }

        Date notBeforeTime = JsonLDUtils.DATE_FORMAT.parse("2023-11-07T06:19:10Z");
        if (notBeforeTime != null) {
            verifiableCredentialBuilder.issuanceDate(notBeforeTime);
        }

        Date expirationTime = JsonLDUtils.DATE_FORMAT.parse("2023-11-07T07:19:10Z");
        if (expirationTime != null ) {
            verifiableCredentialBuilder.expirationDate(expirationTime);
        }


        //Create the credential subject from a map of claims
        LinkedHashMap<String , Object> claimsMap = new LinkedHashMap<>();

        LinkedHashMap<String , Object> namesMap = new LinkedHashMap<>();
        namesMap.put("firstName", firstName);
        namesMap.put("surname", surname);
        namesMap.put("aliases", aliases);
        claimsMap.put("names", namesMap);

        LinkedHashMap<String , Object> locationMap = new LinkedHashMap<>();
        locationMap.put("address", address);
        claimsMap.put("location", locationMap);

        CredentialSubject.Builder<? extends CredentialSubject.Builder<?>> credentialSubjectBuilder = CredentialSubject.builder()
                .id(new URI("https://identityfoundry.com/subjects/007"))
                .claims(claimsMap);
        CredentialSubject credentialSubject = credentialSubjectBuilder.build();
        verifiableCredentialBuilder.credentialSubject(credentialSubject);

        //Add credential status
        boolean addCredentialStatus = false; // turn this off
        if (addCredentialStatus) {
            StatusList2021Entry.Builder statusList2021EntryBuilder = StatusList2021Entry.builder()
                    .id(new URI("https://identityfoundry.com/credentials/status/12345"))
                    .statusListIndex("12345")
                    .statusListCredential(new URI("https://identityfoundry.com/credentials/status/3"))
                    .statusPurpose("revocation");
            StatusList2021Entry statusList2021Entry = statusList2021EntryBuilder.build();
            verifiableCredentialBuilder.credentialStatus(statusList2021Entry);
        }

        //Build the VC
        VerifiableCredential verifiableCredential = verifiableCredentialBuilder.build();
        assertNotNull(verifiableCredential, "verifiableCredential is not null");

        //Signing using proof methods
        // https://w3c-ccg.github.io/vc-extension-registry/#proof-methods
        URI verificationMethod = URI.create("did:sov:1yvXbmgPoUm4dl66D7KhyD#keys-1");
        Date created = Date.from(Instant.now());
        String domain = null;
        String nonce = "c0ae1c8e-c7e7-469f-b252-86e6a0e7387e";

        //RsaSignature2018 option
        //RsaSignature2018LdSigner signer = new RsaSignature2018LdSigner(TestUtil.testRSAPrivateKey);
        //signer.setVerificationMethod(verificationMethod);
        //signer.setCreated(created);
        //signer.setDomain(domain);
        //signer.setNonce(nonce);

        //Ed25519Signature2020 - is the most common
        Ed25519Signature2020LdSigner signer = new Ed25519Signature2020LdSigner(TestUtil.testEd25519PrivateKey);
        signer.setVerificationMethod(verificationMethod);
        signer.setCreated(created);
        signer.setProofPurpose("assertionMethod");

        LdProof ldProof = signer.sign(verifiableCredential, true, false);

        String vcJson = verifiableCredential.toJson(true);
        logger.debug("Built VC json:{}", vcJson);

    }
}
