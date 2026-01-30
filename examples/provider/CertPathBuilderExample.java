/* CertPathBuilderExample.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Example demonstrating CertPathBuilder and CertPathValidator with wolfJCE.
 *
 * This example uses PKIX CertPathBuilder to build certificate chains from a
 * target certificate to a trusted root CA. It also uses PKIX CertPathValidator
 * to validate a pre-built certificate chain against trust anchors.
 *
 * CertPathBuilder: Simple chain (server cert to root CA)
 * CertPathBuilder: Chain with intermediates
 * CertPathValidator: Validate a manually constructed chain
 * Combined: Build with CertPathBuilder, validate with CertPathValidator
 */
public class CertPathBuilderExample {

    /* Certificate file paths (relative to examples/build/provider) */
    private static final String CA_KEYSTORE =
        "../../../examples/certs/ca-server-rsa-2048.jks";
    private static final String SERVER_CERT =
        "../../../examples/certs/server-cert.der";
    private static final String CA_CERT =
        "../../../examples/certs/ca-cert.der";

    /* Intermediate chain paths */
    private static final String INT_SERVER_CERT =
        "../../../examples/certs/intermediate/server-int-cert.pem";
    private static final String INT1_CERT =
        "../../../examples/certs/intermediate/ca-int-cert.pem";
    private static final String INT2_CERT =
        "../../../examples/certs/intermediate/ca-int2-cert.pem";

    /* KeyStore password */
    private static final String KEYSTORE_PASS = "wolfsslpassword";

    /**
     * Load X509Certificate from file.
     *
     * @param path path to certificate file (DER or PEM format)
     * @return X509Certificate loaded from file
     * @throws Exception on error loading certificate
     */
    private static X509Certificate loadCert(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(path)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Load KeyStore from file.
     *
     * @param path path to KeyStore file
     * @param password KeyStore password
     * @return KeyStore loaded from file
     * @throws Exception on error loading KeyStore
     */
    private static KeyStore loadKeyStore(String path, String password)
        throws Exception {

        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(path)) {
            ks.load(is, password.toCharArray());
        }
        return ks;
    }

    /**
     * Print certificate chain information.
     *
     * @param result the CertPathBuilderResult to print
     */
    private static void printResult(PKIXCertPathBuilderResult result) {

        CertPath path = result.getCertPath();
        TrustAnchor anchor = result.getTrustAnchor();
        List<? extends Certificate> certs = path.getCertificates();

        System.out.println("  Certificate chain built successfully!");
        System.out.println("  Chain length: " + certs.size() +
            " certificate(s)");
        System.out.println();

        /* Print each certificate in the chain */
        for (int i = 0; i < certs.size(); i++) {
            X509Certificate cert = (X509Certificate) certs.get(i);
            String prefix = (i == 0) ? "  [Target]  " : "  [CA " + i + "]    ";
            System.out.println(prefix + "Subject: " +
                cert.getSubjectX500Principal().getName());
            System.out.println("            Issuer:  " +
                cert.getIssuerX500Principal().getName());
        }

        /* Print trust anchor */
        X509Certificate anchorCert = anchor.getTrustedCert();
        System.out.println("  [Anchor]  Subject: " +
            anchorCert.getSubjectX500Principal().getName());
        System.out.println();
    }

    /**
     * Builds a simple certificate path from server-cert.der to the root
     * CA (ca-cert.der). This is a direct chain with no intermediate
     * certificates.
     */
    private static void simpleChainExample() throws Exception {

        System.out.println("=================================================");
        System.out.println("Build Simple Certificate Chain");
        System.out.println("  server-cert.der -> ca-cert.der");
        System.out.println("=================================================");
        System.out.println();

        /* Load the KeyStore containing the trusted root CA */
        KeyStore trustStore = loadKeyStore(CA_KEYSTORE, KEYSTORE_PASS);

        /* Load the target (end-entity) certificate */
        X509Certificate serverCert = loadCert(SERVER_CERT);

        /* Create a CertStore containing the target certificate */
        Collection<Certificate> certCollection = new ArrayList<>();
        certCollection.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters with trust anchors from KeyStore */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(trustStore, null);

        /* Disable revocation checking for this example */
        params.setRevocationEnabled(false);

        /* Add CertStore containing certificates to search */
        params.addCertStore(certStore);

        /* Set selector to identify the target certificate */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build the certificate path using wolfJCE */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "wolfJCE");
        CertPathBuilderResult result = cpb.build(params);

        /* Print results */
        printResult((PKIXCertPathBuilderResult) result);
    }

    /**
     * Build a certificate path with intermediate CAs. Builds a path from
     * server-int-cert.pem through two intermediate CAs to the root CA:
     *
     * server-int-cert.pem - ca-int2-cert.pem - ca-int-cert.pem - ca-cert.pem
     */
    private static void intermediateChainExample() throws Exception {

        System.out.println("=================================================");
        System.out.println("Build Certificate Chain with Intermediates");
        System.out.println("  server-int-cert -> ca-int2 -> ca-int -> ca-cert");
        System.out.println("=================================================");
        System.out.println();

        /* Load the KeyStore containing the trusted root CA */
        KeyStore trustStore = loadKeyStore(CA_KEYSTORE, KEYSTORE_PASS);

        /* Load all certificates in the chain */
        X509Certificate serverCert = loadCert(INT_SERVER_CERT);
        X509Certificate int2Cert = loadCert(INT2_CERT);
        X509Certificate int1Cert = loadCert(INT1_CERT);

        /* Create a CertStore containing target and intermediate certs */
        Collection<Certificate> certCollection = new ArrayList<>();
        certCollection.add(serverCert);
        certCollection.add(int2Cert);
        certCollection.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters with trust anchors from KeyStore */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(trustStore, null);

        /* Disable revocation checking for this example */
        params.setRevocationEnabled(false);

        /* Add CertStore containing certificates to search */
        params.addCertStore(certStore);

        /* Set selector to identify the target certificate */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build the certificate path using wolfJCE */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "wolfJCE");
        CertPathBuilderResult result = cpb.build(params);

        /* Print results */
        printResult((PKIXCertPathBuilderResult) result);
    }

    /**
     * Print CertPathValidator result information.
     *
     * @param result the CertPathValidatorResult to print
     * @param path the CertPath that was validated
     */
    private static void printValidatorResult(PKIXCertPathValidatorResult result,
        CertPath path) {

        TrustAnchor anchor = result.getTrustAnchor();
        PublicKey pubKey = result.getPublicKey();
        List<? extends Certificate> certs = path.getCertificates();

        System.out.println("  Certificate chain validated successfully!");
        System.out.println("  Chain length: " + certs.size() +
            " certificate(s)");
        System.out.println();

        /* Print each certificate in the chain */
        for (int i = 0; i < certs.size(); i++) {
            X509Certificate cert = (X509Certificate) certs.get(i);
            String prefix = (i == 0) ? "  [Target]  " : "  [CA " + i + "]    ";
            System.out.println(prefix + "Subject: " +
                cert.getSubjectX500Principal().getName());
            System.out.println("            Issuer:  " +
                cert.getIssuerX500Principal().getName());
        }

        /* Print trust anchor */
        X509Certificate anchorCert = anchor.getTrustedCert();
        System.out.println("  [Anchor]  Subject: " +
            anchorCert.getSubjectX500Principal().getName());
        System.out.println("  Public Key Algo: " + pubKey.getAlgorithm());
        System.out.println();
    }

    /**
     * Validate a manually constructed certificate path.
     *
     * This example shows how to use CertPathValidator to validate
     * a manually-built certificate chain.
     */
    private static void validatorExample() throws Exception {

        System.out.println("=================================================");
        System.out.println("CertPathValidator with Manual Chain)");
        System.out.println("  Validate: server-cert.der -> ca-cert.der");
        System.out.println("=================================================");
        System.out.println();

        /* Load the KeyStore containing the trusted root CA */
        KeyStore trustStore = loadKeyStore(CA_KEYSTORE, KEYSTORE_PASS);

        /* Load the certificate to validate */
        X509Certificate serverCert = loadCert(SERVER_CERT);

        /* Create a CertPath from the certificate list.
         * The list should be ordered from target to closest-to-anchor.
         * Trust anchor is not included in the path. */
        List<Certificate> certList = new ArrayList<>();
        certList.add(serverCert);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath path = cf.generateCertPath(certList);

        /* Create PKIXParameters with trust anchors from KeyStore */
        PKIXParameters params = new PKIXParameters(trustStore);

        /* Disable revocation checking for this example */
        params.setRevocationEnabled(false);

        /* Validate the certificate path using wolfJCE */
        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", "wolfJCE");
        CertPathValidatorResult result = cpv.validate(path, params);

        /* Print results */
        printValidatorResult((PKIXCertPathValidatorResult) result, path);
    }

    /**
     * Build a path with CertPathBuilder, then validate with
     * CertPathValidator.
     *
     * This example demonstrates using both APIs together. CertPathBuilder
     * constructs the chain, then CertPathValidator re-validates it.
     */
    private static void builderAndValidatorExample() throws Exception {

        System.out.println("=================================================");
        System.out.println("CertPathBuilder + CertPathValidator");
        System.out.println("  Build chain, then validate it separately");
        System.out.println("=================================================");
        System.out.println();

        /* Load the KeyStore containing the trusted root CA */
        KeyStore trustStore = loadKeyStore(CA_KEYSTORE, KEYSTORE_PASS);

        /* Load all certificates */
        X509Certificate serverCert = loadCert(INT_SERVER_CERT);
        X509Certificate int2Cert = loadCert(INT2_CERT);
        X509Certificate int1Cert = loadCert(INT1_CERT);

        /* Create a CertStore containing target and intermediate certs */
        Collection<Certificate> certCollection = new ArrayList<>();
        certCollection.add(serverCert);
        certCollection.add(int2Cert);
        certCollection.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters builderParams =
            new PKIXBuilderParameters(trustStore, null);
        builderParams.setRevocationEnabled(false);
        builderParams.addCertStore(certStore);

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        builderParams.setTargetCertConstraints(selector);

        /* Step 1: Build the certificate path */
        System.out.println("  Step 1: Building certificate path...");
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "wolfJCE");
        PKIXCertPathBuilderResult buildResult =
            (PKIXCertPathBuilderResult) cpb.build(builderParams);

        CertPath builtPath = buildResult.getCertPath();
        System.out.println("  Built path with " +
            builtPath.getCertificates().size() + " certificate(s)");
        System.out.println();

        /* Step 2: Validate the built path with CertPathValidator */
        System.out.println("  Step 2: Validating built path...");
        PKIXParameters validatorParams = new PKIXParameters(trustStore);
        validatorParams.setRevocationEnabled(false);

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", "wolfJCE");
        PKIXCertPathValidatorResult validateResult =
            (PKIXCertPathValidatorResult) cpv.validate(builtPath,
            validatorParams);

        /* Print validation results */
        printValidatorResult(validateResult, builtPath);
    }

    public static void main(String[] args) {

        System.out.println();
        System.out.println("CertPathBuilder and CertPathValidator Example");
        System.out.println("=================================================");
        System.out.println();

        /* Install wolfJCE as highest priority provider */
        Security.insertProviderAt(new WolfCryptProvider(), 1);
        System.out.println("Installed wolfJCE provider");
        System.out.println();

        try {
            /* Run CertPathBuilder examples */
            simpleChainExample();
            intermediateChainExample();

            /* Run CertPathValidator examples */
            validatorExample();
            builderAndValidatorExample();

            System.out.println("All examples completed successfully!");
            System.out.println();

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

