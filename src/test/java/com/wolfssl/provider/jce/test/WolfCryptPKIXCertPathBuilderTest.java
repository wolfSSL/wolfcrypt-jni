/* WolfCryptPKIXCertPathBuilderTest.java
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.junit.Test;
import org.junit.BeforeClass;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.lang.IllegalArgumentException;
import java.util.Calendar;
import java.util.Date;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLX509StoreCtx;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class WolfCryptPKIXCertPathBuilderTest {

    protected String provider = "wolfJCE";

    /* Example KeyStore file paths */
    protected static String jksCaServerRSA2048 = null;
    protected static String jksCaServerECC256 = null;

    /* Example KeyStore type */
    protected static String keyStoreType = "JKS";

    /* Example KeyStore password */
    protected static String keyStorePass = "wolfsslpassword";

    /* Example Certificate file paths */
    protected static String serverCertDer    = null; /* server-cert.der */
    protected static String serverEccDer     = null; /* server-ecc.der */
    protected static String clientCertDer    = null; /* client-cert.der */
    protected static String clientEccCertDer = null; /* client-ecc-cert.der */
    protected static String caCertDer        = null; /* ca-cert.der */
    protected static String caEccCertDer     = null; /* ca-ecc-cert.der */

    /* RSA-based cert chain with intermediates:
     * server/peer: server-int-cert.pem/der
     * intermediate CA 2: ca-int2-cert.pem/der
     * intermediate CA 1: ca-int-cert.pem/der
     * root CA: ca-cert.pem */
    protected static String intRsaServerCertDer = null;
    protected static String intRsaInt2CertDer   = null;
    protected static String intRsaInt1CertDer   = null;

    /* ECC-based cert chain with intermediates:
     * server/peer: server-int-ecc-cert.pem/der
     * intermediate CA 2: ca-in2-ecc-cert.pem/der
     * intermediate CA 1: ca-int-ecc-cert.pem/der
     * root CA: ca-ecc-cert.pem */
    protected static String intEccServerCertDer = null;
    protected static String intEccInt2CertDer   = null;
    protected static String intEccInt1CertDer   = null;

    /* Test certificates created with expired validity period.
     * These certificates were created with validity from May 1, 2014 to
     * April 30, 2016. They are used to test custom date validation with
     * PKIXBuilderParameters.setDate(). Not put in files or tied into
     * update script since these are expected to be expired. */

    /* Root CA cert (self-signed, expired April 30, 2016)
     * Subject: CN=wolfSSL Test Expired Root CA */
    private static final String EXPIRED_ROOT_PEM =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDCzCCAfOgAwIBAgIBATANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBx3b2xm\n" +
        "U1NMIFRlc3QgRXhwaXJlZCBSb290IENBMB4XDTE0MDUwMTEyMDAwMFoXDTE2MDQz\n" +
        "MDEyMDAwMFowJzElMCMGA1UEAwwcd29sZlNTTCBUZXN0IEV4cGlyZWQgUm9vdCBD\n" +
        "QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMjoTxkI4HNEftkfVAUZ\n" +
        "KV6puIcQmKmgbEki/5dgmVyBgBMBxohIgsFROUw2USWYX/JAwRKEO54ayCINsdQJ\n" +
        "uC3rsm1jxduhmzp0XcaxTDJqWLNzXKWpFQklwE1xpgIIKde5c9qtky2fTIVO5gNK\n" +
        "E7VDFrebuB7qXyfmxDl/A4ACFNbcvmgadKswJZ69ik3iIoqresZe1yr36Febah0/\n" +
        "ztpqjepJWfxg8tGUv/6ibreqLpikfRADbv1b5bb/SSGWpog/MxHM90uzwrBhou6c\n" +
        "5doJ7DiobKQ0fR3gGnyPgoSuFHgwzn38u6U/TmyEYQsmSEYzsoo3RBG5kxdsO7tU\n" +
        "JDsCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD\n" +
        "VR0OBBYEFB3hLk4AObSAXGouW4CTPbRiXBv7MA0GCSqGSIb3DQEBCwUAA4IBAQC1\n" +
        "1L9+sMOecn2engXaVI0Tq/+EX3IRkR/gC0AH7Wo4RvgN5JYNdjtAaFfCJy5CesB8\n" +
        "J34rJetE0HNNWzHE/MlOg9IKBu7lJ67tLvJOsAy2ksqR67d2uBXW9Tmab0hHeCZj\n" +
        "sDuky8dVwf4PVxzcPS9mKaihVBUSBIf/0AsDQuLahdqHek1f0Kb2OgFd4eAWTJUz\n" +
        "SMtuwsnKNg2KJ3mSbo3Boa/PJfnpbAw/FBR7zPf3Fl6874dFDfQj5cRZEGaJ40yR\n" +
        "O/8ygpr0vnjHs53LOcXwZeNTeSkoKFRCw4mrSN3k8PLN4wRiCEDMsckL9ySfbix5\n" +
        "RRK1n0IV3OspJlzZyxy/\n" +
        "-----END CERTIFICATE-----\n";

    /* Intermediate CA cert (signed by Root, expired April 30, 2016)
     * Subject: CN=wolfSSL Test Expired Intermediate CA
     * Issuer: CN=wolfSSL Test Expired Root CA */
    private static final String EXPIRED_INTERMEDIATE_PEM =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDNDCCAhygAwIBAgIBAjANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBx3b2xm\n" +
        "U1NMIFRlc3QgRXhwaXJlZCBSb290IENBMB4XDTE0MDUwMTEyMDAwMFoXDTE2MDQz\n" +
        "MDEyMDAwMFowLzEtMCsGA1UEAwwkd29sZlNTTCBUZXN0IEV4cGlyZWQgSW50ZXJt\n" +
        "ZWRpYXRlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2IZfL2Hj\n" +
        "fMrcKk+ep0Ryl8wGQkDF8WROjrtM1h9l93H2LGVAxT9E6fVNCE3bEMZ+Ilvh764N\n" +
        "hxw66xqBxcqkx/eSzkbqei4aQmIpzFXnYI+s2GbaJEZiTUTPqAewWnZuo8t91RTd\n" +
        "C+HgSLfDr1CFRsPWI0m0k5f3b4sW8n9IffPhUTtmYPv0H1di2QFLXs18fx5XvUAH\n" +
        "3m6vrbxBUXaEYYSOHuWuS3cM7wPvJhYCVPQDQ/iJrPDG7V/+dOMk2qTq9jtp2DYi\n" +
        "+UeUR2LbtvGdWLAQeOg4GKJtrPnr++rlSaHrOguXsUKy5lVvC9T+EonbJc8Dwycf\n" +
        "f3blt6DRAnPFKQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\n" +
        "AwIBBjAdBgNVHQ4EFgQUIUpdgKnOEVk0edt5Y6dEcNJ5alIwHwYDVR0jBBgwFoAU\n" +
        "HeEuTgA5tIBcai5bgJM9tGJcG/swDQYJKoZIhvcNAQELBQADggEBADy1UJPoDgk8\n" +
        "Nrmbk/pvGV8iXaQxzAQOe1LcDKZzIuD+eM/mD8F6+inwNob1UNVj3vLtztYDmhUu\n" +
        "dlu3s6M565MysXoBXe9gEiZ4PJsmXoeV6G3+F3iIQbIBPfE6gyb0nWvjTQtfLfdJ\n" +
        "l+bYTeULopKd4FBAGqVFlGYrB9rMHu3XUJjx+D5Qxa9KKpnq5RAfE5DI8ND4qzN2\n" +
        "t5FrtUr0eqeO6GvAS0ALsNBRP7UPae0FGBf41m4dku8g4PNOJv1GpBiqX/neNDNE\n" +
        "Yt7LkwDOMrxzloy3Kn7gGbXpiUQf1PJr6cnvj3A63odt1YVI7vDhictKR/8b7k47\n" +
        "YogNNm7pLSI=\n" +
        "-----END CERTIFICATE-----\n";

    /* End-entity/user cert (signed by Intermediate, expired April 30, 2016)
     * Subject: CN=wolfSSL Test Expired User
     * Issuer: CN=wolfSSL Test Expired Intermediate CA */
    private static final String EXPIRED_USER_PEM =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDQzCCAiugAwIBAgIBAzANBgkqhkiG9w0BAQsFADAvMS0wKwYDVQQDDCR3b2xm\n" +
        "U1NMIFRlc3QgRXhwaXJlZCBJbnRlcm1lZGlhdGUgQ0EwHhcNMTQwNTAxMTIwMDAw\n" +
        "WhcNMTYwNDMwMTIwMDAwWjAkMSIwIAYDVQQDDBl3b2xmU1NMIFRlc3QgRXhwaXJl\n" +
        "ZCBVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlzq/KCZKOvcQ\n" +
        "xyykcD4HPJ/vrdrN0oDvsQVhKarCfgLLKss1LDHuZcj3lXS+oVZaluSRpGdssYxw\n" +
        "hy7BGiL7/CLZJ4G7B97qZMVl4Jp/MZVfkckatJamuUM0uojWglbeK3te683qmkVv\n" +
        "6jMOXJmqXwo2syJbHyN6dp2g0lTukQCY8TU5fBR8U34g9iLN+rIfYLWkyt188m/J\n" +
        "q/noBunNPF/WMD+DfdzDzWbtBN1M3303e5ZRS5izZrJoif1ZluDlg8sna2C9zEcj\n" +
        "x0+aqP3WJghwsBq3elzJiG8SE9a+Ay8ZBBUhpk8lOmTIjvM1NiNV6CXfVOTl7sTV\n" +
        "O1nIlYm/ywIDAQABo3UwczAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAT\n" +
        "BgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUAPlQn5MAfVyBqtst44nhebkU\n" +
        "EtkwHwYDVR0jBBgwFoAUIUpdgKnOEVk0edt5Y6dEcNJ5alIwDQYJKoZIhvcNAQEL\n" +
        "BQADggEBAElZB/FraMTHb6f0CZGVTU/20RHMZMlbjP+OKSJO/LKr08s648glQrqu\n" +
        "K4ROxJxt5dnxy/Q2mp5kAkbarSiwjqsfbImexOqiiQXVEGOW2G45a8BQQEHrhaYo\n" +
        "BMWxC/3X5peKZ7nQiSoL1kDU38ZpINLyB7eTBjpKNXkvvQnPOaPHg5HZYWaDFunq\n" +
        "OS07L9LSGW4AGOMZW6KG4lTjzGuBhEVycXSbupjePkDDjqHPFtSapW3niqH5iL7y\n" +
        "QJbpKjSJimpKTHyciclWAvF1ZYBKoFHcLQkoRiVwvyO4eDekzRmfJ7bsTm1EBZZa\n" +
        "cBdF0KRyJbeBYow7CUSMWYeODNLm+4A=\n" +
        "-----END CERTIFICATE-----\n";

    /**
     * Test if this environment is Android.
     * @return true if Android, otherwise false
     */
    private static boolean isAndroid() {
        if (System.getProperty("java.runtime.name").contains("Android")) {
            return true;
        }
        return false;
    }

    /**
     * Check if SUN provider is available (not available on Android).
     *
     * @return true if SUN provider is available, otherwise false
     */
    private static boolean isSunProviderAvailable() {
        return (Security.getProvider("SUN") != null);
    }

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Rule to check if CertPathBuilder is supported (requires wolfSSL 5.8.0+),
     * skips tests if not. */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule certPathBuilderSupported = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    Assume.assumeTrue("CertPathBuilder requires wolfSSL 5.8.0+",
                        WolfSSLX509StoreCtx.isSupported());
                    base.evaluate();
                }
            };
        }
    };

    /* Rule to check if cert files are available, skips tests if not. */
    @Rule(order = Integer.MIN_VALUE + 2)
    public TestRule certFilesAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    File f = new File(jksCaServerRSA2048);
                    Assume.assumeTrue("Test cert files not available: " +
                        jksCaServerRSA2048, f.exists());
                    base.evaluate();
                }
            };
        }
    };

    @BeforeClass
    public static void testSetupAndProviderInstallation()
        throws Exception, NoSuchProviderException {

        String certPre = "";
        String jksExt = ".jks";

        System.out.println("JCE WolfCryptPKIXCertPathBuilder Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        if (isAndroid()) {
            /* On Android, example certs/keys/KeyStores are on SD card */
            certPre = "/data/local/tmp/";

            /* On Android, KeyStore files are .bks and type is BKS */
            jksExt = ".bks";
            keyStoreType = "BKS";
        }

        /* Set paths to example certs/keys/KeyStores */
        jksCaServerRSA2048 =
            certPre.concat("examples/certs/ca-server-rsa-2048").concat(jksExt);
        jksCaServerECC256  =
            certPre.concat("examples/certs/ca-server-ecc-256").concat(jksExt);

        serverCertDer =
            certPre.concat("examples/certs/server-cert.der");
        serverEccDer =
            certPre.concat("examples/certs/server-ecc.der");
        caCertDer =
            certPre.concat("examples/certs/ca-cert.der");

        clientCertDer =
            certPre.concat("examples/certs/client-cert.der");
        clientEccCertDer =
            certPre.concat("examples/certs/client-ecc-cert.der");
        caEccCertDer =
            certPre.concat("examples/certs/ca-ecc-cert.der");

        intRsaServerCertDer =
            certPre.concat(
                "examples/certs/intermediate/server-int-cert.pem");
        intRsaInt1CertDer =
            certPre.concat(
                "examples/certs/intermediate/ca-int-cert.pem");
        intRsaInt2CertDer =
            certPre.concat(
                "examples/certs/intermediate/ca-int2-cert.pem");

        intEccServerCertDer =
            certPre.concat(
                "examples/certs/intermediate/server-int-ecc-cert.der");
        intEccInt1CertDer =
            certPre.concat(
                "examples/certs/intermediate/ca-int-ecc-cert.der");
        intEccInt2CertDer =
            certPre.concat(
                "examples/certs/intermediate/ca-int2-ecc-cert.der");
    }

    /**
     * Create KeyStore object from KeyStore file.
     *
     * @param file    KeyStore file to load into new object
     * @param jksPass password used to load the KeyStore
     *
     * @return KeyStore object loaded from file
     *
     * @throws IllegalArgumentException if file is null
     * @throws FileNotFoundException if file does not exist
     * @throws KeyStoreException if KeyStore cannot be created
     * @throws IOException if file cannot be read
     * @throws NoSuchAlgorithmException if algorithm not available
     * @throws CertificateException if certificate error occurs
     */
    private KeyStore createKeyStoreFromFile(String file, String jksPass)
        throws IllegalArgumentException, FileNotFoundException,
               KeyStoreException, IOException, NoSuchAlgorithmException,
               CertificateException {

        if (file == null) {
            throw new IllegalArgumentException(
                "Input file is null when creating KeyStore");
        }

        KeyStore store = KeyStore.getInstance(keyStoreType);
        try (InputStream stream = new FileInputStream(file)) {
            store.load(stream, jksPass.toCharArray());
        }

        return store;
    }

    /**
     * Load X509Certificate from file.
     */
    private X509Certificate loadCertFromFile(String file)
        throws FileNotFoundException, CertificateException, IOException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(file)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Check PKIXCertPathBuilderResult is valid.
     */
    private void checkPKIXCertPathBuilderResult(
        CertPathBuilderResult result, X509Certificate expectedAnchorCert,
        PublicKey expectedPublicKey) {

        PKIXCertPathBuilderResult pResult = null;
        TrustAnchor anchor = null;
        CertPath path = null;
        PublicKey pubKey = null;

        /* Check not null and of type PKIXCertPathBuilderResult */
        assertNotNull(result);
        assertTrue(result instanceof PKIXCertPathBuilderResult);
        pResult = (PKIXCertPathBuilderResult) result;

        /* Check CertPath is not null */
        path = pResult.getCertPath();
        assertNotNull(path);

        /* Check TrustAnchor matches expected */
        anchor = pResult.getTrustAnchor();
        assertNotNull(anchor);
        assertNotNull(anchor.getTrustedCert());
        assertEquals(anchor.getTrustedCert(), expectedAnchorCert);

        /* Check PublicKey returned matches expected target cert */
        pubKey = pResult.getPublicKey();
        assertNotNull(pubKey);
        assertEquals(pubKey, expectedPublicKey);
    }

    @Test
    public void testGetInstanceWolfJCE() throws NoSuchAlgorithmException,
        NoSuchProviderException {

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        assertNotNull(cpb);
        assertEquals(provider, cpb.getProvider().getName());
    }

    /**
     * Test building a simple single-cert path from target to root CA.
     * Target: server-cert.der
     * CA: ca-cert.der (in KeyStore)
     */
    @Test
    public void testSingleCertBuildRSA()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate caCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load CA cert for expected comparison */
        caCert = loadCertFromFile(caCertDer);

        /* Load server cert for target and CertStore */
        serverCert = loadCertFromFile(serverCertDer);
        certCollection.add(serverCert);

        /* Create CertStore with target cert */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build cert path */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        checkPKIXCertPathBuilderResult(result, caCert,
            serverCert.getPublicKey());

        /* Verify path contains the target certificate */
        CertPath path = ((PKIXCertPathBuilderResult) result).getCertPath();
        assertEquals(1, path.getCertificates().size());
        assertEquals(serverCert, path.getCertificates().get(0));
    }

    /**
     * Test building a simple single-cert path from target to root CA (ECC).
     * Target: server-ecc.der
     * CA: ca-ecc-cert.der (in KeyStore)
     */
    @Test
    public void testSingleCertBuildECC()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate caCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-ecc-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerECC256, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load CA cert for expected comparison */
        caCert = loadCertFromFile(caEccCertDer);

        /* Load server cert for target and CertStore */
        serverCert = loadCertFromFile(serverEccDer);
        certCollection.add(serverCert);

        /* Create CertStore with target cert */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build cert path */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        checkPKIXCertPathBuilderResult(result, caCert,
            serverCert.getPublicKey());

        /* Verify path contains the target certificate */
        CertPath path = ((PKIXCertPathBuilderResult) result).getCertPath();
        assertEquals(1, path.getCertificates().size());
        assertEquals(serverCert, path.getCertificates().get(0));
    }

    /**
     * Test building RSA cert chain with intermediates.
     * Chain:
     *     Root CA (ca-cert.der) - in KeyStore
     *         Intermediate CA 1 (ca-int-cert.pem) - in CertStore
     *             Intermediate CA 2 (ca-int2-cert.pem) - in CertStore
     *                 Peer (server-int-cert.pem) - target
     */
    @Test
    public void testCertChainBuildRSA()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate int2Cert = null;
        X509Certificate int1Cert = null;
        X509Certificate caCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load CA cert for expected comparison */
        caCert = loadCertFromFile(caCertDer);

        /* Load server cert (target) */
        serverCert = loadCertFromFile(intRsaServerCertDer);
        certCollection.add(serverCert);

        /* Load intermediate CA 2 */
        int2Cert = loadCertFromFile(intRsaInt2CertDer);
        certCollection.add(int2Cert);

        /* Load intermediate CA 1 */
        int1Cert = loadCertFromFile(intRsaInt1CertDer);
        certCollection.add(int1Cert);

        /* Create CertStore with all certs */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build cert path */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        checkPKIXCertPathBuilderResult(result, caCert,
            serverCert.getPublicKey());

        /* Verify path contains the correct certificates in order */
        CertPath path = ((PKIXCertPathBuilderResult) result).getCertPath();
        assertEquals(3, path.getCertificates().size());
        assertEquals(serverCert, path.getCertificates().get(0));
        assertEquals(int2Cert, path.getCertificates().get(1));
        assertEquals(int1Cert, path.getCertificates().get(2));
    }

    /**
     * Test building ECC certificate chain with intermediates.
     * Chain:
     *     Root CA (ca-ecc-cert.der) - in KeyStore
     *         Intermediate CA 1 (ca-int-ecc-cert.der) - in CertStore
     *             Intermediate CA 2 (ca-int2-ecc-cert.der) - in CertStore
     *                 Peer (server-int-ecc-cert.der) - target
     */
    @Test
    public void testCertChainBuildECC()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate int2Cert = null;
        X509Certificate int1Cert = null;
        X509Certificate caCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-ecc-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerECC256, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load CA cert for expected comparison */
        caCert = loadCertFromFile(caEccCertDer);

        /* Load server cert (target) */
        serverCert = loadCertFromFile(intEccServerCertDer);
        certCollection.add(serverCert);

        /* Load intermediate CA 2 */
        int2Cert = loadCertFromFile(intEccInt2CertDer);
        certCollection.add(int2Cert);

        /* Load intermediate CA 1 */
        int1Cert = loadCertFromFile(intEccInt1CertDer);
        certCollection.add(int1Cert);

        /* Create CertStore with all certs */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build cert path */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        checkPKIXCertPathBuilderResult(result, caCert,
            serverCert.getPublicKey());

        /* Verify path contains the correct certificates in order */
        CertPath path = ((PKIXCertPathBuilderResult) result).getCertPath();
        assertEquals(3, path.getCertificates().size());
        assertEquals(serverCert, path.getCertificates().get(0));
        assertEquals(int2Cert, path.getCertificates().get(1));
        assertEquals(int1Cert, path.getCertificates().get(2));
    }

    /**
     * Test that building fails when target certificate cannot be found.
     */
    @Test
    public void testBuildFailsNoTargetCert()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        KeyStore store = null;

        /* Use example KeyStore that has ca-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Create empty CertStore */
        Collection<Certificate> emptyCertCollection = new ArrayList<>();
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(emptyCertCollection));

        /* Create PKIXBuilderParameters with selector for non-existent cert */
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject("CN=NonExistentCert");

        PKIXBuilderParameters params = new PKIXBuilderParameters(store,
            selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Try to build cert path - should fail */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException when target not found");
        } catch (CertPathBuilderException e) {
            /* Expected */
        }
    }

    /**
     * Test that building fails when intermediate cert is missing from
     * CertStore.
     */
    @Test
    public void testBuildFailsMissingIntermediate()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load server cert that requires intermediates */
        serverCert = loadCertFromFile(intRsaServerCertDer);
        certCollection.add(serverCert);

        /* Create CertStore with only target cert (missing intermediates) */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Try to build cert path - should fail */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException when intermediate " +
                 "cert is missing");
        } catch (CertPathBuilderException e) {
            /* Expected */
        }
    }

    /**
     * Test that building fails when no trust anchor matches.
     */
    @Test
    public void testBuildFailsNoMatchingTrustAnchor()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        KeyStore store = null;
        X509Certificate clientCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-cert.der as trusted root (RSA) */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load client ECC cert (signed by ECC CA, not RSA CA in KeyStore) */
        clientCert = loadCertFromFile(clientEccCertDer);
        certCollection.add(clientCert);

        /* Create CertStore with client cert */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(clientCert);
        params.setTargetCertConstraints(selector);

        /* Try to build cert path - should fail because ECC cert
         * can't chain to RSA trust anchor */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException when no matching " +
                 "trust anchor");
        } catch (CertPathBuilderException e) {
            /* Expected */
        }
    }

    /**
     * Test that building fails with null CertPathParameters.
     */
    @Test
    public void testBuildFailsNullParams()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(null);
            fail("Expected InvalidAlgorithmParameterException with " +
                 "null params");

        } catch (InvalidAlgorithmParameterException e) {
            /* Expected */
        } catch (CertPathBuilderException e) {
            fail("Expected InvalidAlgorithmParameterException, not " +
                 "CertPathBuilderException");
        }
    }

    /**
     * Test that building fails with no TrustAnchors.
     */
    @Test
    public void testBuildFailsNoTrustAnchors()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        X509Certificate serverCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();
        Set<TrustAnchor> emptyAnchors = new HashSet<>();

        /* Load server cert */
        serverCert = loadCertFromFile(serverCertDer);
        certCollection.add(serverCert);

        /* Create CertStore */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters with empty trust anchors */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(
                emptyAnchors, selector);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            CertPathBuilder cpb =
                CertPathBuilder.getInstance("PKIX", provider);
            cpb.build(params);

            fail("Expected exception with empty trust anchors");

        } catch (InvalidAlgorithmParameterException e) {
            /* Expected - PKIXBuilderParameters constructor throws this */
        } catch (CertPathBuilderException e) {
            /* Also acceptable */
        }
    }

    /**
     * Test that target cert that is itself a trust anchor returns
     * empty path.
     */
    @Test
    public void testTargetIsTrustAnchorReturnsEmptyPath()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();
        Set<TrustAnchor> anchors = new HashSet<>();

        /* Load CA cert which will be both target and trust anchor */
        caCert = loadCertFromFile(caCertDer);
        certCollection.add(caCert);

        /* Create trust anchor from same cert */
        TrustAnchor anchor = new TrustAnchor(caCert, null);
        anchors.add(anchor);

        /* Create CertStore */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(caCert);

        PKIXBuilderParameters params = new PKIXBuilderParameters(
            anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Build cert path */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Verify result */
        assertNotNull(result);
        assertTrue(result instanceof PKIXCertPathBuilderResult);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Path should be empty when target is trust anchor */
        CertPath path = pResult.getCertPath();
        assertNotNull(path);
        assertEquals(0, path.getCertificates().size());

        /* Trust anchor should be the same as target */
        assertEquals(caCert, pResult.getTrustAnchor().getTrustedCert());

        /* Public key should be from the target/anchor cert */
        assertEquals(caCert.getPublicKey(), pResult.getPublicKey());
    }

    /**
     * Test building with target selector that uses subject name instead
     * of direct certificate reference.
     */
    @Test
    public void testBuildWithSubjectSelector()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate caCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load CA cert for expected comparison */
        caCert = loadCertFromFile(caCertDer);

        /* Load server cert for CertStore */
        serverCert = loadCertFromFile(serverCertDer);
        certCollection.add(serverCert);

        /* Create CertStore */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        /* Set target cert selector using subject name */
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(serverCert.getSubjectX500Principal());
        params.setTargetCertConstraints(selector);

        /* Build cert path */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        checkPKIXCertPathBuilderResult(result, caCert,
            serverCert.getPublicKey());
    }

    /**
     * Test that getRevocationChecker() returns a non-null checker.
     */
    @Test
    public void testGetRevocationChecker()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        assertNotNull(cpb.getRevocationChecker());
    }

    /**
     * Test that building respects maxPathLength constraint.
     */
    @Test
    public void testMaxPathLengthConstraint()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate int2Cert = null;
        X509Certificate int1Cert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Use example KeyStore that has ca-cert.der as trusted root */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Load server cert (target) */
        serverCert = loadCertFromFile(intRsaServerCertDer);
        certCollection.add(serverCert);

        /* Load intermediate CA 2 */
        int2Cert = loadCertFromFile(intRsaInt2CertDer);
        certCollection.add(int2Cert);

        /* Load intermediate CA 1 */
        int1Cert = loadCertFromFile(intRsaInt1CertDer);
        certCollection.add(int1Cert);

        /* Create CertStore with all certs */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters with very short max path length */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setMaxPathLength(1); /* Too short for chain with 2 ints */

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Try to build cert path - should fail due to path length */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException when path exceeds " +
                 "maxPathLength");
        } catch (CertPathBuilderException e) {
            /* Expected */
        }
    }

    /**
     * Helper to compare CertPath results between two providers.
     */
    private boolean comparePaths(PKIXCertPathBuilderResult wolf,
                                 PKIXCertPathBuilderResult sun) {

        CertPath wolfPath = wolf.getCertPath();
        CertPath sunPath = sun.getCertPath();

        /* Compare path lengths */
        if (wolfPath.getCertificates().size() !=
            sunPath.getCertificates().size()) {
            return false;
        }

        /* Compare each certificate in path */
        for (int i = 0; i < wolfPath.getCertificates().size(); i++) {
            X509Certificate wolfCert =
                (X509Certificate) wolfPath.getCertificates().get(i);
            X509Certificate sunCert =
                (X509Certificate) sunPath.getCertificates().get(i);

            if (!wolfCert.equals(sunCert)) {
                return false;
            }
        }

        /* Compare trust anchors */
        X509Certificate wolfAnchor = wolf.getTrustAnchor().getTrustedCert();
        X509Certificate sunAnchor = sun.getTrustAnchor().getTrustedCert();

        if (!wolfAnchor.equals(sunAnchor)) {
            return false;
        }

        return true;
    }

    /**
     * SUN interop test - Simple chain (server to root CA).
     */
    @Test
    public void testInteropSimpleChain()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Build with wolfJCE */
        PKIXBuilderParameters wolfParams =
            new PKIXBuilderParameters(anchors, selector);
        wolfParams.setRevocationEnabled(false);
        wolfParams.addCertStore(certStore);

        CertPathBuilder wolfCpb =
            CertPathBuilder.getInstance("PKIX", "wolfJCE");
        PKIXCertPathBuilderResult wolfResult =
            (PKIXCertPathBuilderResult) wolfCpb.build(wolfParams);

        /* Build with SUN */
        PKIXBuilderParameters sunParams =
            new PKIXBuilderParameters(anchors, selector);
        sunParams.setRevocationEnabled(false);
        sunParams.addCertStore(certStore);

        CertPathBuilder sunCpb = CertPathBuilder.getInstance("PKIX", "SUN");
        PKIXCertPathBuilderResult sunResult =
            (PKIXCertPathBuilderResult) sunCpb.build(sunParams);

        /* Compare results */
        assertTrue("wolfJCE and SUN should produce equivalent results",
                   comparePaths(wolfResult, sunResult));
    }

    /**
     * SUN interop test - Chain with intermediates.
     */
    @Test
    public void testInteropIntermediateChain()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int2Cert);
        certs.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Build with wolfJCE */
        PKIXBuilderParameters wolfParams =
            new PKIXBuilderParameters(anchors, selector);
        wolfParams.setRevocationEnabled(false);
        wolfParams.addCertStore(certStore);

        CertPathBuilder wolfCpb =
            CertPathBuilder.getInstance("PKIX", "wolfJCE");
        PKIXCertPathBuilderResult wolfResult =
            (PKIXCertPathBuilderResult) wolfCpb.build(wolfParams);

        /* Build with SUN */
        PKIXBuilderParameters sunParams =
            new PKIXBuilderParameters(anchors, selector);
        sunParams.setRevocationEnabled(false);
        sunParams.addCertStore(certStore);

        CertPathBuilder sunCpb = CertPathBuilder.getInstance("PKIX", "SUN");
        PKIXCertPathBuilderResult sunResult =
            (PKIXCertPathBuilderResult) sunCpb.build(sunParams);

        /* Compare results */
        assertTrue("wolfJCE and SUN should produce equivalent results",
                   comparePaths(wolfResult, sunResult));
    }

    /**
     * SUN interop test - missing intermediate should fail on both providers.
     */
    @Test
    public void testInteropMissingIntermediate()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Only target cert, no intermediates */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        boolean wolfFailed = false;
        boolean sunFailed = false;

        /* Try wolfJCE */
        try {
            PKIXBuilderParameters wolfParams =
                new PKIXBuilderParameters(anchors, selector);
            wolfParams.setRevocationEnabled(false);
            wolfParams.addCertStore(certStore);
            CertPathBuilder wolfCpb =
                CertPathBuilder.getInstance("PKIX", "wolfJCE");
            wolfCpb.build(wolfParams);
        } catch (CertPathBuilderException e) {
            wolfFailed = true;
        }

        /* Try SUN */
        try {
            PKIXBuilderParameters sunParams =
                new PKIXBuilderParameters(anchors, selector);
            sunParams.setRevocationEnabled(false);
            sunParams.addCertStore(certStore);
            CertPathBuilder sunCpb =
                CertPathBuilder.getInstance("PKIX", "SUN");
            sunCpb.build(sunParams);
        } catch (CertPathBuilderException e) {
            sunFailed = true;
        }

        assertTrue("Both providers should fail with missing intermediate",
                   wolfFailed && sunFailed);
    }

    /**
     * SUN interop test - wrong trust anchor should fail on both providers.
     */
    @Test
    public void testInteropWrongTrustAnchor()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        /* RSA CA as trust anchor */
        X509Certificate rsaCaCert = loadCertFromFile(caCertDer);
        /* ECC server cert (signed by ECC CA, not RSA CA) */
        X509Certificate eccServerCert = loadCertFromFile(serverEccDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(rsaCaCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(eccServerCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(eccServerCert);

        boolean wolfFailed = false;
        boolean sunFailed = false;

        /* Try wolfJCE */
        try {
            PKIXBuilderParameters wolfParams =
                new PKIXBuilderParameters(anchors, selector);
            wolfParams.setRevocationEnabled(false);
            wolfParams.addCertStore(certStore);
            CertPathBuilder wolfCpb =
                CertPathBuilder.getInstance("PKIX", "wolfJCE");
            wolfCpb.build(wolfParams);
        } catch (CertPathBuilderException e) {
            wolfFailed = true;
        }

        /* Try SUN */
        try {
            PKIXBuilderParameters sunParams =
                new PKIXBuilderParameters(anchors, selector);
            sunParams.setRevocationEnabled(false);
            sunParams.addCertStore(certStore);
            CertPathBuilder sunCpb =
                CertPathBuilder.getInstance("PKIX", "SUN");
            sunCpb.build(sunParams);
        } catch (CertPathBuilderException e) {
            sunFailed = true;
        }

        assertTrue("Both providers should fail with wrong trust anchor",
                   wolfFailed && sunFailed);
    }

    /**
     * SUN interop test - target is trust anchor (empty path).
     * Both providers should return same path length.
     */
    @Test
    public void testInteropTargetIsTrustAnchor()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        X509Certificate caCert = loadCertFromFile(caCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(caCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(caCert);

        /* Build with wolfJCE */
        PKIXBuilderParameters wolfParams =
            new PKIXBuilderParameters(anchors, selector);
        wolfParams.setRevocationEnabled(false);
        wolfParams.addCertStore(certStore);

        CertPathBuilder wolfCpb =
            CertPathBuilder.getInstance("PKIX", "wolfJCE");
        PKIXCertPathBuilderResult wolfResult =
            (PKIXCertPathBuilderResult) wolfCpb.build(wolfParams);

        /* Build with SUN */
        PKIXBuilderParameters sunParams =
            new PKIXBuilderParameters(anchors, selector);
        sunParams.setRevocationEnabled(false);
        sunParams.addCertStore(certStore);

        CertPathBuilder sunCpb = CertPathBuilder.getInstance("PKIX", "SUN");
        PKIXCertPathBuilderResult sunResult =
            (PKIXCertPathBuilderResult) sunCpb.build(sunParams);

        int wolfPathLen = wolfResult.getCertPath().getCertificates().size();
        int sunPathLen = sunResult.getCertPath().getCertificates().size();

        assertEquals("Both providers should produce same path length",
                     sunPathLen, wolfPathLen);
    }

    /**
     * SUN interop test - path length constraint.
     * Both providers should behave consistently with maxPathLength.
     */
    @Test
    public void testInteropPathLengthConstraint()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int2Cert);
        certs.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        boolean wolfFailed = false;
        boolean sunFailed = false;

        /* Try wolfJCE with maxPathLength=1 */
        try {
            PKIXBuilderParameters wolfParams =
                new PKIXBuilderParameters(anchors, selector);
            wolfParams.setRevocationEnabled(false);
            wolfParams.addCertStore(certStore);
            wolfParams.setMaxPathLength(1);
            CertPathBuilder wolfCpb =
                CertPathBuilder.getInstance("PKIX", "wolfJCE");
            wolfCpb.build(wolfParams);
        } catch (CertPathBuilderException e) {
            wolfFailed = true;
        }

        /* Try SUN with maxPathLength=1 */
        try {
            PKIXBuilderParameters sunParams =
                new PKIXBuilderParameters(anchors, selector);
            sunParams.setRevocationEnabled(false);
            sunParams.addCertStore(certStore);
            sunParams.setMaxPathLength(1);
            CertPathBuilder sunCpb =
                CertPathBuilder.getInstance("PKIX", "SUN");
            sunCpb.build(sunParams);
        } catch (CertPathBuilderException e) {
            sunFailed = true;
        }

        /* Both should either fail or succeed consistently */
        assertEquals("Both providers should behave consistently with " +
                     "maxPathLength constraint", sunFailed, wolfFailed);
    }

    /**
     * Test multiple certificates in CertStore that could match selector.
     * Builder should successfully find and use correct one.
     */
    @Test
    public void testEdgeCaseMultipleCertsInCertStore()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);
        X509Certificate clientCert = loadCertFromFile(clientCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Add multiple certs to CertStore */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(clientCert);
        certs.add(caCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Select specifically the server cert */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Verify we got the server cert, not the client cert */
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        CertPath path = pResult.getCertPath();
        assertEquals(1, path.getCertificates().size());
        assertEquals(serverCert, path.getCertificates().get(0));
    }

    /**
     * Test duplicate certificates in CertStore should not cause issues.
     */
    @Test
    public void testEdgeCaseDuplicateCertsInCertStore()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Add same cert multiple times */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(serverCert);  /* Duplicate */
        certs.add(serverCert);  /* Duplicate */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test using subject selector instead of direct cert reference.
     * Tests that we can find target by subject name only.
     */
    @Test
    public void testEdgeCaseSubjectOnlySelector()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Use only subject, not direct cert reference */
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(serverCert.getSubjectX500Principal());

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(serverCert,
            pResult.getCertPath().getCertificates().get(0));
    }

    /**
     * Test multiple CertStores, cert split across them.
     */
    @Test
    public void testEdgeCaseMultipleCertStores()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Split certs across multiple CertStores */
        Collection<Certificate> certs1 = new ArrayList<>();
        certs1.add(serverCert);
        CertStore certStore1 = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs1));

        Collection<Certificate> certs2 = new ArrayList<>();
        certs2.add(int2Cert);
        CertStore certStore2 = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs2));

        Collection<Certificate> certs3 = new ArrayList<>();
        certs3.add(int1Cert);
        CertStore certStore3 = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs3));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore1);
        params.addCertStore(certStore2);
        params.addCertStore(certStore3);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test maxPathLength exactly matches chain length.
     * Should succeed with chain of 2 intermediates and maxPathLength=2.
     */
    @Test
    public void testEdgeCaseExactMaxPathLength()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int2Cert);
        certs.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Chain has 2 intermediates, set maxPathLength=2 exactly */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setMaxPathLength(2);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test maxPathLength of 0 with direct signing by trust anchor.
     * A simple chain (target, root) has 0 intermediate CAs.
     */
    @Test
    public void testEdgeCaseMaxPathLengthZero()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* maxPathLength=0 means no intermediate CAs allowed */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setMaxPathLength(0);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed - direct chain to root has 0 intermediates */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test maxPathLength of 0 should fail with any intermediates.
     */
    @Test
    public void testEdgeCaseMaxPathLengthZeroWithIntermediate()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int2Cert);
        certs.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* maxPathLength=0 but chain has 2 intermediates */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setMaxPathLength(0);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException with maxPathLength=0 " +
                 "and intermediates");
        } catch (CertPathBuilderException e) {
            /* Expected */
        }
    }

    /**
     * Test multiple trust anchors, only one matches.
     */
    @Test
    public void testEdgeCaseMultipleTrustAnchors()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate rsaCaCert = loadCertFromFile(caCertDer);
        X509Certificate eccCaCert = loadCertFromFile(caEccCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        /* Both RSA and ECC CAs as trust anchors */
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(rsaCaCert, null));
        anchors.add(new TrustAnchor(eccCaCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should find RSA CA anchor */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(rsaCaCert, pResult.getTrustAnchor().getTrustedCert());
    }

    /**
     * Test empty CertStore with only trust anchor certs.
     * Target cert is provided directly in selector.
     */
    @Test
    public void testEdgeCaseTargetInSelectorNotInCertStore()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Empty CertStore - target cert not in it */
        Collection<Certificate> certs = new ArrayList<>();
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* But target cert is directly set in selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed because target was in selector directly */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
        assertEquals(serverCert,
            pResult.getCertPath().getCertificates().get(0));
    }

    /**
     * Test CA cert also in CertStore (not just trust anchor).
     * Should not cause duplicates or loops.
     */
    @Test
    public void testEdgeCaseCACertInCertStoreAndAnchor()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* CA cert is in both trust anchors AND CertStore */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(caCert);  /* Also in CertStore */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed without issues */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        /* Path should only contain server cert, not the CA */
        assertEquals(1, pResult.getCertPath().getCertificates().size());
        assertEquals(caCert, pResult.getTrustAnchor().getTrustedCert());
    }

    /**
     * Test default maxPathLength (-1) means unlimited.
     * Should succeed even with longer chains.
     */
    @Test
    public void testEdgeCaseUnlimitedMaxPathLength()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int2Cert);
        certs.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Explicitly set maxPathLength to -1 (unlimited) */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setMaxPathLength(-1);

        /* Verify -1 is set (unlimited) */
        assertEquals(-1, params.getMaxPathLength());

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed with unlimited path length */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test intermediate certs added in reverse order to CertStore.
     * Builder should still find correct path regardless of order.
     */
    @Test
    public void testEdgeCaseCertsInReverseOrder()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Add certs in reverse order (closest to root first) */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(int1Cert);
        certs.add(int2Cert);
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should still build correct path */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(3, pResult.getCertPath().getCertificates().size());
        /* Path order should be: target, int2, int1 */
        assertEquals(serverCert,
            pResult.getCertPath().getCertificates().get(0));
        assertEquals(int2Cert,
            pResult.getCertPath().getCertificates().get(1));
        assertEquals(int1Cert,
            pResult.getCertPath().getCertificates().get(2));
    }

    /**
     * Test native chain building verifies correct chain order.
     * Chain should be: target-int2-int1 (ordered from target to issuer).
     */
    @Test
    public void testNativeChainBuildingCorrectOrder()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        CertPath path = pResult.getCertPath();

        /* Verify chain order: target -> int2 -> int1 */
        assertEquals(3, path.getCertificates().size());
        assertEquals(serverCert, path.getCertificates().get(0));
        assertEquals(int2Cert, path.getCertificates().get(1));
        assertEquals(int1Cert, path.getCertificates().get(2));

        /* Verify trust anchor is the root CA */
        assertEquals(caCert, pResult.getTrustAnchor().getTrustedCert());
    }

    /**
     * Test native chain building with ECC certificate chain.
     */
    @Test
    public void testNativeChainBuildingECC()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caEccCertDer);
        X509Certificate int1Cert = loadCertFromFile(intEccInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intEccInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intEccServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Verify chain was built correctly */
        assertEquals(3, pResult.getCertPath().getCertificates().size());
        assertEquals(caCert, pResult.getTrustAnchor().getTrustedCert());
    }

    /**
     * Test native chain building with direct target to trust anchor
     * (no intermediates).
     */
    @Test
    public void testNativeChainBuildingDirectToAnchor()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Path should contain only target cert */
        assertEquals(1, pResult.getCertPath().getCertificates().size());
        assertEquals(serverCert,
            pResult.getCertPath().getCertificates().get(0));
        assertEquals(caCert, pResult.getTrustAnchor().getTrustedCert());
    }

    /**
     * Test native chain building with intermediates in trust anchor store
     * (added via addCertificate to native X509_STORE).
     */
    @Test
    public void testNativeChainBuildingIntermediatesInStore()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Include all certs in CertStore - native method collects CA certs */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test native chain building deduplicates CAs that appear in both
     * trust anchors and CertStore.
     */
    @Test
    public void testNativeChainBuildingDeduplication()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* CA cert is in both trust anchors AND CertStore */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(caCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Path should not include CA (it's the trust anchor) */
        assertEquals(1, pResult.getCertPath().getCertificates().size());
        assertEquals(serverCert,
            pResult.getCertPath().getCertificates().get(0));
    }

    /**
     * Test native chain building with multiple CertStores.
     * Intermediates are spread across different stores.
     */
    @Test
    public void testNativeChainBuildingMultipleCertStores()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* CertStore 1: server cert and int1 */
        Collection<Certificate> certs1 = new ArrayList<>();
        certs1.add(serverCert);
        certs1.add(int1Cert);
        CertStore certStore1 = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs1));

        /* CertStore 2: int2 */
        Collection<Certificate> certs2 = new ArrayList<>();
        certs2.add(int2Cert);
        CertStore certStore2 = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs2));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore1);
        params.addCertStore(certStore2);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Should find all intermediates across both stores */
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test native chain building with mixed RSA and ECC trust anchors.
     * Should find the correct matching anchor.
     */
    @Test
    public void testNativeChainBuildingMixedAnchors()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate rsaCaCert = loadCertFromFile(caCertDer);
        X509Certificate eccCaCert = loadCertFromFile(caEccCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        /* Both RSA and ECC CAs as trust anchors */
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(rsaCaCert, null));
        anchors.add(new TrustAnchor(eccCaCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Should find RSA CA anchor (matches the RSA chain) */
        assertEquals(rsaCaCert, pResult.getTrustAnchor().getTrustedCert());
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test concurrent native chain building (thread safety).
     */
    @Test
    public void testNativeChainBuildingConcurrent()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        final X509Certificate caCert = loadCertFromFile(caCertDer);
        final X509Certificate int1Cert =
            loadCertFromFile(intRsaInt1CertDer);
        final X509Certificate int2Cert =
            loadCertFromFile(intRsaInt2CertDer);
        final X509Certificate serverCert =
            loadCertFromFile(intRsaServerCertDer);

        final int numThreads = 5;
        final int iterations = 10;
        final boolean[] success = new boolean[numThreads];
        final Exception[] errors = new Exception[numThreads];

        Thread[] threads = new Thread[numThreads];
        for (int t = 0; t < numThreads; t++) {
            final int threadIdx = t;
            threads[t] = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int i = 0; i < iterations; i++) {
                            Set<TrustAnchor> anchors = new HashSet<>();
                            anchors.add(new TrustAnchor(caCert, null));

                            Collection<Certificate> certs = new ArrayList<>();
                            certs.add(serverCert);
                            certs.add(int1Cert);
                            certs.add(int2Cert);
                            CertStore certStore = CertStore.getInstance(
                                "Collection",
                                new CollectionCertStoreParameters(certs));

                            X509CertSelector selector = new X509CertSelector();
                            selector.setCertificate(serverCert);

                            PKIXBuilderParameters params =
                                new PKIXBuilderParameters(anchors, selector);
                            params.setRevocationEnabled(false);
                            params.addCertStore(certStore);

                            CertPathBuilder cpb =
                                CertPathBuilder.getInstance("PKIX", provider);
                            CertPathBuilderResult result = cpb.build(params);

                            if (result == null) {
                                throw new Exception(
                                    "Chain building returned null");
                            }

                            PKIXCertPathBuilderResult pResult =
                                (PKIXCertPathBuilderResult) result;
                            if (pResult.getCertPath().getCertificates()
                                    .size() != 3) {
                                throw new Exception(
                                    "Wrong chain length: " +
                                    pResult.getCertPath().getCertificates()
                                        .size());
                            }
                        }
                        success[threadIdx] = true;
                    } catch (Exception e) {
                        errors[threadIdx] = e;
                        success[threadIdx] = false;
                    }
                }
            });
        }

        /* Start all threads */
        for (Thread t : threads) {
            t.start();
        }

        /* Wait for completion */
        for (Thread t : threads) {
            t.join();
        }

        /* Check results */
        for (int i = 0; i < numThreads; i++) {
            if (!success[i]) {
                fail("Thread " + i + " failed: " +
                     (errors[i] != null ? errors[i].getMessage() : "unknown"));
            }
        }
    }

    /**
     * Test native chain building returns correct public key.
     */
    @Test
    public void testNativeChainBuildingPublicKey()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Public key should match target cert's public key */
        assertEquals(serverCert.getPublicKey(), pResult.getPublicKey());
    }

    /**
     * Test native chain building with selector using subject only
     * (not the full certificate).
     */
    @Test
    public void testNativeChainBuildingSubjectSelector()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Use subject-based selector instead of full certificate */
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(serverCert.getSubjectX500Principal());

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test native chain building fails gracefully with missing intermediate.
     */
    @Test
    public void testNativeChainBuildingMissingIntermediate()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        /* int1Cert is missing - this breaks the chain */
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Only include int2, not int1 */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException with missing intermediate");
        } catch (CertPathBuilderException e) {
            /* Expected - chain cannot be built */
        }
    }

    /**
     * Test native chain building with single intermediate.
     */
    @Test
    public void testNativeChainBuildingSingleIntermediate()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);

        /* int1Cert is signed by caCert, so we can use it as target
         * with a single-intermediate chain: int1 -> caCert */
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(int1Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(int1Cert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Path: int1 only (directly signed by caCert trust anchor) */
        assertEquals(1, pResult.getCertPath().getCertificates().size());
        assertEquals(int1Cert, pResult.getCertPath().getCertificates().get(0));
        assertEquals(caCert, pResult.getTrustAnchor().getTrustedCert());
    }

    /**
     * Test native chain building maxPathLength boundary: exactly at limit.
     */
    @Test
    public void testNativeChainBuildingMaxPathLengthExact()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Chain has 2 intermediates, set maxPathLength=2 exactly */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setMaxPathLength(2);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed - exactly at limit */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test native chain building maxPathLength boundary: one over limit.
     */
    @Test
    public void testNativeChainBuildingMaxPathLengthExceeded()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Chain has 2 intermediates, but maxPathLength=1 */
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setMaxPathLength(1);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException when chain exceeds " +
                 "maxPathLength");
        } catch (CertPathBuilderException e) {
            /* Expected */
            assertTrue(e.getMessage().contains("exceeds maximum length") ||
                       e.getMessage().contains("path"));
        }
    }

    /**
     * Test native chain building with both RSA and ECC chains available,
     * selecting RSA chain.
     */
    @Test
    public void testNativeChainBuildingSelectRSAChain()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        /* RSA chain */
        X509Certificate rsaCaCert = loadCertFromFile(caCertDer);
        X509Certificate rsaInt1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate rsaInt2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate rsaServerCert = loadCertFromFile(intRsaServerCertDer);

        /* ECC chain */
        X509Certificate eccCaCert = loadCertFromFile(caEccCertDer);
        X509Certificate eccInt1Cert = loadCertFromFile(intEccInt1CertDer);
        X509Certificate eccInt2Cert = loadCertFromFile(intEccInt2CertDer);

        /* Both CAs as trust anchors */
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(rsaCaCert, null));
        anchors.add(new TrustAnchor(eccCaCert, null));

        /* All intermediates in CertStore */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(rsaServerCert);
        certs.add(rsaInt1Cert);
        certs.add(rsaInt2Cert);
        certs.add(eccInt1Cert);
        certs.add(eccInt2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Select RSA server cert */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(rsaServerCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Should use RSA chain and RSA trust anchor */
        assertEquals(rsaCaCert, pResult.getTrustAnchor().getTrustedCert());
        assertEquals(3, pResult.getCertPath().getCertificates().size());
        assertEquals(rsaServerCert,
            pResult.getCertPath().getCertificates().get(0));
    }

    /**
     * Test that native chain building properly handles empty CertStore
     * (target cert provided directly in selector).
     */
    @Test
    public void testNativeChainBuildingEmptyCertStore()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Empty CertStore */
        Collection<Certificate> certs = new ArrayList<>();
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Target cert directly in selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed - target was in selector */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
        assertEquals(serverCert,
            pResult.getCertPath().getCertificates().get(0));
    }

    /**
     * Test native chain building produces same result as SUN provider
     * for simple chain.
     */
    @Test
    public void testNativeChainBuildingInteropSimple()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Build with wolfJCE */
        PKIXBuilderParameters wolfParams =
            new PKIXBuilderParameters(anchors, selector);
        wolfParams.setRevocationEnabled(false);
        wolfParams.addCertStore(certStore);
        CertPathBuilder wolfCpb =
            CertPathBuilder.getInstance("PKIX", "wolfJCE");
        PKIXCertPathBuilderResult wolfResult =
            (PKIXCertPathBuilderResult) wolfCpb.build(wolfParams);

        /* Build with SUN */
        PKIXBuilderParameters sunParams =
            new PKIXBuilderParameters(anchors, selector);
        sunParams.setRevocationEnabled(false);
        sunParams.addCertStore(certStore);
        CertPathBuilder sunCpb = CertPathBuilder.getInstance("PKIX", "SUN");
        PKIXCertPathBuilderResult sunResult =
            (PKIXCertPathBuilderResult) sunCpb.build(sunParams);

        /* Compare results */
        assertEquals(sunResult.getCertPath().getCertificates().size(),
                     wolfResult.getCertPath().getCertificates().size());
        assertEquals(sunResult.getTrustAnchor().getTrustedCert(),
                     wolfResult.getTrustAnchor().getTrustedCert());
        assertEquals(sunResult.getPublicKey(), wolfResult.getPublicKey());
    }

    /**
     * Test native chain building produces same result as SUN provider
     * for chain with intermediates.
     */
    @Test
    public void testNativeChainBuildingInteropWithIntermediates()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        Assume.assumeTrue("SUN provider not available",
            isSunProviderAvailable());

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        /* Build with wolfJCE */
        PKIXBuilderParameters wolfParams =
            new PKIXBuilderParameters(anchors, selector);
        wolfParams.setRevocationEnabled(false);
        wolfParams.addCertStore(certStore);
        CertPathBuilder wolfCpb =
            CertPathBuilder.getInstance("PKIX", "wolfJCE");
        PKIXCertPathBuilderResult wolfResult =
            (PKIXCertPathBuilderResult) wolfCpb.build(wolfParams);

        /* Build with SUN */
        PKIXBuilderParameters sunParams =
            new PKIXBuilderParameters(anchors, selector);
        sunParams.setRevocationEnabled(false);
        sunParams.addCertStore(certStore);
        CertPathBuilder sunCpb = CertPathBuilder.getInstance("PKIX", "SUN");
        PKIXCertPathBuilderResult sunResult =
            (PKIXCertPathBuilderResult) sunCpb.build(sunParams);

        /* Compare results */
        assertEquals(sunResult.getCertPath().getCertificates().size(),
                     wolfResult.getCertPath().getCertificates().size());
        assertEquals(sunResult.getTrustAnchor().getTrustedCert(),
                     wolfResult.getTrustAnchor().getTrustedCert());

        /* Both should have 3 certs in path */
        assertEquals(3, wolfResult.getCertPath().getCertificates().size());
    }

    /**
     * Test that self-signed certificate not in trust anchors fails.
     * A self-signed cert that isn't trusted should not build a path.
     */
    @Test
    public void testSelfSignedNotTrustedFails()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        /* Use ECC CA as trust anchor, try to build path for RSA CA
         * (which is self-signed but not trusted) */
        X509Certificate eccCaCert = loadCertFromFile(caEccCertDer);
        X509Certificate rsaCaCert = loadCertFromFile(caCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(eccCaCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(rsaCaCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(rsaCaCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException for self-signed " +
                 "cert not in trust anchors");
        } catch (CertPathBuilderException e) {
            /* Expected - self-signed cert not trusted */
        }
    }

    /**
     * Test chain building with wrong trust anchor (no path exists).
     */
    @Test
    public void testWrongTrustAnchorFails()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, NoSuchProviderException,
               Exception {

        /* RSA server cert but ECC trust anchor - no valid path */
        X509Certificate eccCaCert = loadCertFromFile(caEccCertDer);
        X509Certificate rsaServerCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(eccCaCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(rsaServerCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(rsaServerCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException with wrong trust anchor");
        } catch (CertPathBuilderException e) {
            /* Expected - no path from RSA server to ECC CA */
        }
    }

    /**
     * Test with duplicate certificates in CertStore.
     * Should handle gracefully without errors.
     */
    @Test
    public void testDuplicateCertsInCertStore()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Add server cert multiple times */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(serverCert);
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed despite duplicates */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test with duplicate intermediate certificates in CertStore.
     */
    @Test
    public void testDuplicateIntermediatesInCertStore()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Add intermediates multiple times */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        certs.add(int1Cert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed despite duplicates */
        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(3, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test that certificates are validated (basic sanity check).
     * Current valid certificates should build successfully.
     */
    @Test
    public void testCertificateValidityCheck()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        /* Verify test certs are currently valid */
        serverCert.checkValidity();
        caCert.checkValidity();

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Should succeed with valid certificates */
        assertNotNull(result);
    }

    /**
     * Test chain building with issuer-based selector (not full cert).
     */
    @Test
    public void testIssuerBasedSelector()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Use issuer-based selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setIssuer(serverCert.getIssuerX500Principal());
        selector.setSubject(serverCert.getSubjectX500Principal());

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test chain building with serial number selector.
     */
    @Test
    public void testSerialNumberSelector()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Use serial number and issuer selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setSerialNumber(serverCert.getSerialNumber());
        selector.setIssuer(serverCert.getIssuerX500Principal());

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
        assertEquals(serverCert,
            pResult.getCertPath().getCertificates().get(0));
    }

    /**
     * Test with no CertStores but target in selector.
     * Should still work if target cert is directly in selector.
     */
    @Test
    public void testNoCertStoresTargetInSelector()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Empty CertStore - no certs */
        Collection<Certificate> certs = new ArrayList<>();
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        /* Target cert directly in selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals(1, pResult.getCertPath().getCertificates().size());
    }

    /**
     * Test multiple trust anchors where first one doesn't match.
     * Should find the correct anchor.
     */
    @Test
    public void testMultipleTrustAnchorsFirstNoMatch()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate rsaCaCert = loadCertFromFile(caCertDer);
        X509Certificate eccCaCert = loadCertFromFile(caEccCertDer);
        X509Certificate rsaServerCert = loadCertFromFile(serverCertDer);

        /* Add ECC first, then RSA - RSA server should find RSA anchor */
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(eccCaCert, null));
        anchors.add(new TrustAnchor(rsaCaCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(rsaServerCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(rsaServerCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;

        /* Should find RSA CA as trust anchor */
        assertEquals(rsaCaCert, pResult.getTrustAnchor().getTrustedCert());
    }

    /**
     * Test that path order is strictly maintained: target first, then
     * intermediates in order toward trust anchor.
     */
    @Test
    public void testPathOrderStrictlyMaintained()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate int1Cert = loadCertFromFile(intRsaInt1CertDer);
        X509Certificate int2Cert = loadCertFromFile(intRsaInt2CertDer);
        X509Certificate serverCert = loadCertFromFile(intRsaServerCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        /* Intentionally add in wrong order */
        Collection<Certificate> certs = new ArrayList<>();
        certs.add(int1Cert);
        certs.add(caCert);
        certs.add(serverCert);
        certs.add(int2Cert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull(result);
        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        List<? extends Certificate> pathCerts =
            pResult.getCertPath().getCertificates();

        /* Verify strict order: server -> int2 -> int1 */
        assertEquals(3, pathCerts.size());
        assertEquals(serverCert, pathCerts.get(0));
        assertEquals(int2Cert, pathCerts.get(1));
        assertEquals(int1Cert, pathCerts.get(2));

        /* Trust anchor should be caCert */
        assertEquals(caCert, pResult.getTrustAnchor().getTrustedCert());

        /* Verify each cert is signed by the next (or anchor for last) */
        X509Certificate cert0 = (X509Certificate) pathCerts.get(0);
        X509Certificate cert1 = (X509Certificate) pathCerts.get(1);
        X509Certificate cert2 = (X509Certificate) pathCerts.get(2);

        assertEquals(cert0.getIssuerX500Principal(),
            cert1.getSubjectX500Principal());
        assertEquals(cert1.getIssuerX500Principal(),
            cert2.getSubjectX500Principal());
        assertEquals(cert2.getIssuerX500Principal(),
            caCert.getSubjectX500Principal());
    }

    /**
     * Test concurrent chain building with different certificate types.
     * Builds RSA and ECC chains concurrently.
     */
    @Test
    public void testConcurrentDifferentChainTypes()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        final X509Certificate rsaCaCert = loadCertFromFile(caCertDer);
        final X509Certificate rsaServerCert = loadCertFromFile(serverCertDer);
        final X509Certificate eccCaCert = loadCertFromFile(caEccCertDer);
        final X509Certificate eccServerCert = loadCertFromFile(serverEccDer);

        final int numThreads = 4;
        final int iterations = 5;
        final boolean[] success = new boolean[numThreads];
        final Exception[] errors = new Exception[numThreads];

        Thread[] threads = new Thread[numThreads];
        for (int t = 0; t < numThreads; t++) {
            final int threadIdx = t;
            final boolean useRsa = (t % 2 == 0);
            threads[t] = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int i = 0; i < iterations; i++) {
                            X509Certificate ca = useRsa ? rsaCaCert : eccCaCert;
                            X509Certificate srv =
                                useRsa ? rsaServerCert : eccServerCert;

                            Set<TrustAnchor> anchors = new HashSet<>();
                            anchors.add(new TrustAnchor(ca, null));

                            Collection<Certificate> certs = new ArrayList<>();
                            certs.add(srv);
                            CertStore certStore = CertStore.getInstance(
                                "Collection",
                                new CollectionCertStoreParameters(certs));

                            X509CertSelector selector = new X509CertSelector();
                            selector.setCertificate(srv);

                            PKIXBuilderParameters params =
                                new PKIXBuilderParameters(anchors, selector);
                            params.setRevocationEnabled(false);
                            params.addCertStore(certStore);

                            CertPathBuilder cpb =
                                CertPathBuilder.getInstance("PKIX", provider);
                            CertPathBuilderResult result = cpb.build(params);

                            if (result == null) {
                                throw new Exception(
                                    "Chain building returned null");
                            }

                            PKIXCertPathBuilderResult pResult =
                                (PKIXCertPathBuilderResult) result;
                            if (!pResult.getTrustAnchor().getTrustedCert()
                                    .equals(ca)) {
                                throw new Exception("Wrong trust anchor");
                            }
                        }
                        success[threadIdx] = true;
                    } catch (Exception e) {
                        errors[threadIdx] = e;
                        success[threadIdx] = false;
                    }
                }
            });
        }

        for (Thread t : threads) {
            t.start();
        }
        for (Thread t : threads) {
            t.join();
        }

        for (int i = 0; i < numThreads; i++) {
            if (!success[i]) {
                fail("Thread " + i + " failed: " +
                     (errors[i] != null ? errors[i].getMessage() : "unknown"));
            }
        }
    }

    /**
     * Test that CertPath type is X.509.
     */
    @Test
    public void testCertPathTypeIsX509()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathBuilderException,
               NoSuchProviderException, Exception {

        X509Certificate caCert = loadCertFromFile(caCertDer);
        X509Certificate serverCert = loadCertFromFile(serverCertDer);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(caCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(serverCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        PKIXCertPathBuilderResult pResult = (PKIXCertPathBuilderResult) result;
        assertEquals("X.509", pResult.getCertPath().getType());
    }

    /**
     * Helper to load X509Certificate from PEM string.
     */
    private X509Certificate loadCertFromPEM(String pem)
        throws CertificateException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bis =
            new ByteArrayInputStream(pem.getBytes());
        return (X509Certificate) cf.generateCertificate(bis);
    }

    /**
     * Helper to create PKIXBuilderParameters for expired cert tests.
     *
     * Loads expired test certificates (valid May 2014 - April 2016)
     * and sets up trust anchors, CertStore, and target selector.
     *
     * @param dateMillis custom validation date in epoch millis,
     *                   or -1 to use current system time
     *
     * @return configured PKIXBuilderParameters
     */
    private PKIXBuilderParameters createExpiredCertParams(long dateMillis)
        throws CertificateException, InvalidAlgorithmParameterException,
               NoSuchAlgorithmException {

        X509Certificate rootCert =
            loadCertFromPEM(EXPIRED_ROOT_PEM);
        X509Certificate intermediateCert =
            loadCertFromPEM(EXPIRED_INTERMEDIATE_PEM);
        X509Certificate userCert =
            loadCertFromPEM(EXPIRED_USER_PEM);

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(rootCert, null));

        Collection<Certificate> certs = new ArrayList<>();
        certs.add(userCert);
        certs.add(intermediateCert);
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certs));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(userCert);

        PKIXBuilderParameters params =
            new PKIXBuilderParameters(anchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);

        if (dateMillis >= 0) {
            params.setDate(new Date(dateMillis));
        }

        return params;
    }

    /**
     * Test building a cert path with expired certificates using
     * a custom validation date set via PKIXBuilderParameters.setDate().
     *
     * This test uses certificates that expired in 2016 and sets a validation
     * date of March 15, 2015 (when the certificates were valid). This
     * verifies that wolfJCE properly supports custom date validation for
     * certificate chain building.
     *
     * This test would fail without proper date override support, as the
     * certificates would be rejected as expired when added to the store.
     */
    @Test
    public void testExpiredCertsWithCustomValidationDate()
        throws CertificateException, InvalidAlgorithmParameterException,
               CertPathBuilderException, NoSuchAlgorithmException,
               NoSuchProviderException {

        Assume.assumeTrue(
            "X509_STORE check_time support not available in " +
            "this wolfSSL version",
            WolfSSLX509StoreCtx.isStoreCheckTimeSupported());

        /* Load certs separately for result assertions below */
        X509Certificate rootCert =
            loadCertFromPEM(EXPIRED_ROOT_PEM);
        X509Certificate intermediateCert =
            loadCertFromPEM(EXPIRED_INTERMEDIATE_PEM);
        X509Certificate userCert =
            loadCertFromPEM(EXPIRED_USER_PEM);

        /* Date is March 15, 2015 (within cert validity 2014-2016).
         * Epoch time 1426399200000L = Sun Mar 15 2015 06:00:00 */
        PKIXBuilderParameters params =
            createExpiredCertParams(1426399200000L);

        /* Build cert path - should succeed with custom date */
        CertPathBuilder cpb =
            CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        /* Verify result */
        assertNotNull(
            "CertPathBuilderResult should not be null", result);
        PKIXCertPathBuilderResult pResult =
            (PKIXCertPathBuilderResult) result;

        /* Verify trust anchor is the root cert */
        assertEquals("Trust anchor should be the root cert",
            rootCert,
            pResult.getTrustAnchor().getTrustedCert());

        /* Verify path contains user and intermediate certs
         * (root/trust anchor is not included in the path) */
        CertPath path = pResult.getCertPath();
        assertNotNull("CertPath should not be null", path);
        assertEquals("Path should contain 2 certificates",
            2, path.getCertificates().size());

        /* Verify path order: user -> intermediate */
        assertEquals("First cert in path should be user cert",
            userCert, path.getCertificates().get(0));
        assertEquals(
            "Second cert in path should be intermediate cert",
            intermediateCert, path.getCertificates().get(1));
    }

    /**
     * Test that setDate() with a date after cert expiry still fails.
     *
     * Uses expired certificates (valid 2014-2016) and sets a validation
     * date of March 15, 2017 (after the certificates expired). This
     * verifies that setDate() properly validates against the custom date.
     */
    @Test
    public void testExpiredCertsFailWithDateAfterExpiry()
        throws CertificateException, InvalidAlgorithmParameterException,
               NoSuchAlgorithmException, NoSuchProviderException {

        Assume.assumeTrue("X509_STORE check_time support not available in " +
            "this wolfSSL version",
            WolfSSLX509StoreCtx.isStoreCheckTimeSupported());

        /* Date is March 15, 2017 (certs expired April 30, 2016).
         * Epoch time 1489561200000L = Wed Mar 15 2017 06:00:00 */
        PKIXBuilderParameters params = createExpiredCertParams(1489561200000L);

        /* Build cert path, should fail because custom date after cert expiry */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException when custom " +
                 "date is after cert expiry");
        } catch (CertPathBuilderException e) {
            /* Expected, date is after cert validity */
            assertNotNull("Exception message should not be null",
                e.getMessage());
            assertTrue("Exception should indicate cert expired, got: " +
                e.getMessage(), e.getMessage().contains("expired"));
        }
    }

    /**
     * Test that setDate() with a date before cert validity still fails.
     *
     * Uses expired certificates (valid May 1, 2014 - April 30, 2016)
     * and sets a validation date of January 1, 2014 (before notBefore).
     * This verifies that setDate() also checks the notBefore boundary.
     */
    @Test
    public void testExpiredCertsFailWithDateBeforeValidity()
        throws CertificateException, InvalidAlgorithmParameterException,
               NoSuchAlgorithmException, NoSuchProviderException {

        Assume.assumeTrue(
            "X509_STORE check_time support not available in " +
            "this wolfSSL version",
            WolfSSLX509StoreCtx.isStoreCheckTimeSupported());

        /* Date is January 1, 2014 (certs valid from May 1, 2014).
         * Epoch time 1388534400000L = Wed Jan 01 2014 00:00:00 */
        PKIXBuilderParameters params =
            createExpiredCertParams(1388534400000L);

        /* Build cert path - should FAIL because custom date is
         * before cert notBefore */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException when custom " +
                 "date is before cert notBefore");
        } catch (CertPathBuilderException e) {
            /* Expected, date is before cert validity */
            assertNotNull("Exception message should not be null",
                e.getMessage());
            assertTrue("Exception should indicate cert not yet valid" +
                ", got: " + e.getMessage(),
                e.getMessage().contains("not yet valid"));
        }
    }

    /**
     * Test that expired certs fail validation when no custom date
     * is set (using current system time).
     *
     * This test verifies that wolfJCE properly rejects expired certificates
     * when validating against the current system time.
     */
    @Test
    public void testExpiredCertsFailWithoutCustomDate()
        throws CertificateException, InvalidAlgorithmParameterException,
               NoSuchAlgorithmException, NoSuchProviderException {

        /* No custom date (-1), uses current system time */
        PKIXBuilderParameters params = createExpiredCertParams(-1);

        /* Build cert path - should FAIL because certs are expired */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException for " +
                 "expired certificates");
        } catch (CertPathBuilderException e) {
            /* Expected, certificates are expired. May fail
             * during store addition ("Failed to add certificate")
             * or during verification ("expired"), depending on
             * wolfSSL version and configuration. */
            assertNotNull("Exception message should not be null",
                e.getMessage());
            assertTrue("Exception should indicate cert date issue" +
                ", got: " + e.getMessage(),
                e.getMessage().contains("expired") ||
                e.getMessage().contains(
                    "Failed to add certificate"));
        }
    }

    /**
     * Test that building a cert path fails when the signature algorithm
     * (SHA256) is in the disabled algorithms list.
     */
    @Test
    public void testAlgorithmConstraintsRejectsSignatureAlgo()
        throws Exception {

        String origProperty = null;
        KeyStore store = null;
        X509Certificate serverCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Save original security property value */
        origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Load KeyStore with CA cert as trust anchor */
            store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
            assertNotNull("KeyStore should not be null", store);

            /* Load server cert (uses SHA256withRSA) */
            serverCert = loadCertFromFile(serverCertDer);
            certCollection.add(serverCert);

            /* Set SHA256 as disabled algorithm */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "SHA256");

            /* Create CertStore with target cert */
            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));

            /* Create PKIXBuilderParameters */
            PKIXBuilderParameters params =
                new PKIXBuilderParameters(store, null);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            /* Set target cert selector */
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(serverCert);
            params.setTargetCertConstraints(selector);

            /* Build cert path, should fail */
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

            try {
                cpb.build(params);
                fail("Expected CertPathBuilderException for SHA256 " +
                     "disabled algorithm");
            } catch (CertPathBuilderException e) {
                /* Expected exception */
                assertNotNull("Exception message should not be null",
                    e.getMessage());
                assertTrue(
                    "Exception should mention algorithm constraints, got: " +
                    e.getMessage(), e.getMessage().contains(
                        "Algorithm constraints"));
            }

        } finally {
            /* Restore original security property */
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    /**
     * Test that building a cert path fails when the key algorithm (RSA) is in
     * the disabled algorithms list.
     */
    @Test
    public void testAlgorithmConstraintsRejectsKeyAlgo()
        throws Exception {

        String origProperty = null;
        KeyStore store = null;
        X509Certificate serverCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Save original security property value */
        origProperty = Security.getProperty("jdk.certpath.disabledAlgorithms");

        try {
            /* Load KeyStore with CA cert as trust anchor */
            store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
            assertNotNull("KeyStore should not be null", store);

            /* Load server cert (uses RSA public key) */
            serverCert = loadCertFromFile(serverCertDer);
            certCollection.add(serverCert);

            /* Set RSA as disabled algorithm */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "RSA");

            /* Create CertStore with target cert */
            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));

            /* Create PKIXBuilderParameters */
            PKIXBuilderParameters params =
                new PKIXBuilderParameters(store, null);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            /* Set target cert selector */
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(serverCert);
            params.setTargetCertConstraints(selector);

            /* Build cert path, should fail */
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

            try {
                cpb.build(params);
                fail("Expected CertPathBuilderException for " +
                     "RSA disabled algorithm");
            } catch (CertPathBuilderException e) {
                /* Expected exception */
                assertNotNull("Exception message should not be null",
                    e.getMessage());
                assertTrue(
                    "Exception should mention algorithm constraints, got: " +
                    e.getMessage(), e.getMessage().contains(
                        "Algorithm constraints"));
            }

        } finally {
            /* Restore original security property */
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    /**
     * Test that building a cert path fails when the RSA key size is smaller
     * than the minimum specified in disabled algorithms.
     */
    @Test
    public void testAlgorithmConstraintsRejectsKeySize()
        throws Exception {

        String origProperty = null;
        KeyStore store = null;
        X509Certificate serverCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Save original security property value */
        origProperty = Security.getProperty("jdk.certpath.disabledAlgorithms");

        try {
            /* Load KeyStore with CA cert as trust anchor */
            store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
            assertNotNull("KeyStore should not be null", store);

            /* Load server cert (uses 2048-bit RSA key) */
            serverCert = loadCertFromFile(serverCertDer);
            certCollection.add(serverCert);

            /* Set minimum RSA key size to 4096 bits, which will
             * reject our 2048-bit certificate */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize < 4096");

            /* Create CertStore with target cert */
            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));

            /* Create PKIXBuilderParameters */
            PKIXBuilderParameters params =
                new PKIXBuilderParameters(store, null);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            /* Set target cert selector */
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(serverCert);
            params.setTargetCertConstraints(selector);

            /* Build cert path - should fail */
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

            try {
                cpb.build(params);
                fail("Expected CertPathBuilderException for " +
                     "RSA key size constraint");
            } catch (CertPathBuilderException e) {
                /* Expected exception */
                assertNotNull("Exception message should not be null",
                    e.getMessage());
                assertTrue(
                    "Exception should mention algorithm constraints, got: " +
                    e.getMessage(), e.getMessage().contains(
                        "Algorithm constraints"));
            }

        } finally {
            /* Restore original security property */
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    /**
     * Test that building a cert path fails when SHA-256 (hyphenated variant)
     * is in the disabled algorithms list, which should match SHA256withRSA
     * via decomposition.
     */
    @Test
    public void testAlgorithmConstraintsRejectsAlgoVariant()
        throws Exception {

        String origProperty = null;
        KeyStore store = null;
        X509Certificate serverCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        /* Save original security property value */
        origProperty = Security.getProperty("jdk.certpath.disabledAlgorithms");

        try {
            /* Load KeyStore with CA cert as trust anchor */
            store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
            assertNotNull("KeyStore should not be null", store);

            /* Load server cert (uses SHA256withRSA) */
            serverCert = loadCertFromFile(serverCertDer);
            certCollection.add(serverCert);

            /* Set SHA-256 (hyphenated) as disabled algorithm */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "SHA-256");

            /* Create CertStore with target cert */
            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));

            /* Create PKIXBuilderParameters */
            PKIXBuilderParameters params =
                new PKIXBuilderParameters(store, null);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            /* Set target cert selector */
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(serverCert);
            params.setTargetCertConstraints(selector);

            /* Build cert path, should fail */
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

            try {
                cpb.build(params);
                fail("Expected CertPathBuilderException for " +
                     "SHA-256 disabled algorithm variant");
            } catch (CertPathBuilderException e) {
                /* Expected exception */
                assertNotNull("Exception message should not be null",
                    e.getMessage());
                assertTrue("Exception should mention algorithm " +
                    "constraints, got: " + e.getMessage(),
                    e.getMessage().contains("Algorithm constraints"));
            }

        } finally {
            /* Restore original security property */
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    /**
     * Test that building a cert path fails when trust anchor's public key size
     * violates the disabled algorithms constraint, even when the target cert
     * is the trust anchor.
     */
    @Test
    public void testTrustAnchorKeyConstraintsRejectsKeySize()
        throws Exception {

        String origProperty = null;
        CertificateFactory cf = null;
        X509Certificate caCert = null;
        TrustAnchor anchor = null;
        Set<TrustAnchor> anchors = null;
        FileInputStream fis = null;

        /* Save original security property value */
        origProperty = Security.getProperty("jdk.certpath.disabledAlgorithms");

        try {
            /* Load CA cert (uses 2048-bit RSA key) */
            cf = CertificateFactory.getInstance("X.509");
            fis = new FileInputStream(caCertDer);
            caCert = (X509Certificate)cf.generateCertificate(fis);
            fis.close();

            /* Set minimum RSA key size to 4096 bits */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize < 4096");

            /* Setup trust anchor with CA cert */
            anchor = new TrustAnchor(caCert, null);
            anchors = new HashSet<TrustAnchor>();
            anchors.add(anchor);

            /* Create PKIXBuilderParameters with CA cert as
             * both trust anchor and target */
            PKIXBuilderParameters params =
                new PKIXBuilderParameters(anchors, new X509CertSelector());
            params.setRevocationEnabled(false);

            /* Set target to CA cert itself (trust anchor) */
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(caCert);
            params.setTargetCertConstraints(selector);

            /* Add CA cert to CertStore so it can be found */
            Collection<Certificate> certCollection = new ArrayList<>();
            certCollection.add(caCert);
            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));
            params.addCertStore(certStore);

            /* Build cert path, should fail due to trust
             * anchor key size constraint */
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

            try {
                cpb.build(params);
                fail("Expected CertPathBuilderException for " +
                     "trust anchor RSA key size constraint");
            } catch (CertPathBuilderException e) {
                /* Expected exception */
                assertNotNull("Exception message should not be null",
                    e.getMessage());
                assertTrue("Exception should mention algorithm constraints, " +
                    "got: " + e.getMessage(),
                    e.getMessage().contains("Algorithm constraints"));
            }

        } finally {
            /* Close any open file streams */
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    /* Ignore close errors */
                }
            }

            /* Restore original security property */
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    /**
     * Test that setDate() with a date within cert validity succeeds regardless
     * of native check_time support.
     *
     * Uses currently-valid certs and sets a custom date that is also within
     * their validity period. Exercises the Java date validation fallback when
     * native check_time propagation is not supported.
     */
    @Test
    public void testSetDateFallbackSucceedsWithValidDate()
        throws Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate caCert = null;
        Collection<Certificate> certCollection =
            new ArrayList<>();

        /* Load KeyStore with CA cert as trust anchor */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        assertNotNull("KeyStore should not be null", store);

        /* Load CA and server certs */
        caCert = loadCertFromFile(caCertDer);
        serverCert = loadCertFromFile(serverCertDer);
        certCollection.add(serverCert);

        /* Create CertStore with target cert */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters with custom date set
         * to yesterday (within cert validity period) */
        PKIXBuilderParameters params = new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setDate(new Date(System.currentTimeMillis() - 86400000L));

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build cert path - should succeed with both native
         * check_time and Java fallback paths */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);
        CertPathBuilderResult result = cpb.build(params);

        assertNotNull("CertPathBuilderResult should not be null", result);
        checkPKIXCertPathBuilderResult(result, caCert,
            serverCert.getPublicKey());
    }

    /**
     * Test that setDate() with a date after cert expiry fails regardless of
     * native check_time support.
     *
     * Uses currently-valid certs but sets a custom date far in the future
     * which is after their expiry. When native check_time is supported,
     * the native builder rejects. When not supported, the Java fallback date
     * check rejects the target cert before native building.
     */
    @Test
    public void testSetDateFallbackRejectsExpiredDate()
        throws Exception {

        KeyStore store = null;
        X509Certificate serverCert = null;
        Collection<Certificate> certCollection =
            new ArrayList<>();

        /* Load KeyStore with CA cert as trust anchor */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        assertNotNull("KeyStore should not be null", store);

        /* Load server cert */
        serverCert = loadCertFromFile(serverCertDer);
        certCollection.add(serverCert);

        /* Create CertStore with target cert */
        CertStore certStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(certCollection));

        /* Create PKIXBuilderParameters with custom date set
         * to 100 years from now (after any test cert's validity) */
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.YEAR, 100);
        PKIXBuilderParameters params =
            new PKIXBuilderParameters(store, null);
        params.setRevocationEnabled(false);
        params.addCertStore(certStore);
        params.setDate(cal.getTime());

        /* Set target cert selector */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(serverCert);
        params.setTargetCertConstraints(selector);

        /* Build cert path, should fail with both native
         * check_time and Java fallback paths */
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", provider);

        try {
            cpb.build(params);
            fail("Expected CertPathBuilderException for date after " +
                "cert expiry");
        } catch (CertPathBuilderException e) {
            /* Expected */
            assertNotNull("Exception message should not be null",
                e.getMessage());
        }
    }

    /**
     * Test that building a cert path with intermediate chain fails when
     * key size constraint disables the signer's key. Uses the RSA
     * intermediate chain (server -> int2 -> int1 -> root) with
     * RSA keySize < 4096, so all 2048-bit signer keys are rejected.
     */
    @Test
    public void testSignerKeyConstraintsRejectsSmallKey()
        throws Exception {

        String origProperty = null;
        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate int2Cert = null;
        X509Certificate int1Cert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            store = createKeyStoreFromFile(
                jksCaServerRSA2048, keyStorePass);
            assertNotNull("KeyStore should not be null", store);

            serverCert = loadCertFromFile(intRsaServerCertDer);
            int2Cert = loadCertFromFile(intRsaInt2CertDer);
            int1Cert = loadCertFromFile(intRsaInt1CertDer);
            certCollection.add(serverCert);
            certCollection.add(int2Cert);
            certCollection.add(int1Cert);

            /* Disable RSA keys smaller than 4096 bits,
             * all test certs use 2048-bit RSA */
            Security.setProperty(
                "jdk.certpath.disabledAlgorithms",
                "RSA keySize < 4096");

            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));

            PKIXBuilderParameters params =
                new PKIXBuilderParameters(store, null);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(serverCert);
            params.setTargetCertConstraints(selector);

            CertPathBuilder cpb =
                CertPathBuilder.getInstance("PKIX", provider);

            try {
                cpb.build(params);
                fail("Expected CertPathBuilderException for " +
                     "RSA keySize < 4096 constraint");
            } catch (CertPathBuilderException e) {
                assertNotNull(
                    "Exception message should not be null",
                    e.getMessage());
                assertTrue(
                    "Exception should mention algorithm " +
                    "constraints, got: " + e.getMessage(),
                    e.getMessage().contains(
                        "Algorithm constraints"));
            }

        } finally {
            if (origProperty != null) {
                Security.setProperty(
                    "jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty(
                    "jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    /**
     * Test that intermediate filtering prevents chain building when
     * intermediates use a disabled signature algorithm. Uses the RSA
     * intermediate chain (server -> int2 -> int1 -> root) and disables
     * SHA256 so intermediates are filtered out, preventing native
     * chain building from finding a valid path.
     */
    @Test
    public void testDisabledAlgoFiltersIntermediates()
        throws Exception {

        String origProperty = null;
        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate int2Cert = null;
        X509Certificate int1Cert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            store = createKeyStoreFromFile(
                jksCaServerRSA2048, keyStorePass);
            assertNotNull("KeyStore should not be null", store);

            serverCert = loadCertFromFile(intRsaServerCertDer);
            int2Cert = loadCertFromFile(intRsaInt2CertDer);
            int1Cert = loadCertFromFile(intRsaInt1CertDer);
            certCollection.add(serverCert);
            certCollection.add(int2Cert);
            certCollection.add(int1Cert);

            /* Disable SHA256, which is used in all cert
             * signatures (SHA256withRSA). Target cert check
             * should catch this before intermediates are
             * even considered. */
            Security.setProperty(
                "jdk.certpath.disabledAlgorithms", "SHA256");

            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));

            PKIXBuilderParameters params =
                new PKIXBuilderParameters(store, null);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(serverCert);
            params.setTargetCertConstraints(selector);

            CertPathBuilder cpb =
                CertPathBuilder.getInstance("PKIX", provider);

            try {
                cpb.build(params);
                fail("Expected CertPathBuilderException for " +
                     "SHA256 disabled with intermediate chain");
            } catch (CertPathBuilderException e) {
                assertNotNull(
                    "Exception message should not be null",
                    e.getMessage());
                assertTrue(
                    "Exception should mention algorithm " +
                    "constraints, got: " + e.getMessage(),
                    e.getMessage().contains(
                        "Algorithm constraints"));
            }

        } finally {
            if (origProperty != null) {
                Security.setProperty(
                    "jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty(
                    "jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    /**
     * Test that algorithm constraints allow a valid chain when
     * the disabled algorithms list does not conflict with the
     * chain's algorithms. Uses the RSA intermediate chain with
     * only MD2 disabled (which none of the test certs use).
     */
    @Test
    public void testAlgorithmConstraintsAllowValidChain()
        throws Exception {

        String origProperty = null;
        KeyStore store = null;
        X509Certificate serverCert = null;
        X509Certificate int2Cert = null;
        X509Certificate int1Cert = null;
        X509Certificate caCert = null;
        Collection<Certificate> certCollection = new ArrayList<>();

        origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            store = createKeyStoreFromFile(
                jksCaServerRSA2048, keyStorePass);
            assertNotNull("KeyStore should not be null", store);

            caCert = loadCertFromFile(caCertDer);
            serverCert = loadCertFromFile(intRsaServerCertDer);
            int2Cert = loadCertFromFile(intRsaInt2CertDer);
            int1Cert = loadCertFromFile(intRsaInt1CertDer);
            certCollection.add(serverCert);
            certCollection.add(int2Cert);
            certCollection.add(int1Cert);

            /* Set disabled algorithms to MD2 only, which is
             * not used by any cert in the chain. Chain should
             * build successfully. */
            Security.setProperty(
                "jdk.certpath.disabledAlgorithms", "MD2");

            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certCollection));

            PKIXBuilderParameters params =
                new PKIXBuilderParameters(store, null);
            params.setRevocationEnabled(false);
            params.addCertStore(certStore);

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(serverCert);
            params.setTargetCertConstraints(selector);

            CertPathBuilder cpb =
                CertPathBuilder.getInstance("PKIX", provider);
            CertPathBuilderResult result = cpb.build(params);

            assertNotNull(
                "CertPathBuilderResult should not be null",
                result);
            checkPKIXCertPathBuilderResult(
                result, caCert, serverCert.getPublicKey());

        } finally {
            if (origProperty != null) {
                Security.setProperty(
                    "jdk.certpath.disabledAlgorithms",
                    origProperty);
            }
            else {
                Security.setProperty(
                    "jdk.certpath.disabledAlgorithms", "");
            }
        }
    }
}

