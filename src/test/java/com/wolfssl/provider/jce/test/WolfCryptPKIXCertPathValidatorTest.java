/* wolfCryptPKIXCertPathValidatorTest.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
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
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.TrustAnchor;
import java.security.cert.PolicyNode;
import java.security.cert.X509CertSelector;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.lang.IllegalArgumentException;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptPKIXCertPathValidatorTest {

    protected String provider = "wolfJCE";
    //protected String provider = "SUN";

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
    protected static String crlDer           = null; /* crl.der */

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

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testSetupAndProviderInstallation()
        throws Exception, NoSuchProviderException {

        String certPre = "";
        String jksExt = ".jks";

        System.out.println("JCE WolfCryptPKIXCertPathValidator Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        if (isAndroid()) {
            /* On Android, example certs/keys/KeyStores are on SD card */
            certPre = "/sdcard/";

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
            certPre.concat("examples/certs/intermediate/server-int-cert.pem");
        intRsaInt1CertDer =
            certPre.concat("examples/certs/intermediate/ca-int-cert.pem");
        intRsaInt2CertDer =
            certPre.concat("examples/certs/intermediate/ca-int2-cert.pem");

        intEccServerCertDer =
            certPre.concat("examples/certs/intermediate/server-int-ecc-cert.der");
        intEccInt1CertDer =
            certPre.concat("examples/certs/intermediate/ca-int-ecc-cert.der");
        intEccInt2CertDer =
            certPre.concat("examples/certs/intermediate/ca-int2-ecc-cert.der");

        crlDer =
            certPre.concat("examples/certs/crl/crl.der");

        /* Test if file exists, if not might be running on Android */
        File f = new File(jksCaServerRSA2048);
        if (!f.exists()) {
            /* No known file paths, throw exception */
            System.out.println("Could not find example JKS file " +
                f.getAbsolutePath());
            throw new Exception("Unable to find example JKS files for test");
        }
    }

    /**
     * Create KeyStore object from KeyStore file (.jks/.bks).
     * @param KeyStore file to load into new object
     */
    private KeyStore createKeyStoreFromFile(String file, String jksPass)
        throws IllegalArgumentException, FileNotFoundException,
               KeyStoreException, IOException, NoSuchAlgorithmException,
               CertificateException {

        KeyStore store = null;
        InputStream stream = null;

        if (file == null) {
            throw new IllegalArgumentException(
                "Input file is null when creating KeyStore");
        }

        stream = new FileInputStream(file);
        store = KeyStore.getInstance(keyStoreType);
        store.load(stream, jksPass.toCharArray());
        stream.close();

        return store;
    }

    private void checkPKIXCertPathValidatorResult(
        CertPathValidatorResult result, X509Certificate expectedAnchor,
        PublicKey expectedPublicKey) {

        PKIXCertPathValidatorResult pResult = null;
        TrustAnchor anchor = null;
        PolicyNode policyTree = null;
        PublicKey pubKey = null;

        /* Check not null and of type PKIXCertPathValidatorResult */
        assertNotNull(result);
        assertTrue(result instanceof PKIXCertPathValidatorResult);
        pResult = (PKIXCertPathValidatorResult)result;

        /* Check TrustAnchor matches expected */
        anchor = pResult.getTrustAnchor();
        assertNotNull(anchor);
        assertNotNull(anchor.getTrustedCert());
        assertEquals(anchor.getTrustedCert(), expectedAnchor);

        /* Check PolicyTree matches expected - TODO */
        //policyTree = pResult.getPolicyTree();
        //assertNotNull(policyTree);

        /* Check PublicKey returned matches expected leaf cert */
        pubKey = pResult.getPublicKey();
        assertNotNull(pubKey);
        assertEquals(pubKey, expectedPublicKey);
    }

    @Test
    public void testSingleCertValidateRSA()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate serverCert = null;
        List<Certificate> certList = new ArrayList<>();
        X509Certificate caCert = null;
        PublicKey certPubKey = null;

        /* Use example KeyStore that verifies server-cert.der */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        certFactory = CertificateFactory.getInstance("X.509");

        /* Create X509Certificate from CA cert for TrustAnchor result compare */
        fis = new FileInputStream(caCertDer);
        caCert = (X509Certificate)certFactory.generateCertificate(fis);
        fis.close();

        /* Import server-cert.der into Certificate object */
        fis = new FileInputStream(serverCertDer);
        serverCert = certFactory.generateCertificate(fis);
        certPubKey = serverCert.getPublicKey(); /* for comparison later */
        certList.add(serverCert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        CertPathValidatorResult result = cpv.validate(path, params);

        checkPKIXCertPathValidatorResult(result, caCert, certPubKey);
    }

    /**
     * Test that setting the target cert constraints with
     * PKIXParameters.setTargetCertConstraints() passes with correct cert
     * and fails with wrong cert.
     */
    @Test
    public void testSingleCertValidateRSAWithCertConstraints()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate serverCert = null;
        List<Certificate> certList = new ArrayList<>();
        X509Certificate caCert = null;
        PublicKey certPubKey = null;

        /* Use example KeyStore that verifies server-cert.der */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        certFactory = CertificateFactory.getInstance("X.509");

        /* Create X509Certificate from CA cert for TrustAnchor result compare */
        fis = new FileInputStream(caCertDer);
        caCert = (X509Certificate)certFactory.generateCertificate(fis);
        fis.close();

        /* Import server-cert.der into Certificate object */
        fis = new FileInputStream(serverCertDer);
        serverCert = certFactory.generateCertificate(fis);
        certPubKey = serverCert.getPublicKey(); /* for comparison later */
        certList.add(serverCert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Add some cert constraints, should pass */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate((X509Certificate)serverCert);
        params.setTargetCertConstraints(selector);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        CertPathValidatorResult result = cpv.validate(path, params);

        checkPKIXCertPathValidatorResult(result, caCert, certPubKey);

        /* Invalid cert constraints should cause failure */
        fis = new FileInputStream(clientCertDer); /* wrong cert */
        serverCert = certFactory.generateCertificate(fis);
        fis.close();
        selector.setCertificate((X509Certificate)serverCert);
        params.setTargetCertConstraints(selector);

        try {
            result = cpv.validate(path, params);
        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }

    /**
     * Test that enabling revocation checking support works when CRL is loaded
     * and fails when CRL is not.
     */
    @Test
    public void testSingleCertValidateRSAWithCRL()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate serverCert = null;
        List<Certificate> certList = new ArrayList<>();
        X509Certificate caCert = null;
        PublicKey certPubKey = null;

        /* For CRL use */
        CRL crl = null;
        CertStore crlStore = null;
        Collection<CRL> crls = null;
        List<CertStore> certStores = null;

        if (!WolfCrypt.CrlEnabled()) {
            /* Native CRL not enabled, skip CRL test */
            System.out.println("CertPathValidator CRL test skipped, " +
                "CRL not compiled in");
            return;
        }

        /* Use example KeyStore that verifies server-cert.der */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        certFactory = CertificateFactory.getInstance("X.509");

        /* Create X509Certificate from CA cert for TrustAnchor result compare */
        fis = new FileInputStream(caCertDer);
        caCert = (X509Certificate)certFactory.generateCertificate(fis);
        fis.close();

        /* Import server-cert.der into Certificate object */
        fis = new FileInputStream(serverCertDer);
        serverCert = certFactory.generateCertificate(fis);
        certPubKey = serverCert.getPublicKey(); /* for comparison later */
        certList.add(serverCert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Load CRL into PKIXParameters for use in verification
         * crl.der matches ca-cert.der, which is the root for server-cert.der */
        certStores = new ArrayList<>();
        crls = new HashSet<>();
        fis = new FileInputStream(crlDer);
        crl = certFactory.generateCRL(fis);
        fis.close();
        crls.add(crl);
        crlStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(crls));
        certStores.add(crlStore);
        params.setCertStores(certStores);
        params.setRevocationEnabled(true);

        /* Add some cert constraints, should pass */
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate((X509Certificate)serverCert);
        params.setTargetCertConstraints(selector);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        CertPathValidatorResult result = cpv.validate(path, params);

        checkPKIXCertPathValidatorResult(result, caCert, certPubKey);

        /* Verification with revocation enabled, but no CRL loaded
         * should fail */

        params.setCertStores(null);
        params.setRevocationEnabled(true);
        try {
            result = cpv.validate(path, params);
        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }

    @Test
    public void testSingleCertValidateRSAFailure()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate clientCert = null;
        List<Certificate> certList = new ArrayList<>();

        /* Use example KeyStore that verifies server-cert.der */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Import client-cert.der into Certificate object */
        certFactory = CertificateFactory.getInstance("X.509");
        fis = new FileInputStream(clientCertDer);
        clientCert = certFactory.generateCertificate(fis);
        certList.add(clientCert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        try {
            cpv.validate(path, params);

            fail("CertPathValidator.validate() should fail when mismatched " +
                 "cert and TrustAnchors");
        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }

    /**
     * Test validate succeeds on a certificate chain with two intermediate
     * CAs in between peer and root.
     *
     * Chain (RSA-based):
     *     Root CA (ca-cert.der)
     *         Intermediate CA 1 (ca-int-cert.der)
     *             Intermediate CA 1 (ca-int2-cert.der)
     *                 Peer (server-cert.der)
     */
    @Test
    public void testCertChainValidateRSA()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate cert = null;
        List<Certificate> certList = new ArrayList<>();
        X509Certificate caCert = null;
        PublicKey certPubKey = null;

        /* Use example KeyStore that verifies server-cert.der */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Build cert chain, going from peer to last intermediate */
        certFactory = CertificateFactory.getInstance("X.509");

        /* Create X509Certificate from CA cert for TrustAnchor result compare */
        fis = new FileInputStream(caCertDer);
        caCert = (X509Certificate)certFactory.generateCertificate(fis);
        fis.close();

        /* Server/peer cert */
        fis = new FileInputStream(intRsaServerCertDer);
        cert = certFactory.generateCertificate(fis);
        certPubKey = cert.getPublicKey(); /* for expected comparison later */
        certList.add(cert);
        fis.close();

        /* Intermediate CA 2 */
        fis = new FileInputStream(intRsaInt2CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Intermediate CA 1 */
        fis = new FileInputStream(intRsaInt1CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        CertPathValidatorResult result = cpv.validate(path, params);

        checkPKIXCertPathValidatorResult(result, caCert, certPubKey);
    }

    /**
     * Test validate fails on an out-of-order certificate chain with two
     * intermediate CAs in between peer and root.
     *
     * Correct Chain (RSA-based):
     *     Root CA (ca-cert.der)
     *         Intermediate CA 1 (ca-int-cert.der)
     *             Intermediate CA 2 (ca-int2-cert.der)
     *                 Peer (server-cert.der)
     *
     * Out of Order Chain (RSA-based) - incorrect:
     *     Root CA (ca-cert.der)
     *         Intermediate CA 2 (ca-int2-cert.der)
     *             Intermediate CA 1 (ca-int-cert.der)
     *                 Peer (server-cert.der)
     */
    @Test
    public void testCertChainValidateRSAFailureOutOfOrder()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate cert = null;
        List<Certificate> certList = new ArrayList<>();

        /* Use example KeyStore that verifies server-cert.der */
        store = createKeyStoreFromFile(jksCaServerRSA2048, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Build cert chain, going from peer to last intermediate */
        certFactory = CertificateFactory.getInstance("X.509");

        /* Server/peer cert */
        fis = new FileInputStream(intRsaServerCertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Intermediate CA 1 (out of order, should be last) */
        fis = new FileInputStream(intRsaInt1CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Intermediate CA 2 (out of order, should be middle) */
        fis = new FileInputStream(intRsaInt2CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);

        try {
            cpv.validate(path, params);
            fail("Expected out of order cert chain to fail");

        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }

    @Test
    public void testSingleCertValidateECC()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate serverCert = null;
        List<Certificate> certList = new ArrayList<>();
        X509Certificate caCert = null;
        PublicKey certPubKey = null;

        /* Use example KeyStore that verifies server-ecc.der */
        store = createKeyStoreFromFile(jksCaServerECC256, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        certFactory = CertificateFactory.getInstance("X.509");

        /* Create X509Certificate from CA cert for TrustAnchor result compare */
        fis = new FileInputStream(caEccCertDer);
        caCert = (X509Certificate)certFactory.generateCertificate(fis);
        fis.close();

        /* Import server-ecc.der into Certificate object */
        fis = new FileInputStream(serverEccDer);
        serverCert = certFactory.generateCertificate(fis);
        certPubKey = serverCert.getPublicKey(); /* for comparison later */
        certList.add(serverCert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        CertPathValidatorResult result = cpv.validate(path, params);

        checkPKIXCertPathValidatorResult(result, caCert, certPubKey);
    }

    @Test
    public void testSingleCertValidateECCFailure()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate clientCert = null;
        List<Certificate> certList = new ArrayList<>();

        /* Use example KeyStore that verifies server-ecc.der */
        store = createKeyStoreFromFile(jksCaServerECC256, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Import client-ecc-cert.der into Certificate object */
        certFactory = CertificateFactory.getInstance("X.509");
        fis = new FileInputStream(clientEccCertDer);
        clientCert = certFactory.generateCertificate(fis);
        certList.add(clientCert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);

        try {
            cpv.validate(path, params);
            fail("CertPathValidator.validate() should fail when mismatched " +
                 "cert and TrustAnchors");
        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }

    /**
     * Test validate succeeds on a certificate chain with two intermediate
     * CAs in between peer and root.
     *
     * Chain (ECC-based):
     *     Root CA (ca-ecc-cert.der)
     *         Intermediate CA 1 (ca-int-ecc-cert.der)
     *             Intermediate CA 1 (ca-int2-ecc-cert.der)
     *                 Peer (server-ecc.der)
     */
    @Test
    public void testCertChainValidateECC()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate cert = null;
        List<Certificate> certList = new ArrayList<>();
        X509Certificate caCert = null;
        PublicKey certPubKey = null;

        /* Use example KeyStore that verifies server-ecc.der */
        store = createKeyStoreFromFile(jksCaServerECC256, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Build cert chain, going from peer to last intermediate */
        certFactory = CertificateFactory.getInstance("X.509");

        /* Create X509Certificate from CA cert for TrustAnchor result compare */
        fis = new FileInputStream(caEccCertDer);
        caCert = (X509Certificate)certFactory.generateCertificate(fis);
        fis.close();

        /* Server/peer cert */
        fis = new FileInputStream(intEccServerCertDer);
        cert = certFactory.generateCertificate(fis);
        certPubKey = cert.getPublicKey(); /* for comparison later */
        certList.add(cert);
        fis.close();

        /* Intermediate CA 2 */
        fis = new FileInputStream(intEccInt2CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Intermediate CA 1 */
        fis = new FileInputStream(intEccInt1CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        CertPathValidatorResult result = cpv.validate(path, params);

        checkPKIXCertPathValidatorResult(result, caCert, certPubKey);
    }

    /**
     * Test validate succeeds on a certificate chain with two intermediate
     * CAs in between peer and root.
     *
     * Correct Chain (ECC-based):
     *     Root CA (ca-ecc-cert.der)
     *         Intermediate CA 1 (ca-int-ecc-cert.der)
     *             Intermediate CA 2 (ca-int2-ecc-cert.der)
     *                 Peer (server-ecc.der)
     * Out of Order Chain (ECC-based) - invalid:
     *     Root CA (ca-ecc-cert.der)
     *         Intermediate CA 2 (ca-int2-ecc-cert.der)
     *             Intermediate CA 1 (ca-int-ecc-cert.der)
     *                 Peer (server-ecc.der)
     */
    @Test
    public void testCertChainValidateECCFailureOutOfOrder()
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException,
               InvalidAlgorithmParameterException, CertPathValidatorException,
               NoSuchProviderException, Exception {

        KeyStore store = null;
        CertificateFactory certFactory = null;
        InputStream fis = null;
        Certificate cert = null;
        List<Certificate> certList = new ArrayList<>();


        /* Use example KeyStore that verifies server-ecc.der */
        store = createKeyStoreFromFile(jksCaServerECC256, keyStorePass);
        if (store == null || store.size() != 1) {
            throw new Exception("Error creating KeyStore");
        }

        /* Build cert chain, going from peer to last intermediate */
        certFactory = CertificateFactory.getInstance("X.509");

        /* Server/peer cert */
        fis = new FileInputStream(intEccServerCertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Intermediate CA 1 (out of order, should be last) */
        fis = new FileInputStream(intEccInt1CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Intermediate CA 2 (out of order, should be middle) */
        fis = new FileInputStream(intEccInt2CertDer);
        cert = certFactory.generateCertificate(fis);
        certList.add(cert);
        fis.close();

        /* Create PKIXParameters with trusted KeyStore */
        PKIXParameters params = new PKIXParameters(store);

        /* Disable revocation, fails with SUN. Missing CRL in cert? */
        params.setRevocationEnabled(false);

        /* Validate cert chain, throws CertPathValidatorException on error */
        CertPath path = certFactory.generateCertPath(certList);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);

        try {
            cpv.validate(path, params);
            fail("Expected out of order cert chain to fail");

        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }
}

