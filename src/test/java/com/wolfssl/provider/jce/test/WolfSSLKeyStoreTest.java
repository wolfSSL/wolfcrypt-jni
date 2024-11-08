/* wolfSSLKeyStoreTest.java
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
import org.junit.Assume;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;

import java.util.Arrays;
import java.util.List;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;

import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfSSLKeyStoreTest {

    private final String storeType = "WKS";
    private final String jksExt = ".wks";
    private static final String storeProvider = "wolfJCE";
    /* Example pass is "wolfsslpassword" instead of normal
     * "wolfSSL test" because with wolfCrypt FIPS the HMAC minimum key
     * length is 14 bytes. Password gets passed down to HMAC via PBKDF2 */
    protected static String storePass = "wolfsslpassword";

    /*
     * Example Certificate and Key file paths:
     *   serverCertDer = server-cert.der
     *   serverEccDer  = server-ecc.der
     *   clientCertDer = client-cert.der
     *   clientEccCertDer = client-ecc-cert.der
     *   caCertDer     = ca-cert.der
     *   caEccCertDer  = ca-ecc-cert.der
     */
    protected static String serverCertDer    = null;
    protected static String serverEccDer     = null;
    protected static String clientCertDer    = null;
    protected static String clientEccCertDer = null;
    protected static String caCertDer        = null;
    protected static String caEccCertDer     = null;

    /*
     * Example private key files:
     *   server-keyPkcs8.der, matches to server-cert.der
     *   ecc-keyPkcs8.der, matches to server-ecc.der
     */
    protected static String serverPkcs8Der   = null;
    protected static String eccPkcs8Der      = null;

    /* RSA-based cert chain with intermediates:
     * server/peer: server-int-cert.der
     * intermediate CA 2: ca-int2-cert.der
     * intermediate CA 1: ca-int-cert.der
     * root CA: ca-cert.pem */
    protected static String intRsaServerCertDer = null;
    protected static String intRsaInt2CertDer   = null;
    protected static String intRsaInt1CertDer   = null;

    /* ECC-based cert chain with intermediates:
     * server/peer: server-int-ecc-cert.der
     * intermediate CA 2: ca-in2-ecc-cert.der
     * intermediate CA 1: ca-int-ecc-cert.der
     * root CA: ca-ecc-cert.pem */
    protected static String intEccServerCertDer = null;
    protected static String intEccInt2CertDer   = null;
    protected static String intEccInt1CertDer   = null;

    /* Java PrivateKey / Certificate objects containing example key/certs */
    private static PrivateKey serverKeyRsa = null;    /* server-keyPkcs8.der */
    private static PrivateKey serverKeyEcc = null;    /* ecc-keyPkcs8.der */
    private static Certificate serverCertRsa = null;  /* server-cert.der */
    private static Certificate serverCertEcc = null;  /* server-ecc.der */
    private static Certificate clientCertRsa = null;  /* client-cert.der */
    private static Certificate clientCertEcc = null;  /* client-ecc-cert.der */
    private static Certificate[] rsaServerChain = null; /* RSA chain */
    private static Certificate[] eccServerChain = null; /* ECC chain */
    private static Certificate[] invalidChain = null;

    /* Example .wks KeyStore file paths */
    private static String clientWKS = null;          /* client.wks */
    private static String clientRsa1024WKS = null;   /* client-rsa-1024.wks */
    private static String clientRsaWKS = null;       /* client-rsa.wks */
    private static String clientEccWKS = null;       /* client-ecc.wks */
    private static String serverWKS = null;          /* server.wks */
    private static String serverRsa1024WKS = null;   /* server-rsa-1024.wks */
    private static String serverRsaWKS = null;       /* server-rsa.wks */
    private static String serverEccWKS = null;       /* server-ecc.wks */
    private static String caCertsWKS = null;         /* cacerts.wks */
    private static String caClientWKS = null;        /* ca-client.wks */
    private static String caServerWKS = null;        /* ca-server.wks */
    private static String caServerRsa2048WKS = null; /* ca-server-rsa-2048.wks */
    private static String caServerEcc256WKS = null;  /* ca-server-ecc-256.wks */

    /* Class wide SecureRandom for use, only initialize once */
    private SecureRandom rand = new SecureRandom();

    /* Used to store/reset Java Security property for PBKDF2 iteration
     * count. Default 210,000 PBKDF2 iterations makes this test run very
     * slow. We set down to 10,000 for test duration. */
    private static boolean iterationCountPropSet = false;
    private static String iterationCountProp = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

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
     * Test if this environment is Windows.
     * @return true if Windows, otherwise false.
     */
    private static boolean isWindows() {
        if (System.getProperty("os.name").startsWith("Windows")) {
            return true;
        }
        return false;
    }

    /**
     * Read in and convert DER private key into PrivateKey object.
     *
     * @param derFilePath file path to DER-encoded private key
     * @param alg algorithm type: "RSA", "EC"
     *
     * @return new PrivateKey object representing DER key file passed in
     *
     * @throws IllegalArgumentException on bad argument or processing of arg
     * @throws IOException on error converting File to Path
     * @throws NoSuchAlgorithmException on bad "alg" when getting KeyFactory
     * @throws InvalidKeySpecException on error generating PrivateKey object
     * @throws Exception on other error
     */
    private static PrivateKey derFileToPrivateKey(String derFilePath,
        String alg) throws IllegalArgumentException, IOException,
                           NoSuchAlgorithmException, InvalidKeySpecException,
                           InvalidKeySpecException {

        File file = null;
        byte[] fileBytes = null;
        PKCS8EncodedKeySpec spec = null;
        KeyFactory kf = null;
        PrivateKey key = null;

        if (derFilePath == null || derFilePath.isEmpty()) {
            throw new IllegalArgumentException(
                "Input DER file path is null or empty");
        }

        file = new File(derFilePath);
        fileBytes = Files.readAllBytes(file.toPath());

        if (fileBytes == null || fileBytes.length == 0) {
            throw new IllegalArgumentException(
                "Bytes read from DER file is null or empty, bad file path?");
        }

        spec = new PKCS8EncodedKeySpec(fileBytes);
        if (spec == null) {
            throw new InvalidKeySpecException(
                "Unable to create PKCS8EncodedKeySpec");
        }

        kf = KeyFactory.getInstance(alg);
        key = kf.generatePrivate(spec);

        return key;
    }

    /**
     * Read in and convert certificate file to Certificate object.
     *
     * @param certPath path to certificate file
     *
     * @return new Certificate object representing certPath file
     *
     * @throws FileNotFoundException on error reading certPath file
     * @throws CertificateException on error geting CertificateFactory or
     *         generating Certificate object
     */
    private static Certificate certFileToCertificate(String certPath)
        throws FileNotFoundException, CertificateException {

        FileInputStream fis = null;
        CertificateFactory cf = null;
        Certificate cert = null;

        fis = new FileInputStream(certPath);
        cf = CertificateFactory.getInstance("X.509");
        cert = cf.generateCertificate(fis);

        return cert;
    }


    /**
     * Create PrivateKey and Certificate objects based on files.
     * Assumes paths have already been set prior in
     * testSetupAndProviderInstallation().
     */
    private static void createTestObjects()
        throws IOException, FileNotFoundException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException {

        Certificate tmpCert = null;

        /* Create PrivateKey from server RSA private key DER */
        serverKeyRsa = derFileToPrivateKey(serverPkcs8Der, "RSA");
        assertNotNull(serverKeyRsa);

        /* Create PrivateKey from server ECC private key DER */
        serverKeyEcc = derFileToPrivateKey(eccPkcs8Der, "EC");
        assertNotNull(serverKeyEcc);

        /* Create Certificate from server RSA cert */
        serverCertRsa = certFileToCertificate(serverCertDer);
        assertNotNull(serverCertRsa);

        /* Create Certificate from server ECC cert */
        serverCertEcc = certFileToCertificate(serverEccDer);
        assertNotNull(serverCertEcc);

        /* Create Certificate from client RSA cert */
        clientCertRsa = certFileToCertificate(clientCertDer);
        assertNotNull(clientCertRsa);

        /* Create Certificate from client ECC cert */
        clientCertEcc = certFileToCertificate(clientEccCertDer);
        assertNotNull(clientCertEcc);

        /* Create RSA cert chain */
        rsaServerChain = new Certificate[3];
        tmpCert = certFileToCertificate(intRsaServerCertDer);
        rsaServerChain[0] = tmpCert;
        tmpCert = certFileToCertificate(intRsaInt2CertDer);
        rsaServerChain[1] = tmpCert;
        tmpCert = certFileToCertificate(intRsaInt1CertDer);
        rsaServerChain[2] = tmpCert;

        /* Create ECC cert chain */
        eccServerChain = new Certificate[3];
        tmpCert = certFileToCertificate(intEccServerCertDer);
        eccServerChain[0] = tmpCert;
        tmpCert = certFileToCertificate(intEccInt2CertDer);
        eccServerChain[1] = tmpCert;
        tmpCert = certFileToCertificate(intEccInt1CertDer);
        eccServerChain[2] = tmpCert;

        /* Create invalid cert chain */
        invalidChain = new Certificate[3];
        tmpCert = certFileToCertificate(intRsaServerCertDer);
        invalidChain[0] = tmpCert;
        tmpCert = certFileToCertificate(intEccInt2CertDer);
        invalidChain[1] = tmpCert;
        tmpCert = certFileToCertificate(intRsaInt1CertDer);
        invalidChain[2] = tmpCert;
    }

    @BeforeClass
    public static void testSetupAndProviderInstallation()
        throws Exception, NoSuchProviderException {

        String certPre = "";

        System.out.println("JCE WolfSSLKeyStore Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider(storeProvider);
        assertNotNull(p);

        if (isAndroid()) {
            /* On Android, example certs/keys/KeyStores are on SD card */
            certPre = "/sdcard/";
        }

        /* Set paths to example certs/keys */
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

        serverPkcs8Der =
            certPre.concat("examples/certs/server-keyPkcs8.der");
        eccPkcs8Der =
            certPre.concat("examples/certs/ecc-keyPkcs8.der");

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

        /* Set paths to example WKS KeyStore files */
        clientWKS =
            certPre.concat("examples/certs/client.wks");
        clientRsa1024WKS =
            certPre.concat("examples/certs/client-rsa-1024.wks");
        clientRsaWKS =
            certPre.concat("examples/certs/client-rsa.wks");
        clientEccWKS =
            certPre.concat("examples/certs/client-ecc.wks");
        serverWKS =
            certPre.concat("examples/certs/server.wks");
        serverRsa1024WKS =
            certPre.concat("examples/certs/server-rsa-1024.wks");
        serverRsaWKS =
            certPre.concat("examples/certs/server-rsa.wks");
        serverEccWKS =
            certPre.concat("examples/certs/server-ecc.wks");
        caCertsWKS =
            certPre.concat("examples/certs/cacerts.wks");
        caClientWKS =
            certPre.concat("examples/certs/ca-client.wks");
        caServerWKS =
            certPre.concat("examples/certs/ca-server.wks");
        caServerRsa2048WKS =
            certPre.concat("examples/certs/ca-server-rsa-2048.wks");
        caServerEcc256WKS =
            certPre.concat("examples/certs/ca-server-ecc-256.wks");

        /* Test if file exists, if not might be running on Android */
        File f = new File(serverCertDer);
        if (!f.exists()) {
            /* No known file paths, throw exception */
            System.out.println("Could not find example cert file " +
                f.getAbsolutePath());
            throw new Exception("Unable to find example cert files for test");
        }

        /* Create PrivateKey / Certificate objects from files */
        createTestObjects();

        /* Save existing PBKDF2 iteration count, set lower for test */
        String iCount = Security.getProperty("wolfjce.wks.iterationCount");
        iterationCountProp = iCount;
        Security.setProperty("wolfjce.wks.iterationCount", "10000");
        iterationCountPropSet = true;
    }

    @AfterClass
    public static void resetSecurityProperties()
        throws Exception, NoSuchProviderException {

        if (iterationCountPropSet && (iterationCountProp != null)) {
            Security.setProperty("wolfjce.wks.iterationCount",
                iterationCountProp);
        }
    }

    @Test
    public void testGetKeyStoreFromProvider()
        throws NoSuchProviderException, KeyStoreException {

        KeyStore store = null;

        /* Getting WKS after wolfJCE is installed should work w/o exception */
        store = KeyStore.getInstance(storeType);

        /* Getting WKS type from wolfJCE should work without exception */
        store = KeyStore.getInstance(storeType, storeProvider);
        assertNotNull(store);

        try {
            store = KeyStore.getInstance("NotValid", storeProvider);
        } catch (KeyStoreException e) {
            /* expected */
        }
    }

    @Test
    public void testStoreSingleKeyAndCert()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate certOut = null;

        /* Storing single RSA key and matching cert should succeed */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("serverCert", serverKeyRsa, storePass.toCharArray(),
            new Certificate[] { serverCertRsa });
        assertEquals(1, store.size());

        keyOut = (PrivateKey)store.getKey("serverCert",
            storePass.toCharArray());
        assertNotNull(keyOut);
        if (!serverKeyRsa.equals(keyOut)) {
            fail("Key get/set does not match each other");
        }
        certOut = store.getCertificate("serverCert");
        assertNotNull(certOut);
        assertEquals(serverCertRsa, certOut);

        /* Storing single ECC key and matching cert should succeed */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("serverCert", serverKeyEcc, storePass.toCharArray(),
            new Certificate[] { serverCertEcc });
        assertEquals(1, store.size());

        keyOut = (PrivateKey)store.getKey("serverCert",
            storePass.toCharArray());
        assertNotNull(keyOut);
        if (!serverKeyEcc.equals(keyOut)) {
            fail("Key get/set does not match each other");
        }
        certOut = store.getCertificate("serverCert");
        assertNotNull(certOut);
        assertEquals(serverCertEcc, certOut);

        /* Storing RSA key with non-matching cert should fail */
        /* SUN JKS seems to allow loading invalid key/cert matches */
        if (!storeProvider.equals("SUN")) {
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());
            try {
                store.setKeyEntry("invalidKey", serverKeyRsa,
                    storePass.toCharArray(),
                    new Certificate[] { serverCertEcc });
                fail("setKeyEntry() should fail with mismatched key/cert");
            } catch (KeyStoreException e) {
                /* expected */
            }
            assertEquals(0, store.size());

            /* Storing ECC key with non-matching cert should fail */
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());
            try {
                store.setKeyEntry("invalidKey", serverKeyEcc,
                    storePass.toCharArray(),
                    new Certificate[] { serverCertRsa });
                fail("setKeyEntry() should fail with mismatched key/cert");
            } catch (KeyStoreException e) {
                /* expected */
            }
            assertEquals(0, store.size());
        }
    }

    @Test
    public void testStoreMultipleKeyAndCertPairs()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate certOut = null;

        /* Storing multiple matching key/cert pairs should succeed */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("serverCertRsa", serverKeyRsa,
            storePass.toCharArray(), new Certificate[] { serverCertRsa });
        assertEquals(1, store.size());
        store.setKeyEntry("serverCertEcc", serverKeyEcc,
            storePass.toCharArray(), new Certificate[] { serverCertEcc });
        assertEquals(2, store.size());

        keyOut = (PrivateKey)store.getKey("serverCertRsa",
            storePass.toCharArray());
        assertNotNull(keyOut);
        if (!serverKeyRsa.equals(keyOut)) {
            fail("RSA Key get/set does not match each other");
        }
        certOut = store.getCertificate("serverCertRsa");
        assertNotNull(certOut);
        assertEquals(serverCertRsa, certOut);

        keyOut = (PrivateKey)store.getKey("serverCertEcc",
            storePass.toCharArray());
        assertNotNull(keyOut);
        if (!serverKeyEcc.equals(keyOut)) {
            fail("ECC Key get/set does not match each other");
        }
        certOut = store.getCertificate("serverCertEcc");
        assertNotNull(certOut);
        assertEquals(serverCertEcc, certOut);
    }

    @Test
    public void testStoreSingleKeyAndCertChain()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate[] chainOut = null;

        /* Storing single RSA key/cert chain should succeed */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("serverRsa", serverKeyRsa,
            storePass.toCharArray(), rsaServerChain);
        assertEquals(1, store.size());

        keyOut = (PrivateKey)store.getKey("serverRsa",
            storePass.toCharArray());
        assertNotNull(keyOut);
        if (!serverKeyRsa.equals(keyOut)) {
            fail("RSA get/set Key does not match each other");
        }
        chainOut = store.getCertificateChain("serverRsa");
        assertNotNull(chainOut);
        if (!Arrays.equals(rsaServerChain, chainOut)) {
            fail("RSA get/set chain does not match");
        }

        /* Storing single ECC key/cert chain should succeed */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("serverEcc", serverKeyEcc,
            storePass.toCharArray(), eccServerChain);
        assertEquals(1, store.size());

        keyOut = (PrivateKey)store.getKey("serverEcc",
            storePass.toCharArray());
        assertNotNull(keyOut);
        if (!serverKeyEcc.equals(keyOut)) {
            fail("ECC get/set Key does not match each other");
        }
        chainOut = store.getCertificateChain("serverEcc");
        assertNotNull(chainOut);
        if (!Arrays.equals(eccServerChain, chainOut)) {
            fail("ECC get/set chain does not match");
        }

        /* Storing invalid chain should fail */
        /* SUN JKS seems to allow loading invalid cert chains, but we don't */
        if (!storeProvider.equals("SUN")) {
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());
            try {
                store.setKeyEntry("serverRsa", serverKeyRsa,
                    storePass.toCharArray(), invalidChain);
                fail("setKeyEntry() with invalid chain should fail");
            } catch (KeyStoreException e) {
                /* expected */
            }
            assertEquals(0, store.size());
        }
    }

    @Test
    public void testStoreMultipleKeyAndCertChains()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate[] chainOut = null;
        
        /* Storing multiple valid key/cert chain should succeed */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("serverRsa", serverKeyRsa,
            storePass.toCharArray(), rsaServerChain);
        assertEquals(1, store.size());
        store.setKeyEntry("serverEcc", serverKeyEcc,
            storePass.toCharArray(), eccServerChain);
        assertEquals(2, store.size());

        keyOut = (PrivateKey)store.getKey("serverRsa",
            storePass.toCharArray());
        assertNotNull(keyOut);
        if (!serverKeyRsa.equals(keyOut)) {
            fail("RSA get/set Key does not match");
        }
        chainOut = store.getCertificateChain("serverRsa");
        assertNotNull(chainOut);
        if (!Arrays.equals(rsaServerChain, chainOut)) {
            fail("RSA get/set chain does not match");
        }

        keyOut = (PrivateKey)store.getKey("serverEcc",
            storePass.toCharArray());
        if (!serverKeyEcc.equals(keyOut)) {
            fail("ECC get/set Key does not match each other");
        }
        chainOut = store.getCertificateChain("serverEcc");
        assertNotNull(chainOut);
        if (!Arrays.equals(eccServerChain, chainOut)) {
            fail("ECC get/set chain does not match");
        }

        /* Storing invalid chain should fail */
        /* SUN JKS seems to allow loading invalid cert chains, but we don't */
        if (!storeProvider.equals("SUN")) {
            try {
                store.setKeyEntry("serverRsa", serverKeyRsa,
                    storePass.toCharArray(), invalidChain);
                fail("setKeyEntry() with invalid chain should fail");
            } catch (KeyStoreException e) {
                /* expected */
            }
            /* Verify size of KeyStore has not changed on failure storing entry */
            assertEquals(2, store.size());
        }
    }

    @Test
    public void testStoreSingleCertOnly()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        Certificate certOut = null;
        String alias = null;
        
        /* Storing single RSA cert should succeed */
        alias = "serverRsa";
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setCertificateEntry(alias, serverCertRsa);
        assertEquals(1, store.size());
        assertTrue(store.isCertificateEntry(alias));

        certOut = store.getCertificate(alias);
        assertNotNull(certOut);
        assertEquals(serverCertRsa, certOut);
        if (storeProvider.equals("SUN")) {
            /* SUN JKS seems to lowercase all aliases, but we don't */
            assertEquals(alias.toLowerCase(),
                store.getCertificateAlias(serverCertRsa));
        }
        else {
            assertEquals(alias, store.getCertificateAlias(serverCertRsa));
        }

        /* Storing single ECC cert should succeed */
        alias = "serverEcc";
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setCertificateEntry(alias, serverCertEcc);
        assertEquals(1, store.size());
        assertTrue(store.isCertificateEntry(alias));

        certOut = store.getCertificate(alias);
        assertNotNull(certOut);
        assertEquals(serverCertEcc, certOut);
        if (storeProvider.equals("SUN")) {
            /* SUN JKS seems to lowercase all aliases, but we don't */
            assertEquals(alias.toLowerCase(),
                store.getCertificateAlias(serverCertEcc));
        }
        else {
            assertEquals(alias, store.getCertificateAlias(serverCertEcc));
        }

        /* Storing null cert should still pass (matching SUN behavior) */
        alias = "serverRsa";
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setCertificateEntry(alias, null);
        assertEquals(1, store.size());
        assertTrue(store.isCertificateEntry(alias));

        certOut = store.getCertificate(alias);
        assertNull(certOut);
        assertNull(store.getCertificateAlias(serverCertRsa));
    }

    @Test
    public void testStoreSecretKeysOnly()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        KeyGenerator kg = null;
        SecretKey hmacKey = null;
        Key keyOut = null;
        SecretKey aesKey = null;

        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        /* Generate HMAC key (256-bit) */
        kg = KeyGenerator.getInstance("HmacSHA256");
        assertNotNull(kg);
        kg.init(256, rand);
        hmacKey = kg.generateKey();
        assertNotNull(hmacKey);
        assertTrue(hmacKey.getEncoded().length > 0);

        /* Generate AES key (256-bit) */
        kg = KeyGenerator.getInstance("AES");
        assertNotNull(kg);
        kg.init(256, rand);
        aesKey = kg.generateKey();
        assertNotNull(aesKey);
        assertTrue(aesKey.getEncoded().length > 0);

        /* Store HMAC and AES key */
        store.setKeyEntry("hmacKey", hmacKey, storePass.toCharArray(), null);
        assertEquals(1, store.size());
        assertTrue(store.isKeyEntry("hmacKey"));

        store.setKeyEntry("aesKey", aesKey, storePass.toCharArray(), null);
        assertEquals(2, store.size());
        assertTrue(store.isKeyEntry("aesKey"));

        /* Read keys back out, compare against original */
        keyOut = store.getKey("hmacKey", storePass.toCharArray());
        assertNotNull(keyOut);
        assertTrue(keyOut instanceof SecretKey);
        assertEquals(hmacKey, keyOut);
        assertTrue(Arrays.equals(hmacKey.getEncoded(), keyOut.getEncoded()));

        keyOut = store.getKey("aesKey", storePass.toCharArray());
        assertNotNull(keyOut);
        assertTrue(keyOut instanceof SecretKey);
        assertEquals(aesKey, keyOut);
        assertTrue(Arrays.equals(aesKey.getEncoded(), keyOut.getEncoded()));
    }

    @Test
    public void testStoreMultipleCertsKeysChains()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate certOut = null;
        Certificate[] chainOut = null;
        KeyGenerator kg = null;
        SecretKey aesKey = null;
        SecretKey sKeyOut = null;
        
        /* Storing multiple certs/keys/chains should succeed */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        /** ----- INSERT entries ----- */

        /* INSERT [1]: RSA cert only */
        store.setCertificateEntry("serverRsa", serverCertRsa);
        assertEquals(1, store.size());
        assertTrue(store.isCertificateEntry("serverRsa"));

        /* INSERT [2]: ECC cert only */
        store.setCertificateEntry("serverEcc", serverCertEcc);
        assertEquals(2, store.size());
        assertTrue(store.isCertificateEntry("serverEcc"));

        /* INSERT [3]: RSA priv key + cert */
        store.setKeyEntry("rsaCert", serverKeyRsa,
            storePass.toCharArray(),
            new Certificate[] { serverCertRsa });
        assertEquals(3, store.size());
        assertTrue(store.isKeyEntry("rsaCert"));

        /* INSERT [4]: ECC priv key + cert */
        store.setKeyEntry("eccCert", serverKeyEcc,
            storePass.toCharArray(),
            new Certificate[] { serverCertEcc });
        assertEquals(4, store.size());
        assertTrue(store.isKeyEntry("eccCert"));

        /* INSERT [5]: RSA priv key + chain */
        store.setKeyEntry("rsaChain", serverKeyRsa,
            storePass.toCharArray(), rsaServerChain);
        assertEquals(5, store.size());
        assertTrue(store.isKeyEntry("rsaChain"));

        /* INSERT [6]: ECC priv key + chain */
        store.setKeyEntry("eccChain", serverKeyEcc,
            storePass.toCharArray(), eccServerChain);
        assertEquals(6, store.size());
        assertTrue(store.isKeyEntry("eccChain"));

        /* INSERT [7]: AES SecretKey */
        kg = KeyGenerator.getInstance("AES");
        assertNotNull(kg);
        kg.init(256, rand);
        aesKey = kg.generateKey();
        assertNotNull(aesKey);
        assertTrue(aesKey.getEncoded().length > 0);
        store.setKeyEntry("aesKey", aesKey, storePass.toCharArray(), null);

        /** ----- GET/VERIFY entries ----- */

        /* GET/VERIFY [1] */
        certOut = store.getCertificate("serverRsa");
        assertNotNull(certOut);
        assertEquals(serverCertRsa, certOut);

        /* GET/VERIFY [2] */
        certOut = store.getCertificate("serverEcc");
        assertNotNull(certOut);
        assertEquals(serverCertEcc, certOut);

        /* GET/VERIFY [3] */
        keyOut = (PrivateKey)store.getKey("rsaCert", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyRsa, keyOut);
        certOut = store.getCertificate("rsaCert");
        assertNotNull(certOut);
        assertEquals(serverCertRsa, certOut);

        /* GET/VERIFY [4] */
        keyOut = (PrivateKey)store.getKey("eccCert", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyEcc, keyOut);
        certOut = store.getCertificate("eccCert");
        assertNotNull(certOut);
        assertEquals(serverCertEcc, certOut);

        /* GET/VERIFY [5] */
        keyOut = (PrivateKey)store.getKey("rsaChain", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyRsa, keyOut);
        chainOut = store.getCertificateChain("rsaChain");
        assertNotNull(chainOut);
        assertTrue(Arrays.equals(rsaServerChain, chainOut));

        /* GET/VERIFY [6] */
        keyOut = (PrivateKey)store.getKey("eccChain", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyEcc, keyOut);
        chainOut = store.getCertificateChain("eccChain");
        assertNotNull(chainOut);
        assertTrue(Arrays.equals(eccServerChain, chainOut));

        /* GET/VERIFY [7] */
        sKeyOut = (SecretKey)store.getKey("aesKey", storePass.toCharArray());
        assertNotNull(sKeyOut);
        assertEquals(aesKey, sKeyOut);
        assertTrue(Arrays.equals(aesKey.getEncoded(), sKeyOut.getEncoded()));
    }

    @Test
    public void testDeleteEntry()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate certOut = null;
        Certificate[] chainOut = null;
        KeyGenerator kg = null;
        SecretKey aesKey = null;
        SecretKey sKeyOut = null;

        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        /** ----- INSERT entries ----- */

        /* INSERT [1]: RSA cert only */
        store.setCertificateEntry("serverRsa", serverCertRsa);
        assertEquals(1, store.size());
        assertTrue(store.isCertificateEntry("serverRsa"));
        assertTrue(store.containsAlias("serverRsa"));

        /* INSERT [2]: ECC cert only */
        store.setCertificateEntry("serverEcc", serverCertEcc);
        assertEquals(2, store.size());
        assertTrue(store.isCertificateEntry("serverEcc"));
        assertTrue(store.containsAlias("serverEcc"));

        /* INSERT [3]: RSA priv key + cert */
        store.setKeyEntry("rsaCert", serverKeyRsa,
            storePass.toCharArray(),
            new Certificate[] { serverCertRsa });
        assertEquals(3, store.size());
        assertTrue(store.isKeyEntry("rsaCert"));
        assertTrue(store.containsAlias("rsaCert"));

        /* INSERT [4]: ECC priv key + cert */
        store.setKeyEntry("eccCert", serverKeyEcc,
            storePass.toCharArray(),
            new Certificate[] { serverCertEcc });
        assertEquals(4, store.size());
        assertTrue(store.isKeyEntry("eccCert"));
        assertTrue(store.containsAlias("eccCert"));

        /* INSERT [5]: RSA priv key + chain */
        store.setKeyEntry("rsaChain", serverKeyRsa,
            storePass.toCharArray(), rsaServerChain);
        assertEquals(5, store.size());
        assertTrue(store.isKeyEntry("rsaChain"));
        assertTrue(store.containsAlias("rsaChain"));

        /* INSERT [6]: ECC priv key + chain */
        store.setKeyEntry("eccChain", serverKeyEcc,
            storePass.toCharArray(), eccServerChain);
        assertEquals(6, store.size());
        assertTrue(store.isKeyEntry("eccChain"));
        assertTrue(store.containsAlias("eccChain"));

        /* INSERT [7]: AES SecretKey */
        kg = KeyGenerator.getInstance("AES");
        assertNotNull(kg);
        kg.init(256, rand);
        aesKey = kg.generateKey();
        assertNotNull(aesKey);
        assertTrue(aesKey.getEncoded().length > 0);
        store.setKeyEntry("aesKey", aesKey, storePass.toCharArray(), null);
        assertEquals(7, store.size());
        assertTrue(store.isKeyEntry("aesKey"));
        assertTrue(store.containsAlias("aesKey"));

        /** ----- REMOVE entries ----- */

        store.deleteEntry("serverRsa");
        assertFalse(store.containsAlias("serverRsa"));
        assertEquals(6, store.size());

        store.deleteEntry("serverEcc");
        assertFalse(store.containsAlias("serverEcc"));
        assertEquals(5, store.size());

        store.deleteEntry("rsaCert");
        assertFalse(store.containsAlias("rsaCert"));
        assertEquals(4, store.size());

        store.deleteEntry("eccCert");
        assertFalse(store.containsAlias("eccCert"));
        assertEquals(3, store.size());

        store.deleteEntry("rsaChain");
        assertFalse(store.containsAlias("rsaChain"));
        assertEquals(2, store.size());

        store.deleteEntry("eccChain");
        assertFalse(store.containsAlias("eccChain"));
        assertEquals(1, store.size());

        store.deleteEntry("aesKey");
        assertFalse(store.containsAlias("aesKey"));
        assertEquals(0, store.size());
    }

    @Test
    public void testAliases()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        Enumeration<String> aliases = null;
        List<String> aliasList = null;
        
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("serverRsa", serverKeyRsa,
            storePass.toCharArray(), rsaServerChain);
        store.setKeyEntry("serverEcc", serverKeyEcc,
            storePass.toCharArray(), eccServerChain);

        aliases = store.aliases();
        aliasList = Collections.list(aliases);
        assertEquals(2, aliasList.size());
        if (storeProvider.equals("SUN")) {
            /* SUN JKS lower cases all aliases, but we don't */
            assertTrue(aliasList.contains("serverrsa"));
            assertTrue(aliasList.contains("serverecc"));
        }
        else {
            assertTrue(aliasList.contains("serverRsa"));
            assertTrue(aliasList.contains("serverEcc"));
        }
    }

    @Test
    public void testGetType()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;

        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        assertEquals("WKS", store.getType());
    }

    @Test
    public void testStoreAndLoadEmptyKeyStore()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        ByteArrayOutputStream bos = null;
        byte[] storeOut = null;

        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        /* Store KeyStore with no entries */
        bos = new ByteArrayOutputStream();
        store.store(bos, storePass.toCharArray());
        storeOut = bos.toByteArray();
        bos.close();

        assertNotNull(storeOut);
        assertTrue(storeOut.length > 0);

        /* Load back in empty stored KeyStore */

        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new ByteArrayInputStream(storeOut), storePass.toCharArray());
    }

    @Test
    public void testLoadFailsWithBadTampers()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        ByteArrayOutputStream bos = null;
        byte tmp = 0;
        byte[] storeOut = null;

        /* Create and load single entry so not empty, RSA cert only */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setCertificateEntry("serverRsa", serverCertRsa);

        /* Store to byte array */
        bos = new ByteArrayOutputStream();
        store.store(bos, storePass.toCharArray());
        storeOut = bos.toByteArray();
        bos.close();

        assertNotNull(storeOut);
        assertTrue(storeOut.length > 0);

        /* Bad magic number should fail to load */
        tmp = storeOut[0];
        storeOut[0] = 9;
        store = KeyStore.getInstance(storeType, storeProvider);
        try {
            store.load(new ByteArrayInputStream(storeOut),
                       storePass.toCharArray());
        } catch (IOException e) {
            /* expected */
        }
        storeOut[0] = tmp;

        /* Bad KeyStore version should fail to load */
        tmp = storeOut[1];
        storeOut[1] = 9;
        store = KeyStore.getInstance(storeType, storeProvider);
        try {
            store.load(new ByteArrayInputStream(storeOut),
                       storePass.toCharArray());
        } catch (IOException e) {
            /* expected */
        }
        storeOut[1] = tmp;

        /* Sanity check that store loads successfully with no changes */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new ByteArrayInputStream(storeOut), storePass.toCharArray());
    }

    @Test
    public void testStoreAndLoadIncludingTamper()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate certOut = null;
        Certificate[] chainOut = null;
        KeyGenerator kg = null;
        SecretKey aesKey = null;
        SecretKey sKeyOut = null;

        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        /** ----- INSERT entries ----- */

        /* INSERT [1]: RSA cert only */
        store.setCertificateEntry("serverRsa", serverCertRsa);
        assertEquals(1, store.size());
        assertTrue(store.isCertificateEntry("serverRsa"));

        /* INSERT [2]: ECC cert only */
        store.setCertificateEntry("serverEcc", serverCertEcc);
        assertEquals(2, store.size());
        assertTrue(store.isCertificateEntry("serverEcc"));

        /* INSERT [3]: RSA priv key + cert */
        store.setKeyEntry("rsaCert", serverKeyRsa,
            storePass.toCharArray(),
            new Certificate[] { serverCertRsa });
        assertEquals(3, store.size());
        assertTrue(store.isKeyEntry("rsaCert"));

        /* INSERT [4]: ECC priv key + cert */
        store.setKeyEntry("eccCert", serverKeyEcc,
            storePass.toCharArray(),
            new Certificate[] { serverCertEcc });
        assertEquals(4, store.size());
        assertTrue(store.isKeyEntry("eccCert"));

        /* INSERT [5]: RSA priv key + chain */
        store.setKeyEntry("rsaChain", serverKeyRsa,
            storePass.toCharArray(), rsaServerChain);
        assertEquals(5, store.size());
        assertTrue(store.isKeyEntry("rsaChain"));

        /* INSERT [6]: ECC priv key + chain */
        store.setKeyEntry("eccChain", serverKeyEcc,
            storePass.toCharArray(), eccServerChain);
        assertEquals(6, store.size());
        assertTrue(store.isKeyEntry("eccChain"));

        /* INSERT [7]: AES SecretKey */
        kg = KeyGenerator.getInstance("AES");
        assertNotNull(kg);
        kg.init(256, rand);
        aesKey = kg.generateKey();
        assertNotNull(aesKey);
        assertTrue(aesKey.getEncoded().length > 0);
        store.setKeyEntry("aesKey", aesKey, storePass.toCharArray(), null);
        assertEquals(7, store.size());
        assertTrue(store.isKeyEntry("aesKey"));

        /** ----- WRITE OUT to byte array ----- */

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        store.store(bos, storePass.toCharArray());
        byte[] storeOut = bos.toByteArray();
        bos.close();

        assertNotNull(storeOut);
        assertTrue(storeOut.length > 0);

        /** ----- READ IN from tampered byte array, should fail ----- */

        /* Offset 18 gets us past the header and into the alias string */
        byte storeOut18 = storeOut[18];
        storeOut[18] = 'x';
        store = KeyStore.getInstance(storeType, storeProvider);
        try {
            store.load(new ByteArrayInputStream(storeOut),
                       storePass.toCharArray());
        } catch (IOException e) {
            /* expected */
        }

        /** ----- READ IN from byte array ----- */

        storeOut[18] = storeOut18;
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new ByteArrayInputStream(storeOut), storePass.toCharArray());

        /** ----- GET/VERIFY entries ----- */

        /* GET/VERIFY [1] */
        certOut = store.getCertificate("serverRsa");
        assertNotNull(certOut);
        assertEquals(serverCertRsa, certOut);

        /* GET/VERIFY [2] */
        certOut = store.getCertificate("serverEcc");
        assertNotNull(certOut);
        assertEquals(serverCertEcc, certOut);

        /* GET/VERIFY [3] */
        keyOut = (PrivateKey)store.getKey("rsaCert", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyRsa, keyOut);
        certOut = store.getCertificate("rsaCert");
        assertNotNull(certOut);
        assertEquals(serverCertRsa, certOut);

        /* GET/VERIFY [4] */
        keyOut = (PrivateKey)store.getKey("eccCert", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyEcc, keyOut);
        certOut = store.getCertificate("eccCert");
        assertNotNull(certOut);
        assertEquals(serverCertEcc, certOut);

        /* GET/VERIFY [5] */
        keyOut = (PrivateKey)store.getKey("rsaChain", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyRsa, keyOut);
        chainOut = store.getCertificateChain("rsaChain");
        assertNotNull(chainOut);
        assertTrue(Arrays.equals(rsaServerChain, chainOut));

        /* GET/VERIFY [6] */
        keyOut = (PrivateKey)store.getKey("eccChain", storePass.toCharArray());
        assertNotNull(keyOut);
        assertEquals(serverKeyEcc, keyOut);
        chainOut = store.getCertificateChain("eccChain");
        assertNotNull(chainOut);
        assertTrue(Arrays.equals(eccServerChain, chainOut));

        /* GET/VERIFY [7] */
        sKeyOut = (SecretKey)store.getKey("aesKey", storePass.toCharArray());
        assertNotNull(sKeyOut);
        assertEquals(aesKey, sKeyOut);
        assertTrue(Arrays.equals(aesKey.getEncoded(), sKeyOut.getEncoded()));
    }

    @Test
    public void testStorePreProtectedKeyIsUnsupported()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        byte[] tmpArr = new byte[] { 0x00, 0x01, 0x02 };

        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        try {
            store.setKeyEntry("myAlias", tmpArr, null);
        } catch (UnsupportedOperationException e) {
            /* expected, no supported */
        }
    }

    @Test
    public void testLoadWKSFromFile()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;

        /* client.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(clientWKS),
                   storePass.toCharArray());
        assertEquals(2, store.size());

        /* client-rsa-1024.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(clientRsa1024WKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());

        /* client-rsa.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(clientRsaWKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());

        /* client-ecc.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(clientEccWKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());

        /* server.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(serverWKS),
                   storePass.toCharArray());
        assertEquals(2, store.size());

        /* server-rsa-1024.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(serverRsa1024WKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());

        /* server-rsa.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(serverRsaWKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());

        /* server-ecc.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(serverEccWKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());

        /* cacerts.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(caCertsWKS),
                   storePass.toCharArray());
        assertEquals(6, store.size());

        /* ca-client.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(caClientWKS),
                   storePass.toCharArray());
        assertEquals(2, store.size());

        /* ca-server.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(caServerWKS),
                   storePass.toCharArray());
        assertEquals(2, store.size());

        /* ca-server-rsa-2048.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(caServerRsa2048WKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());

        /* ca-server-ecc-256.wks */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(caServerEcc256WKS),
                   storePass.toCharArray());
        assertEquals(1, store.size());
    }

    @Test
    public void testLoadSystemCAKeyStore()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException, InterruptedException {

        int exitVal = -1;
        String userDir = System.getProperty("user.dir");
        String scriptDir = "/examples/certs/systemcerts/";
        String scriptName = "system-cacerts-to-wks.sh";
        String cacertsWKS = "cacerts.wks";
        String jssecacertsWKS = "jssecacerts.wks";
        String providerJARPath = "/lib/wolfcrypt-jni.jar";
        String cmd = "cd " + userDir + scriptDir + " && /bin/sh " + scriptName +
            " " + userDir + providerJARPath;
        KeyStore store = null;
        String cacertsPass = "changeitchangeit";
        File cacertFile = null;

        /* Skip running this test on Android, since directory structure
         * and cacert gen script won't be there. */
        Assume.assumeTrue(!isAndroid());

        /* Skip running this test on Windows until portabiliy of running
         * above script is figured out. */
        Assume.assumeTrue(!isWindows());

        /* Skip of wolfcrypt-jni.jar does not exist. This can happen if we
         * are running via 'mvn test' and the jar has not been created yet */
        File jarFile = new File(userDir + providerJARPath);
        Assume.assumeTrue(jarFile.exists());

        assertNotNull(userDir);

        /* Call system-cacerts-to-wks.sh script, converts system cacerts
         * KeyStore from JKS to WKS type placing output cacerts.wks at
         * /examples/certs/systemcerts/cacerts.wks */
        Process ps = Runtime.getRuntime().exec
            (new String[] {"sh", "-c", cmd});
        ps.waitFor();

        exitVal = ps.exitValue();
        assertEquals(0, exitVal);

        /* Try to load newly-generated cacerts.wks into WolfSSLKeyStore */
        cacertFile = new File(userDir + scriptDir + cacertsWKS);
        if (cacertFile.exists() && !cacertFile.isDirectory()) {
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(new FileInputStream(userDir + scriptDir + cacertsWKS),
                       cacertsPass.toCharArray());
        }

        /* Try to load newly-generated jssecacerts.wks if exists */
        cacertFile = new File(userDir + scriptDir + jssecacertsWKS);
        if (cacertFile.exists() && !cacertFile.isDirectory()) {
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(new FileInputStream(
                       userDir + scriptDir + jssecacertsWKS),
                       cacertsPass.toCharArray());
        }
    }

    @Test
    public void testLoadNullArgs()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException, InterruptedException {

        KeyStore store = null;

        /* load(null, null) should work */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, null);
    }

    @Test
    public void testLoadWKSWithoutPassword()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;

        /* Test loading client.wks not specifying password. This should
         * succeed and just skip integrity check. */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new FileInputStream(clientWKS), null);
        assertEquals(2, store.size());
    }

    @Test
    public void testStoreToByteArrayThreaded()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException, InterruptedException {

        int numThreads = 15;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        /* Insert/store/load/verify from numThreads parallel threads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int ret = 0;
                    KeyStore store = null;
                    PrivateKey keyOut = null;
                    Certificate certOut = null;
                    Certificate[] chainOut = null;
                    KeyGenerator kg = null;
                    SecretKey aesKey = null;
                    SecretKey sKeyOut = null;

                    try {

                        store = KeyStore.getInstance(storeType, storeProvider);
                        store.load(null, storePass.toCharArray());

                        /** ----- INSERT entries ----- */

                        /* INSERT [1]: RSA cert only */
                        store.setCertificateEntry("serverRsa", serverCertRsa);
                        assertEquals(1, store.size());
                        assertTrue(store.isCertificateEntry("serverRsa"));

                        /* INSERT [2]: ECC cert only */
                        store.setCertificateEntry("serverEcc", serverCertEcc);
                        assertEquals(2, store.size());
                        assertTrue(store.isCertificateEntry("serverEcc"));

                        /* INSERT [3]: RSA priv key + cert */
                        store.setKeyEntry("rsaCert", serverKeyRsa,
                            storePass.toCharArray(),
                            new Certificate[] { serverCertRsa });
                        assertEquals(3, store.size());
                        assertTrue(store.isKeyEntry("rsaCert"));

                        /* INSERT [4]: ECC priv key + cert */
                        store.setKeyEntry("eccCert", serverKeyEcc,
                            storePass.toCharArray(),
                            new Certificate[] { serverCertEcc });
                        assertEquals(4, store.size());
                        assertTrue(store.isKeyEntry("eccCert"));

                        /* INSERT [5]: RSA priv key + chain */
                        store.setKeyEntry("rsaChain", serverKeyRsa,
                            storePass.toCharArray(), rsaServerChain);
                        assertEquals(5, store.size());
                        assertTrue(store.isKeyEntry("rsaChain"));

                        /* INSERT [6]: ECC priv key + chain */
                        store.setKeyEntry("eccChain", serverKeyEcc,
                            storePass.toCharArray(), eccServerChain);
                        assertEquals(6, store.size());
                        assertTrue(store.isKeyEntry("eccChain"));

                        /* INSERT [7]: AES SecretKey */
                        kg = KeyGenerator.getInstance("AES");
                        assertNotNull(kg);
                        kg.init(256, rand);
                        aesKey = kg.generateKey();
                        assertNotNull(aesKey);
                        assertTrue(aesKey.getEncoded().length > 0);
                        store.setKeyEntry("aesKey", aesKey,
                            storePass.toCharArray(), null);
                        assertEquals(7, store.size());
                        assertTrue(store.isKeyEntry("aesKey"));

                        /** ----- WRITE OUT to byte array ----- */

                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        store.store(bos, storePass.toCharArray());
                        byte[] storeOut = bos.toByteArray();
                        bos.close();

                        assertNotNull(storeOut);
                        assertTrue(storeOut.length > 0);

                        /** ----- READ IN from byte array ----- */

                        store = KeyStore.getInstance(storeType, storeProvider);
                        store.load(new ByteArrayInputStream(storeOut),
                            storePass.toCharArray());

                        /** ----- GET/VERIFY entries ----- */

                        /* GET/VERIFY [1] */
                        certOut = store.getCertificate("serverRsa");
                        assertNotNull(certOut);
                        assertEquals(serverCertRsa, certOut);

                        /* GET/VERIFY [2] */
                        certOut = store.getCertificate("serverEcc");
                        assertNotNull(certOut);
                        assertEquals(serverCertEcc, certOut);

                        /* GET/VERIFY [3] */
                        keyOut = (PrivateKey)store.getKey("rsaCert",
                            storePass.toCharArray());
                        assertNotNull(keyOut);
                        assertEquals(serverKeyRsa, keyOut);
                        certOut = store.getCertificate("rsaCert");
                        assertNotNull(certOut);
                        assertEquals(serverCertRsa, certOut);

                        /* GET/VERIFY [4] */
                        keyOut = (PrivateKey)store.getKey("eccCert",
                            storePass.toCharArray());
                        assertNotNull(keyOut);
                        assertEquals(serverKeyEcc, keyOut);
                        certOut = store.getCertificate("eccCert");
                        assertNotNull(certOut);
                        assertEquals(serverCertEcc, certOut);

                        /* GET/VERIFY [5] */
                        keyOut = (PrivateKey)store.getKey("rsaChain",
                            storePass.toCharArray());
                        assertNotNull(keyOut);
                        assertEquals(serverKeyRsa, keyOut);
                        chainOut = store.getCertificateChain("rsaChain");
                        assertNotNull(chainOut);
                        assertTrue(Arrays.equals(rsaServerChain, chainOut));

                        /* GET/VERIFY [6] */
                        keyOut = (PrivateKey)store.getKey("eccChain",
                            storePass.toCharArray());
                        assertNotNull(keyOut);
                        assertEquals(serverKeyEcc, keyOut);
                        chainOut = store.getCertificateChain("eccChain");
                        assertNotNull(chainOut);
                        assertTrue(Arrays.equals(eccServerChain, chainOut));

                        /* GET/VERIFY [7] */
                        sKeyOut = (SecretKey)store.getKey("aesKey",
                            storePass.toCharArray());
                        assertNotNull(sKeyOut);
                        assertEquals(aesKey, sKeyOut);
                        assertTrue(Arrays.equals(aesKey.getEncoded(),
                            sKeyOut.getEncoded()));


                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(1);

                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in KeyStore threaded test");
            }
        }
    }
}

