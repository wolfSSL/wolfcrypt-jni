/* wolfSSLKeyStoreTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
import java.util.Map;
import java.lang.reflect.Field;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Base64;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfSSLKeyStore;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class WolfSSLKeyStoreTest {

    private final String storeType = "WKS";
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
     *   rsapss/server-rsapss-priv.der, matches to rsapss/server-rsapss.der
     */
    protected static String serverPkcs8Der   = null;
    protected static String eccPkcs8Der      = null;
    protected static String rsaPssPkcs8Der   = null;

    /* RSA-PSS certificate file */
    protected static String serverRsaPssDer  = null;

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
    /* server-rsapss-priv.der */
    private static PrivateKey serverKeyRsaPss = null;
    private static Certificate serverCertRsa = null;  /* server-cert.der */
    private static Certificate serverCertEcc = null;  /* server-ecc.der */
    /* server-rsapss.der */
    private static Certificate serverCertRsaPss = null;
    private static Certificate clientCertRsa = null;  /* client-cert.der */
    private static Certificate clientCertEcc = null;  /* client-ecc-cert.der */
    private static Certificate[] rsaServerChain = null; /* RSA chain */
    private static Certificate[] eccServerChain = null; /* ECC chain */
    private static Certificate[] invalidChain = null;

    /* ML-DSA (FIPS 204) self-signed test keys/certs from native
     * wolfssl/certs/mldsa/. Loaded only if FeatureDetect.MlDsaEnabled()
     * is true. */
    private static String mldsa44KeyPem = null;
    private static String mldsa65KeyPem = null;
    private static String mldsa87KeyPem = null;
    private static String mldsa44CertPem = null;
    private static String mldsa65CertPem = null;
    private static String mldsa87CertPem = null;
    private static String lmsCertDer = null;
    private static PrivateKey   serverKeyMlDsa44  = null;
    private static PrivateKey   serverKeyMlDsa65  = null;
    private static PrivateKey   serverKeyMlDsa87  = null;
    private static Certificate  serverCertMlDsa44 = null;
    private static Certificate  serverCertMlDsa65 = null;
    private static Certificate  serverCertMlDsa87 = null;

    /* XMSS self-signed root certificate (verify-only), from
     * examples/certs/xmss/. Loaded only if FeatureDetect.XmssEnabled(). */
    private static String xmssRootCertDer = null;

    /* SLH-DSA self-signed root certs/keys from wolfssl/certs/slhdsa/. Loaded
     * only if FeatureDetect.SlhDsaEnabled() is true. */
    private static String slhDsaSha2KeyPem   = null;
    private static String slhDsaSha2CertPem  = null;
    private static String slhDsaShakeKeyPem  = null;
    private static String slhDsaShakeCertPem = null;
    private static PrivateKey  keySlhDsaSha2   = null;
    private static Certificate certSlhDsaSha2  = null;
    private static PrivateKey  keySlhDsaShake  = null;
    private static Certificate certSlhDsaShake = null;

    /* Example .jks KeyStore file paths */
    private static String clientJKS = null;          /* client.jks */

    /* Examnple .p12 KeyStore file paths */
    private static String clientP12 = null;          /* client.p12 */

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
    /* ML-DSA WKS keystore paths (built by BuildMlDsaKeystores helper). */
    private static String serverMlDsa44WKS = null;   /* server-mldsa44.wks */
    private static String serverMlDsa65WKS = null;   /* server-mldsa65.wks */
    private static String serverMlDsa87WKS = null;   /* server-mldsa87.wks */
    private static String caMlDsa44WKS     = null;   /* ca-mldsa44.wks */
    private static String caMlDsa65WKS     = null;   /* ca-mldsa65.wks */
    private static String caMlDsa87WKS     = null;   /* ca-mldsa87.wks */

    /* Class wide SecureRandom for use, only initialize once */
    private SecureRandom rand = new SecureRandom();

    /* Used to store/reset Java Security property for PBKDF2 iteration
     * count. Default 210,000 PBKDF2 iterations makes this test run very
     * slow. We set down to 10,000 for test duration. */
    private static boolean iterationCountPropSet = false;
    private static String iterationCountProp = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

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
     * Load a PKCS#8 PEM file and return as a PrivateKey for the given
     * algorithm. Used for ML-DSA test keys from native wolfssl/certs/mldsa/,
     * which ship as PEM only.
     *
     * @param pemFilePath path to PEM file
     * @param alg algorithm name (e.g. "ML-DSA")
     *
     * @return new PrivateKey
     *
     * @throws Exception on read / decode / KeyFactory error
     */
    private static PrivateKey pemFileToPrivateKey(String pemFilePath,
        String alg) throws Exception {

        File f = new File(pemFilePath);
        if (!f.exists()) {
            throw new IOException("PEM file not found: " + pemFilePath);
        }

        String pem = new String(Files.readAllBytes(f.toPath()),
            StandardCharsets.US_ASCII);
        int begin = pem.indexOf("-----BEGIN");
        int end   = pem.indexOf("-----END");
        if (begin < 0 || end < 0) {
            throw new IllegalArgumentException(
                "PEM headers not found in: " + pemFilePath);
        }

        int contentStart = pem.indexOf('\n', begin) + 1;
        String b64 = pem.substring(contentStart, end).replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(b64);

        KeyFactory kf = KeyFactory.getInstance(alg);

        return kf.generatePrivate(new PKCS8EncodedKeySpec(der));
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
     * Store a verify-only XMSS self-signed certificate as a trusted entry in a
     * WKS KeyStore, serialize and reload the store, and confirm the cert
     * round-trips. wolfJCE can then import the certificate's XMSS public key
     * via the registered KeyFactory.
     */
    @Test
    public void testXmssCertificateRoundTrip() throws Exception {

        Assume.assumeTrue("XMSS not compiled in", FeatureDetect.XmssEnabled());

        Assume.assumeTrue("XMSS test certificate not present",
            new File(xmssRootCertDer).exists());

        Certificate xmssCert = certFileToCertificate(xmssRootCertDer);

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        store.load(null, storePass.toCharArray());
        store.setCertificateEntry("xmss-root", xmssCert);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        store.store(bos, storePass.toCharArray());

        KeyStore reloaded = KeyStore.getInstance("WKS", "wolfJCE");
        reloaded.load(new ByteArrayInputStream(bos.toByteArray()),
            storePass.toCharArray());

        Certificate got = reloaded.getCertificate("xmss-root");
        assertNotNull("XMSS certificate missing after reload", got);
        assertTrue("XMSS entry should be a certificate entry",
            reloaded.isCertificateEntry("xmss-root"));
        assertArrayEquals("XMSS certificate did not round-trip",
            xmssCert.getEncoded(), got.getEncoded());

        /* wolfJCE can import the certificate's XMSS public key. Guarded
         * because the JDK has no XMSS support and may not expose an XMSS
         * certificate public key on all versions. */
        PublicKey certPub = null;
        try {
            certPub = got.getPublicKey();
        } catch (RuntimeException e) {
            certPub = null;
        }
        if (certPub != null && certPub.getEncoded() != null) {
            KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
            PublicKey wolfPub = kf.generatePublic(
                new X509EncodedKeySpec(certPub.getEncoded()));
            assertEquals("XMSS", wolfPub.getAlgorithm());
        }
    }

    /**
     * A crafted WKS stream with an oversized encoded entry length must be
     * rejected with an IOException, not trigger an unbounded allocation.
     * Uses a null password so the HMAC integrity check is skipped.
     */
    @Test
    public void testEngineLoadRejectsOversizedEntry() throws Exception {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(7);                 /* WKS magic number */
        dos.writeInt(1);                 /* WKS store version */
        dos.writeInt(1);                 /* entry count */
        dos.writeInt(2);                 /* entry type: certificate */
        dos.writeUTF("evil");            /* alias */
        dos.writeInt(Integer.MAX_VALUE); /* encoded entry length */
        dos.flush();

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        try {
            store.load(new ByteArrayInputStream(bos.toByteArray()), null);
            fail("oversized encoded entry length should throw IOException");
        } catch (IOException e) {
            /* expected, allocation must be bounded before it happens */
        }
    }

    /**
     * A crafted WKS stream with an HMAC length that is not the expected
     * HMAC-SHA512 size must be rejected with an IOException, not trigger an
     * unbounded allocation. Uses a null password so the HMAC integrity
     * check is skipped.
     */
    @Test
    public void testEngineLoadRejectsInvalidHmacLength() throws Exception {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(7);                 /* WKS magic number */
        dos.writeInt(1);                 /* WKS store version */
        dos.writeInt(0);                 /* entry count */
        dos.writeInt(16);                /* salt length */
        dos.write(new byte[16]);         /* salt */
        dos.writeInt(10000);             /* PBKDF2 iterations */
        dos.writeInt(Integer.MAX_VALUE); /* HMAC length */
        dos.flush();

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        try {
            store.load(new ByteArrayInputStream(bos.toByteArray()), null);
            fail("invalid HMAC length should throw IOException");
        } catch (IOException e) {
            /* expected, allocation must be bounded before it happens */
        }
    }

    /**
     * A WKS load that fails its HMAC integrity check must not expose the
     * parsed entries. A KeyStore already initialized by a prior successful
     * load keeps initialized == true, so getCertificate() stays reachable
     * after a failed second load. Entries from the failed load must not be
     * visible.
     */
    @Test
    public void testEngineLoadFailureDoesNotExposeEntries()
        throws Exception {

        Assume.assumeTrue("test certificate not available",
            serverCertRsa != null);

        char[] pass = storePass.toCharArray();

        /* Build a valid WKS blob, then tamper the trailing HMAC so the
         * integrity check fails while the entries still parse. */
        KeyStore src = KeyStore.getInstance("WKS", "wolfJCE");
        src.load(null, pass);
        src.setCertificateEntry("evil", serverCertRsa);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        src.store(bos, pass);
        byte[] tampered = bos.toByteArray();
        tampered[tampered.length - 1] ^= 0x01;

        /* Initialize the victim with an empty load so it stays usable
         * after the failed load below. */
        KeyStore victim = KeyStore.getInstance("WKS", "wolfJCE");
        victim.load(null, pass);

        try {
            victim.load(new ByteArrayInputStream(tampered), pass);
            fail("tampered WKS should fail the integrity check");
        } catch (IOException e) {
            /* expected */
        }

        assertNull("failed load must not expose an entry",
            victim.getCertificate("evil"));
        assertFalse("failed load must not expose an alias",
            victim.containsAlias("evil"));
    }

    /**
     * A crafted WKS private key entry whose encrypted key length field is
     * oversized must be rejected with an IOException. Uses a null
     * password so the HMAC integrity check is skipped.
     */
    @Test
    public void testEngineLoadRejectsOversizedPrivateKeyField()
        throws Exception {

        /* Build a WKSPrivateKey entry that is valid up to the encrypted key
         * length field, which claims Integer.MAX_VALUE bytes. */
        ByteArrayOutputStream entryBos = new ByteArrayOutputStream();
        DataOutputStream e = new DataOutputStream(entryBos);
        e.writeLong(0L);                 /* creationDate */
        e.writeInt(16);                  /* kdfSalt length */
        e.write(new byte[16]);           /* kdfSalt */
        e.writeInt(10000);               /* kdfIterations */
        e.writeInt(16);                  /* iv length */
        e.write(new byte[16]);           /* iv */
        e.writeInt(Integer.MAX_VALUE);   /* encrypted key length */
        e.flush();
        byte[] entry = entryBos.toByteArray();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(7);                 /* WKS magic number */
        dos.writeInt(1);                 /* WKS store version */
        dos.writeInt(1);                 /* entry count */
        dos.writeInt(1);                 /* entry type: private key */
        dos.writeUTF("evil");            /* alias */
        dos.writeInt(entry.length);      /* encoded entry length */
        dos.write(entry);                /* encoded entry */
        dos.flush();

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        try {
            store.load(new ByteArrayInputStream(bos.toByteArray()), null);
            fail("oversized encrypted key length should throw IOException");
        } catch (IOException ex) {
            /* expected, allocation must be bounded before it happens */
        }
    }

    /**
     * A crafted WKS secret key entry whose encrypted key length field is
     * oversized must be rejected with an IOException. Uses a null
     * password so the HMAC integrity check is skipped.
     */
    @Test
    public void testEngineLoadRejectsOversizedSecretKeyField()
        throws Exception {

        /* Build a WKSSecretKey entry that is valid up to the encrypted key
         * length field, which claims Integer.MAX_VALUE bytes. */
        ByteArrayOutputStream entryBos = new ByteArrayOutputStream();
        DataOutputStream e = new DataOutputStream(entryBos);
        e.writeLong(0L);                 /* creationDate */
        e.writeUTF("AES");               /* key algorithm */
        e.writeInt(16);                  /* kdfSalt length */
        e.write(new byte[16]);           /* kdfSalt */
        e.writeInt(10000);               /* kdfIterations */
        e.writeInt(16);                  /* iv length */
        e.write(new byte[16]);           /* iv */
        e.writeInt(Integer.MAX_VALUE);   /* encrypted key length */
        e.flush();
        byte[] entry = entryBos.toByteArray();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(7);                 /* WKS magic number */
        dos.writeInt(1);                 /* WKS store version */
        dos.writeInt(1);                 /* entry count */
        dos.writeInt(3);                 /* entry type: secret key */
        dos.writeUTF("evil");            /* alias */
        dos.writeInt(entry.length);      /* encoded entry length */
        dos.write(entry);                /* encoded entry */
        dos.flush();

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        try {
            store.load(new ByteArrayInputStream(bos.toByteArray()), null);
            fail("oversized encrypted key length should throw IOException");
        } catch (IOException ex) {
            /* expected, allocation must be bounded before it happens */
        }
    }

    /**
     * A crafted WKS private key entry whose certificate chain contains an
     * oversized cert encoding length must be rejected with an IOException.
     * Uses a null password so the HMAC integrity check is skipped.
     */
    @Test
    public void testEngineLoadRejectsOversizedChainCert()
        throws Exception {

        /* Build a WKSPrivateKey entry that is valid up to the first chain
         * cert encoding length, which claims Integer.MAX_VALUE bytes. */
        ByteArrayOutputStream entryBos = new ByteArrayOutputStream();
        DataOutputStream e = new DataOutputStream(entryBos);
        e.writeLong(0L);                 /* creationDate */
        e.writeInt(16);                  /* kdfSalt length */
        e.write(new byte[16]);           /* kdfSalt */
        e.writeInt(10000);               /* kdfIterations */
        e.writeInt(16);                  /* iv length */
        e.write(new byte[16]);           /* iv */
        e.writeInt(0);                   /* encrypted key length (empty) */
        e.writeInt(1);                   /* chain count */
        e.writeUTF("X.509");             /* chain cert type */
        e.writeInt(Integer.MAX_VALUE);   /* chain cert encoding length */
        e.flush();
        byte[] entry = entryBos.toByteArray();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(7);                 /* WKS magic number */
        dos.writeInt(1);                 /* WKS store version */
        dos.writeInt(1);                 /* entry count */
        dos.writeInt(1);                 /* entry type: private key */
        dos.writeUTF("evil");            /* alias */
        dos.writeInt(entry.length);      /* encoded entry length */
        dos.write(entry);                /* encoded entry */
        dos.flush();

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        try {
            store.load(new ByteArrayInputStream(bos.toByteArray()), null);
            fail("oversized chain cert length should throw IOException");
        } catch (IOException ex) {
            /* expected, allocation must be bounded before it happens */
        }
    }

    /**
     * A crafted WKS certificate entry whose DER encoding length is oversized
     * must be rejected with an IOException. Uses a null password so the
     * HMAC integrity check is skipped.
     */
    @Test
    public void testEngineLoadRejectsOversizedCertificate()
        throws Exception {

        /* Build a WKSCertificate entry that is valid up to the encoding
         * length field, which claims Integer.MAX_VALUE bytes. */
        ByteArrayOutputStream entryBos = new ByteArrayOutputStream();
        DataOutputStream e = new DataOutputStream(entryBos);
        e.writeLong(0L);                 /* creationDate */
        e.writeUTF("X.509");             /* certificate type */
        e.writeInt(Integer.MAX_VALUE);   /* cert encoding length */
        e.flush();
        byte[] entry = entryBos.toByteArray();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(7);                 /* WKS magic number */
        dos.writeInt(1);                 /* WKS store version */
        dos.writeInt(1);                 /* entry count */
        dos.writeInt(2);                 /* entry type: certificate */
        dos.writeUTF("evil");            /* alias */
        dos.writeInt(entry.length);      /* encoded entry length */
        dos.write(entry);                /* encoded entry */
        dos.flush();

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        try {
            store.load(new ByteArrayInputStream(bos.toByteArray()), null);
            fail("oversized cert encoding length should throw IOException");
        } catch (IOException ex) {
            /* expected, allocation must be bounded before it happens */
        }
    }

    /**
     * A crafted WKS entry with a zero-length encoded body must be rejected
     * with an IOException, not an unchecked IllegalArgumentException from the
     * per-entry decoder. engineLoad() declares only checked exceptions, so a
     * malformed entry must fail predictably. Uses a null password so the
     * HMAC integrity check is skipped, matching the zero-credential scenario.
     */
    @Test
    public void testEngineLoadRejectsZeroLengthEntry() throws Exception {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(7);                 /* WKS magic number */
        dos.writeInt(1);                 /* WKS store version */
        dos.writeInt(1);                 /* entry count */
        dos.writeInt(1);                 /* entry type: private key */
        dos.writeUTF("evil");            /* alias */
        dos.writeInt(0);                 /* encoded entry length */
        /* trailing bytes so the entry length is not at end of stream, which
         * is what lets the empty entry reach the per-entry decoder */
        dos.writeInt(16);
        dos.write(new byte[16]);
        dos.flush();

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        try {
            store.load(new ByteArrayInputStream(bos.toByteArray()), null);
            fail("zero-length entry should throw IOException");
        } catch (IOException ex) {
            /* expected, malformed input fails with a checked exception */
        }
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

        /* Create PrivateKey from server RSA-PSS private key DER,
         * may be null if RSASSA-PSS not supported or file not present */
        try {
            serverKeyRsaPss = derFileToPrivateKey(rsaPssPkcs8Der, "RSASSA-PSS");
        } catch (Exception e) {
            serverKeyRsaPss = null;
        }

        /* Create Certificate from server RSA cert */
        serverCertRsa = certFileToCertificate(serverCertDer);
        assertNotNull(serverCertRsa);

        /* Create Certificate from server ECC cert */
        serverCertEcc = certFileToCertificate(serverEccDer);
        assertNotNull(serverCertEcc);

        /* Create Certificate from server RSA-PSS cert,
         * may be null if cert file not present */
        try {
            serverCertRsaPss = certFileToCertificate(serverRsaPssDer);
        } catch (FileNotFoundException e) {
            serverCertRsaPss = null;
        }

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

        /* Load ML-DSA self-signed test certs + keys if ML-DSA compiled in.
         * Native wolfssl/certs/mldsa/ ships PEM only (no DER PKCS#8), use
         * pemFileToPrivateKey(). */
        if (FeatureDetect.MlDsaEnabled()) {
            File mlDsa44KeyFile = new File(mldsa44KeyPem);
            if (mlDsa44KeyFile.exists()) {
                try {
                    serverKeyMlDsa44 =
                        pemFileToPrivateKey(mldsa44KeyPem, "ML-DSA");
                    serverKeyMlDsa65 =
                        pemFileToPrivateKey(mldsa65KeyPem, "ML-DSA");
                    serverKeyMlDsa87 =
                        pemFileToPrivateKey(mldsa87KeyPem, "ML-DSA");
                    serverCertMlDsa44 = certFileToCertificate(mldsa44CertPem);
                    serverCertMlDsa65 = certFileToCertificate(mldsa65CertPem);
                    serverCertMlDsa87 = certFileToCertificate(mldsa87CertPem);
                }
                catch (Exception e) {
                    serverKeyMlDsa44 = null;
                    serverKeyMlDsa65 = null;
                    serverKeyMlDsa87 = null;
                    serverCertMlDsa44 = null;
                    serverCertMlDsa65 = null;
                    serverCertMlDsa87 = null;
                }
            }
        }

        /* Load SLH-DSA self-signed test certs/keys if SLH-DSA compiled in. */
        if (FeatureDetect.SlhDsaEnabled()) {
            if (new File(slhDsaSha2KeyPem).exists()) {
                try {
                    keySlhDsaSha2 =
                        pemFileToPrivateKey(slhDsaSha2KeyPem, "SLH-DSA");
                    certSlhDsaSha2 = certFileToCertificate(slhDsaSha2CertPem);
                }
                catch (Exception e) {
                    keySlhDsaSha2 = null;
                    certSlhDsaSha2 = null;
                }
            }
            if (new File(slhDsaShakeKeyPem).exists()) {
                try {
                    keySlhDsaShake =
                        pemFileToPrivateKey(slhDsaShakeKeyPem, "SLH-DSA");
                    certSlhDsaShake = certFileToCertificate(slhDsaShakeCertPem);
                }
                catch (Exception e) {
                    keySlhDsaShake = null;
                    certSlhDsaShake = null;
                }
            }
        }
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
            certPre = "/data/local/tmp/";
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

        xmssRootCertDer =
            certPre.concat("examples/certs/xmss/xmss_root_cert.der");

        serverPkcs8Der =
            certPre.concat("examples/certs/server-keyPkcs8.der");
        eccPkcs8Der =
            certPre.concat("examples/certs/ecc-keyPkcs8.der");
        rsaPssPkcs8Der =
            certPre.concat("examples/certs/rsapss/server-rsapss-priv.der");
        serverRsaPssDer =
            certPre.concat("examples/certs/rsapss/server-rsapss.der");

        intRsaServerCertDer =
            certPre.concat("examples/certs/intermediate/server-int-cert.pem");
        intRsaInt1CertDer =
            certPre.concat("examples/certs/intermediate/ca-int-cert.pem");
        intRsaInt2CertDer =
            certPre.concat("examples/certs/intermediate/ca-int2-cert.pem");

        intEccServerCertDer =
            certPre.concat(
                "examples/certs/intermediate/server-int-ecc-cert.der");
        intEccInt1CertDer =
            certPre.concat("examples/certs/intermediate/ca-int-ecc-cert.der");
        intEccInt2CertDer =
            certPre.concat("examples/certs/intermediate/ca-int2-ecc-cert.der");

        /* Set paths to example JKS KeyStore files */
        clientJKS =
            certPre.concat("examples/certs/client.jks");

        /* Set paths to example PKCS12 KeyStore files */
        clientP12 =
            certPre.concat("examples/certs/client.p12");

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

        /* ML-DSA test material paths */
        mldsa44KeyPem  =
            certPre.concat("examples/certs/mldsa/mldsa44-key.pem");
        mldsa65KeyPem  =
            certPre.concat("examples/certs/mldsa/mldsa65-key.pem");
        mldsa87KeyPem  =
            certPre.concat("examples/certs/mldsa/mldsa87-key.pem");
        mldsa44CertPem =
            certPre.concat("examples/certs/mldsa/mldsa44-cert.pem");
        mldsa65CertPem =
            certPre.concat("examples/certs/mldsa/mldsa65-cert.pem");
        mldsa87CertPem =
            certPre.concat("examples/certs/mldsa/mldsa87-cert.pem");
        lmsCertDer =
            certPre.concat("examples/certs/lms/bc_lms_native_bc_root.der");
        serverMlDsa44WKS =
            certPre.concat("examples/certs/server-mldsa44.wks");
        serverMlDsa65WKS =
            certPre.concat("examples/certs/server-mldsa65.wks");
        serverMlDsa87WKS =
            certPre.concat("examples/certs/server-mldsa87.wks");
        caMlDsa44WKS =
            certPre.concat("examples/certs/ca-mldsa44.wks");
        caMlDsa65WKS =
            certPre.concat("examples/certs/ca-mldsa65.wks");
        caMlDsa87WKS =
            certPre.concat("examples/certs/ca-mldsa87.wks");

        /* SLH-DSA test material paths */
        slhDsaSha2KeyPem = certPre.concat(
            "examples/certs/slhdsa/root-slhdsa-sha2-128s-priv.pem");
        slhDsaSha2CertPem = certPre.concat(
            "examples/certs/slhdsa/root-slhdsa-sha2-128s.pem");
        slhDsaShakeKeyPem = certPre.concat(
            "examples/certs/slhdsa/root-slhdsa-shake-128s-priv.pem");
        slhDsaShakeCertPem = certPre.concat(
            "examples/certs/slhdsa/root-slhdsa-shake-128s.pem");

        /* Test if file exists. Skip tests gracefully if cert files not
         * available (eg running on Android). */
        File f = new File(serverCertDer);
        Assume.assumeTrue("Test cert files not available: " + serverCertDer,
            f.exists());

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
        KeyGenerator kg = null;
        SecretKey aesKey = null;

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
    public void testLoadWKSasJKSFromFile()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        /* Skip on Android, JKS KeyStore type not available */
        Assume.assumeTrue(!isAndroid());

        WolfCryptProvider prov = null;
        KeyStore store = null;

        /* Use client.wks (clientWKS) to test. Any WKS KeyStore could be used,
         * this was just picked since was first used/tested in test above. */

        /* If Security property "wolfjce.mapJKStoWKS=true" has been set,
         * WolfSSLKeyStore should be able to load a WKS file when using a
         * "JKS" KeyStore type. */
        String origProperty = Security.getProperty("wolfjce.mapJKStoWKS");

        /* The wolfJCE service list needs to be refreshed after changing
         * Security properties that will adjust the services we register */
        Security.setProperty("wolfjce.mapJKStoWKS", "true");
        prov = (WolfCryptProvider)Security.getProvider("wolfJCE");
        prov.refreshServices();

        /* Load WKS as JKS, should work w/o exception */
        store = KeyStore.getInstance("JKS");
        assertNotNull(store);
        assertNotNull(store.getProvider());
        assertTrue(store.getProvider().contains("wolfJCE"));
        store.load(new FileInputStream(clientWKS), storePass.toCharArray());
        assertEquals(2, store.size());

        /* Load JKS as JKS when this is set should fail, since using WKS
         * implementation underneath fake JKS mapping */
        try {
            store.load(new FileInputStream(clientJKS), storePass.toCharArray());
            fail("Loaded JKS as JKS, but shouldn't with fake mapping set");
        } catch (IOException e) {
            /* expected */
        }

        /* Set mapping to false, loading a WKS as JKS should throw exception */
        Security.setProperty("wolfjce.mapJKStoWKS", "false");
        prov = (WolfCryptProvider)Security.getProvider("wolfJCE");
        prov.refreshServices();
        store = KeyStore.getInstance("JKS");
        assertTrue(!store.getProvider().contains("wolfJCE"));
        try {
            store.load(new FileInputStream(clientWKS), storePass.toCharArray());
            fail("Loaded WKS as JKS, but shouldn't have been able to");
        } catch (IOException e) {
            /* expected */
        }

        /* Loading JKS as JKS should work when mapping not set */
        store.load(new FileInputStream(clientJKS), storePass.toCharArray());

        /* Restore Security property */
        if (origProperty == null) {
            Security.setProperty("wolfjce.mapJKStoWKS", "");
        }
        else {
            Security.setProperty("wolfjce.mapJKStoWKS", origProperty);
        }
    }

    @Test
    public void testLoadWKSasPKCS12FromFile()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        WolfCryptProvider prov = null;
        KeyStore store = null;

        /* Use client.wks (clientWKS) to test. Any WKS KeyStore could be used,
         * this was just picked since was first used/tested in test above. */

        /* If Security property "wolfjce.mapPKCS12toWKS=true" has been set,
         * WolfSSLKeyStore should be able to load a WKS file when using a
         * "PKCS12" KeyStore type. */
        String origProperty = Security.getProperty("wolfjce.mapPKCS12toWKS");

        /* The wolfJCE service list needs to be refreshed after changing
         * Security properties that will adjust the services we register */
        Security.setProperty("wolfjce.mapPKCS12toWKS", "true");
        prov = (WolfCryptProvider)Security.getProvider("wolfJCE");
        prov.refreshServices();

        /* Load WKS as PKCS12, should work w/o exception */
        store = KeyStore.getInstance("PKCS12");
        assertNotNull(store);
        assertNotNull(store.getProvider());
        assertTrue(store.getProvider().contains("wolfJCE"));
        store.load(new FileInputStream(clientWKS), storePass.toCharArray());
        assertEquals(2, store.size());

        /* Load PKCS12 as PKCS12 when this is set should fail, since using WKS
         * implementation underneath fake PKCS12 mapping */
        try {
            store.load(new FileInputStream(clientP12), storePass.toCharArray());
            fail("Loaded PKCS12 as PKCS12, but shouldn't with fake mapping set");
        } catch (IOException e) {
            /* expected */
        }

        /* Set mapping to false, loading WKS as PKCS12 should throw exception */
        Security.setProperty("wolfjce.mapPKCS12toWKS", "false");
        prov = (WolfCryptProvider)Security.getProvider("wolfJCE");
        prov.refreshServices();
        store = KeyStore.getInstance("PKCS12");
        assertTrue(!store.getProvider().contains("wolfJCE"));
        try {
            store.load(new FileInputStream(clientWKS), storePass.toCharArray());
            fail("Loaded WKS as PKCS12, but shouldn't have been able to");
        } catch (IOException e) {
            /* expected */
        }

        /* Loading PKCS12 as PKCS12 should work when mapping not set */
        store.load(new FileInputStream(clientP12), storePass.toCharArray());

        /* Restore Security property */
        if (origProperty == null) {
            Security.setProperty("wolfjce.mapPKCS12toWKS", "");
        }
        else {
            Security.setProperty("wolfjce.mapPKCS12toWKS", origProperty);
        }
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

        int numThreads = 5;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        /* Insert/store/load/verify from numThreads parallel threads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

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

    /*
     * Test that SecretKey entries can be stored with one iteration count,
     * then retrieved successfully after the iteration count changes.
     * This verifies that SecretKey decryption uses the stored kdfIterations
     * instead of the current global WKS_PBKDF2_ITERATION_COUNT.
     */
    @Test
    public void testSecretKeyWithIterationCountChange()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        KeyGenerator kg = null;
        SecretKey aesKey1 = null;
        SecretKey aesKey2 = null;
        SecretKey hmacKey = null;
        Key keyOut = null;
        ByteArrayOutputStream baos = null;
        ByteArrayInputStream bais = null;
        String origIterationCount =
            Security.getProperty("wolfjce.wks.iterationCount");

        try {
            /* Create KeyStore and load empty */
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());

            /* Set iteration count to 20000 */
            Security.setProperty("wolfjce.wks.iterationCount", "20000");

            /* Generate and store AES key with 20000 iterations */
            kg = KeyGenerator.getInstance("AES");
            assertNotNull(kg);
            kg.init(256, rand);
            aesKey1 = kg.generateKey();
            assertNotNull(aesKey1);
            store.setKeyEntry("aesKey1", aesKey1,
                storePass.toCharArray(), null);

            /* Store KeyStore to byte array */
            baos = new ByteArrayOutputStream();
            store.store(baos, storePass.toCharArray());

            /* Change iteration count to 15000 (LOWER) */
            Security.setProperty("wolfjce.wks.iterationCount", "15000");

            /* Load KeyStore from byte array */
            bais = new ByteArrayInputStream(baos.toByteArray());
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(bais, storePass.toCharArray());

            /* Retrieve and verify key works with lower iteration count */
            keyOut = store.getKey("aesKey1", storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(keyOut instanceof SecretKey);
            assertTrue(Arrays.equals(aesKey1.getEncoded(),
                keyOut.getEncoded()));

            /* Add new key with lower iteration count (15000) */
            aesKey2 = kg.generateKey();
            assertNotNull(aesKey2);
            store.setKeyEntry("aesKey2", aesKey2,
                storePass.toCharArray(), null);

            /* Store KeyStore again */
            baos = new ByteArrayOutputStream();
            store.store(baos, storePass.toCharArray());

            /* Change iteration count to 30000 (higher than both) */
            Security.setProperty("wolfjce.wks.iterationCount", "30000");

            /* Load KeyStore from byte array */
            bais = new ByteArrayInputStream(baos.toByteArray());
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(bais, storePass.toCharArray());

            /* Verify both keys work with higher iteration count set */
            keyOut = store.getKey("aesKey1", storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(keyOut instanceof SecretKey);
            assertTrue(Arrays.equals(aesKey1.getEncoded(),
                keyOut.getEncoded()));

            keyOut = store.getKey("aesKey2", storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(keyOut instanceof SecretKey);
            assertTrue(Arrays.equals(aesKey2.getEncoded(),
                keyOut.getEncoded()));

            /* Add HMAC key with new higher iteration count (30000) */
            kg = KeyGenerator.getInstance("HmacSHA256");
            assertNotNull(kg);
            kg.init(256, rand);
            hmacKey = kg.generateKey();
            assertNotNull(hmacKey);
            store.setKeyEntry("hmacKey", hmacKey,
                storePass.toCharArray(), null);

            /* Verify all three keys work together */
            keyOut = store.getKey("aesKey1", storePass.toCharArray());
            assertTrue(Arrays.equals(aesKey1.getEncoded(),
                keyOut.getEncoded()));
            keyOut = store.getKey("aesKey2", storePass.toCharArray());
            assertTrue(Arrays.equals(aesKey2.getEncoded(),
                keyOut.getEncoded()));
            keyOut = store.getKey("hmacKey", storePass.toCharArray());
            assertTrue(Arrays.equals(hmacKey.getEncoded(),
                keyOut.getEncoded()));

        } finally {
            /* Reset iteration count back to original value */
            if (origIterationCount != null) {
                Security.setProperty("wolfjce.wks.iterationCount",
                    origIterationCount);
            }
            else {
                Security.setProperty("wolfjce.wks.iterationCount", "10000");
            }
        }
    }

    /*
     * Test that PrivateKey entries can be stored with one iteration count,
     * then retrieved successfully after the iteration count changes.
     * This is a regression test to ensure PrivateKey continues to work
     * correctly alongside the SecretKey fix.
     */
    @Test
    public void testPrivateKeyWithIterationCountChange()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        PrivateKey keyOut = null;
        Certificate[] chainOut = null;
        ByteArrayOutputStream baos = null;
        ByteArrayInputStream bais = null;
        String origIterationCount =
            Security.getProperty("wolfjce.wks.iterationCount");

        try {
            /* Create KeyStore and load empty */
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());

            /* Set iteration count to 20000 */
            Security.setProperty("wolfjce.wks.iterationCount", "20000");

            /* Store RSA PrivateKey with cert chain at 20000 iterations */
            store.setKeyEntry("serverRsa", serverKeyRsa,
                storePass.toCharArray(), rsaServerChain);
            assertEquals(1, store.size());
            assertTrue(store.isKeyEntry("serverRsa"));

            /* Store KeyStore to byte array */
            baos = new ByteArrayOutputStream();
            store.store(baos, storePass.toCharArray());

            /* Change iteration count to 15000 (LOWER) */
            Security.setProperty("wolfjce.wks.iterationCount", "15000");

            /* Load KeyStore from byte array */
            bais = new ByteArrayInputStream(baos.toByteArray());
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(bais, storePass.toCharArray());

            /* Retrieve and verify key works with lower iteration count */
            keyOut = (PrivateKey)store.getKey("serverRsa",
                storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(keyOut instanceof PrivateKey);
            assertTrue(Arrays.equals(serverKeyRsa.getEncoded(),
                keyOut.getEncoded()));
            chainOut = store.getCertificateChain("serverRsa");
            assertNotNull(chainOut);
            assertTrue(Arrays.equals(rsaServerChain, chainOut));

            /* Add ECC PrivateKey with lower iteration count (15000) */
            store.setKeyEntry("serverEcc", serverKeyEcc,
                storePass.toCharArray(), eccServerChain);

            /* Store KeyStore again */
            baos = new ByteArrayOutputStream();
            store.store(baos, storePass.toCharArray());

            /* Change iteration count to 30000 (HIGHER than both) */
            Security.setProperty("wolfjce.wks.iterationCount", "30000");

            /* Load KeyStore from byte array */
            bais = new ByteArrayInputStream(baos.toByteArray());
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(bais, storePass.toCharArray());

            /* Verify both keys work with higher iteration count set */
            keyOut = (PrivateKey)store.getKey("serverRsa",
                storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(Arrays.equals(serverKeyRsa.getEncoded(),
                keyOut.getEncoded()));
            chainOut = store.getCertificateChain("serverRsa");
            assertTrue(Arrays.equals(rsaServerChain, chainOut));

            keyOut = (PrivateKey)store.getKey("serverEcc",
                storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(Arrays.equals(serverKeyEcc.getEncoded(),
                keyOut.getEncoded()));
            chainOut = store.getCertificateChain("serverEcc");
            assertTrue(Arrays.equals(eccServerChain, chainOut));

        } finally {
            /* Reset iteration count back to original value */
            if (origIterationCount != null) {
                Security.setProperty("wolfjce.wks.iterationCount",
                    origIterationCount);
            }
            else {
                Security.setProperty("wolfjce.wks.iterationCount", "10000");
            }
        }
    }

    /*
     * Test that a KeyStore can contain PrivateKey, SecretKey, and
     * Certificate entries encrypted with different iteration counts,
     * and all can be retrieved correctly regardless of what the current
     * iteration count property is set to.
     */
    @Test
    public void testMixedIterationCountsInSameKeyStore()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException {

        KeyStore store = null;
        KeyGenerator kg = null;
        SecretKey aesKey1 = null;
        SecretKey aesKey2 = null;
        SecretKey hmacKey = null;
        Key keyOut = null;
        PrivateKey privKeyOut = null;
        Certificate[] chainOut = null;
        Certificate certOut = null;
        ByteArrayOutputStream baos = null;
        ByteArrayInputStream bais = null;
        String origIterationCount =
            Security.getProperty("wolfjce.wks.iterationCount");

        try {
            /* Create KeyStore and load empty */
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());

            /* Set iteration count to 12000 and add first entries */
            Security.setProperty("wolfjce.wks.iterationCount", "12000");

            kg = KeyGenerator.getInstance("AES");
            kg.init(256, rand);
            aesKey1 = kg.generateKey();
            store.setKeyEntry("aesKey12k", aesKey1,
                storePass.toCharArray(), null);
            store.setKeyEntry("rsaKey12k", serverKeyRsa,
                storePass.toCharArray(), rsaServerChain);

            /* Change to 18000 and add more entries */
            Security.setProperty("wolfjce.wks.iterationCount", "18000");

            kg = KeyGenerator.getInstance("HmacSHA256");
            kg.init(256, rand);
            hmacKey = kg.generateKey();
            store.setKeyEntry("hmacKey18k", hmacKey,
                storePass.toCharArray(), null);
            store.setKeyEntry("eccKey18k", serverKeyEcc,
                storePass.toCharArray(), eccServerChain);

            /* Change to 25000 and add more entries */
            Security.setProperty("wolfjce.wks.iterationCount", "25000");

            kg = KeyGenerator.getInstance("AES");
            kg.init(128, rand);
            aesKey2 = kg.generateKey();
            store.setKeyEntry("aesKey25k", aesKey2,
                storePass.toCharArray(), null);
            store.setCertificateEntry("clientCertRsa", clientCertRsa);

            /* Store KeyStore to byte array with 25000 iteration count */
            baos = new ByteArrayOutputStream();
            store.store(baos, storePass.toCharArray());

            /* Change iteration count to something completely different */
            Security.setProperty("wolfjce.wks.iterationCount", "35000");

            /* Load KeyStore */
            bais = new ByteArrayInputStream(baos.toByteArray());
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(bais, storePass.toCharArray());

            /* Verify all entries can be retrieved correctly with 35000 set */
            assertEquals(6, store.size());

            /* Verify 12000-iteration entries */
            keyOut = store.getKey("aesKey12k", storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(Arrays.equals(aesKey1.getEncoded(),
                keyOut.getEncoded()));

            privKeyOut = (PrivateKey)store.getKey("rsaKey12k",
                storePass.toCharArray());
            assertNotNull(privKeyOut);
            assertTrue(Arrays.equals(serverKeyRsa.getEncoded(),
                privKeyOut.getEncoded()));
            chainOut = store.getCertificateChain("rsaKey12k");
            assertTrue(Arrays.equals(rsaServerChain, chainOut));

            /* Verify 18000-iteration entries */
            keyOut = store.getKey("hmacKey18k", storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(Arrays.equals(hmacKey.getEncoded(),
                keyOut.getEncoded()));

            privKeyOut = (PrivateKey)store.getKey("eccKey18k",
                storePass.toCharArray());
            assertNotNull(privKeyOut);
            assertTrue(Arrays.equals(serverKeyEcc.getEncoded(),
                privKeyOut.getEncoded()));
            chainOut = store.getCertificateChain("eccKey18k");
            assertTrue(Arrays.equals(eccServerChain, chainOut));

            /* Verify 25000-iteration entries */
            keyOut = store.getKey("aesKey25k", storePass.toCharArray());
            assertNotNull(keyOut);
            assertTrue(Arrays.equals(aesKey2.getEncoded(),
                keyOut.getEncoded()));

            certOut = store.getCertificate("clientCertRsa");
            assertNotNull(certOut);
            assertEquals(clientCertRsa, certOut);

            /* Change iteration count again and verify still works */
            Security.setProperty("wolfjce.wks.iterationCount", "11000");

            /* Re-store and reload with new iteration count */
            baos = new ByteArrayOutputStream();
            store.store(baos, storePass.toCharArray());
            bais = new ByteArrayInputStream(baos.toByteArray());
            store = KeyStore.getInstance(storeType, storeProvider);
            store.load(bais, storePass.toCharArray());

            /* Verify all original entries still work */
            keyOut = store.getKey("aesKey12k", storePass.toCharArray());
            assertTrue(Arrays.equals(aesKey1.getEncoded(),
                keyOut.getEncoded()));
            keyOut = store.getKey("hmacKey18k", storePass.toCharArray());
            assertTrue(Arrays.equals(hmacKey.getEncoded(),
                keyOut.getEncoded()));
            keyOut = store.getKey("aesKey25k", storePass.toCharArray());
            assertTrue(Arrays.equals(aesKey2.getEncoded(),
                keyOut.getEncoded()));

        } finally {
            /* Reset iteration count back to original value */
            if (origIterationCount != null) {
                Security.setProperty("wolfjce.wks.iterationCount",
                    origIterationCount);
            }
            else {
                Security.setProperty("wolfjce.wks.iterationCount", "10000");
            }
        }
    }

    /**
     * Test concurrent access to engineGetCertificateAlias() while other
     * threads are modifying the same KeyStore instance via setKeyEntry()
     * and setCertificateEntry().
     */
    @Test
    public void testGetCertificateAliasConcurrent()
        throws KeyStoreException, IOException, FileNotFoundException,
               NoSuchProviderException, NoSuchAlgorithmException,
               CertificateException, InvalidKeySpecException,
               UnrecoverableKeyException, InterruptedException {

        int numThreads = 10;
        int iterationsPerThread = 10;
        final KeyStore store = KeyStore.getInstance(storeType,
            storeProvider);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch doneLatch = new CountDownLatch(numThreads);

        /* Initialize KeyStore with some initial entries */
        store.load(null, null);
        store.setKeyEntry("initialKey", serverKeyRsa,
            storePass.toCharArray(), rsaServerChain);
        store.setCertificateEntry("initialCert", serverCertRsa);

        /* Create thread pool */
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        /* Start reader threads that call getCertificateAlias() */
        for (int i = 0; i < numThreads / 2; i++) {
            final int threadId = i;
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        /* Wait for all threads to be ready */
                        startLatch.await();

                        for (int j = 0; j < iterationsPerThread; j++) {
                            /* Look up alias for existing certificate */
                            String alias = store.getCertificateAlias(
                                serverCertRsa);
                            if (alias == null) {
                                /* Certificate should exist, either as
                                 * initialCert or in a key entry chain */
                                results.add(1);
                                return;
                            }

                            /* Verify alias is valid */
                            if (!alias.equals("initialCert") &&
                                !alias.startsWith("writerKey")) {
                                results.add(1);
                                return;
                            }

                            /* Look up alias for certificate that might
                             * be added/removed by writers */
                            alias = store.getCertificateAlias(
                                clientCertRsa);
                            /* Result can be null or valid alias, both OK */
                            if (alias != null &&
                                !alias.startsWith("writerCert")) {
                                results.add(1);
                                return;
                            }
                        }

                        /* Success */
                        results.add(0);

                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(1);

                    } finally {
                        doneLatch.countDown();
                    }
                }
            });
        }

        /* Start writer threads that modify KeyStore */
        for (int i = numThreads / 2; i < numThreads; i++) {
            final int threadId = i;
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        /* Wait for all threads to be ready */
                        startLatch.await();

                        for (int j = 0; j < iterationsPerThread; j++) {
                            String keyAlias = "writerKey" + threadId +
                                "_" + j;
                            String certAlias = "writerCert" + threadId +
                                "_" + j;

                            /* Add key entry */
                            store.setKeyEntry(keyAlias, serverKeyRsa,
                                storePass.toCharArray(), rsaServerChain);

                            /* Add certificate entry */
                            store.setCertificateEntry(certAlias,
                                clientCertRsa);

                            /* Delete some entries periodically */
                            if (j % 10 == 0 && j > 0) {
                                String oldKeyAlias = "writerKey" + threadId +
                                    "_" + (j - 10);
                                String oldCertAlias = "writerCert" +
                                    threadId + "_" + (j - 10);
                                try {
                                    store.deleteEntry(oldKeyAlias);
                                    store.deleteEntry(oldCertAlias);
                                } catch (KeyStoreException e) {
                                    /* Entry might not exist, ignore */
                                }
                            }
                        }

                        /* Success */
                        results.add(0);

                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(1);

                    } finally {
                        doneLatch.countDown();
                    }
                }
            });
        }

        /* Start all threads simultaneously */
        startLatch.countDown();

        /* Wait for all threads to complete */
        doneLatch.await();

        /* Shutdown executor */
        executor.shutdown();

        /* Check results - all threads should have succeeded */
        assertEquals("Expected " + numThreads + " results",
            numThreads, results.size());

        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur != 0) {
                fail("Threading error in concurrent " +
                    "getCertificateAlias test");
            }
        }

        /* Verify KeyStore is still in valid state */
        assertNotNull(store.getCertificate("initialCert"));
        Certificate[] chain = store.getCertificateChain("initialKey");
        assertNotNull(chain);
        assertTrue(chain.length > 0);
    }

    /**
     * Test that engineProbe() correctly identifies WKS format by checking
     * the magic number at the beginning of the stream.
     */
    @Test
    public void testEngineProbeIdentifiesWKS()
        throws KeyStoreException, IOException, NoSuchProviderException,
               NoSuchAlgorithmException, CertificateException {

        /* Create a WKS keystore and store it to a byte array */
        KeyStore store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        store.store(baos, storePass.toCharArray());
        byte[] wksBytes = baos.toByteArray();

        /* Get the WolfSSLKeyStore SPI instance via reflection to call
         * engineProbe directly (since KeyStore doesn't expose it) */
        try {
            WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();

            /* Test that valid WKS data returns true */
            ByteArrayInputStream bais = new ByteArrayInputStream(wksBytes);
            boolean result = wksSpi.engineProbe(bais);
            assertTrue("engineProbe should return true for valid WKS", result);

            /* Verify stream position is preserved after engineProbe().
             * Per KeyStoreSpi spec, probe should leave stream at original
             * position so other implementations can try. */
            assertEquals("Stream should be at beginning after engineProbe()",
                wksBytes[0] & 0xFF, bais.read());

            /* Test that invalid data (non-WKS) returns false */
            byte[] invalidData = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
            };
            bais = new ByteArrayInputStream(invalidData);
            result = wksSpi.engineProbe(bais);
            assertFalse("engineProbe should return false for non-WKS", result);

            /* Test that JKS magic number returns false
             * JKS magic is 0xFEEDFEED */
            byte[] jksMagic = new byte[] {
                (byte)0xFE, (byte)0xED, (byte)0xFE, (byte)0xED
            };
            bais = new ByteArrayInputStream(jksMagic);
            result = wksSpi.engineProbe(bais);
            assertFalse("engineProbe should return false for JKS", result);

            /* Test that empty stream returns false */
            bais = new ByteArrayInputStream(new byte[0]);
            result = wksSpi.engineProbe(bais);
            assertFalse("engineProbe should return false for empty stream",
                result);

            /* Test that stream shorter than 4 bytes returns false */
            bais = new ByteArrayInputStream(new byte[] {0x00, 0x00, 0x00});
            result = wksSpi.engineProbe(bais);
            assertFalse("engineProbe should return false for short stream",
                result);

        } catch (Exception e) {
            fail("engineProbe test threw exception: " + e.getMessage());
        }
    }

    /**
     * Test that engineProbe() throws NullPointerException for null stream.
     */
    @Test(expected = NullPointerException.class)
    public void testEngineProbeNullStream() throws IOException {
        WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
        wksSpi.engineProbe(null);
    }

    /* Get internal KEK cache map via reflection */
    private static Map<?, ?> getKekCacheMap(WolfSSLKeyStore wks)
        throws Exception {

        Field field = WolfSSLKeyStore.class.getDeclaredField("kekCache");
        field.setAccessible(true);
        return (Map<?, ?>)field.get(wks);
    }

    @Test
    public void testKekCacheDisabledByDefault() throws Exception {

        /* Ensure cache is disabled by default */
        String enabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");
        assertTrue("KEK cache should be disabled by default",
            (enabled == null) || !enabled.equalsIgnoreCase("true"));

        /* Use WolfSSLKeyStore directly to inspect KEK cache */
        WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
        wksSpi.engineLoad(null, storePass.toCharArray());
        wksSpi.engineSetKeyEntry("rsaKey", serverKeyRsa,
            storePass.toCharArray(), new Certificate[] { serverCertRsa });

        Key key1 = wksSpi.engineGetKey("rsaKey", storePass.toCharArray());
        Key key2 = wksSpi.engineGetKey("rsaKey", storePass.toCharArray());
        assertNotNull(key1);
        assertNotNull(key2);

        /* Cache stays empty when disabled */
        assertTrue("KEK cache should remain empty when disabled",
            getKekCacheMap(wksSpi).isEmpty());
    }

    @Test
    public void testKekCacheEnabledImprovePerformance() throws Exception {

        /* Save original properties */
        String origEnabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");
        String origTtl = Security.getProperty(
            "wolfjce.keystore.kekCacheTtlSec");

        try {
            /* Enable cache */
            Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");
            Security.setProperty("wolfjce.keystore.kekCacheTtlSec", "300");

            /* Use WolfSSLKeyStore directly to inspect KEK cache */
            WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
            wksSpi.engineLoad(null, storePass.toCharArray());
            wksSpi.engineSetKeyEntry("rsaKey", serverKeyRsa,
                storePass.toCharArray(),
                new Certificate[] { serverCertRsa });

            Map<?, ?> cache = getKekCacheMap(wksSpi);
            assertTrue("KEK cache should start empty", cache.isEmpty());

            /* First getKey() populates cache */
            Key key1 = wksSpi.engineGetKey("rsaKey", storePass.toCharArray());
            assertNotNull(key1);
            assertEquals("KEK cache should hold one entry after getKey",
                1, cache.size());

            /* Cache hit, no new entry added */
            Key key2 = wksSpi.engineGetKey("rsaKey", storePass.toCharArray());
            assertNotNull(key2);
            assertEquals(key1, key2);
            assertEquals("KEK cache should still hold one entry",
                1, cache.size());

        } finally {
            /* Restore original properties */
            if (origEnabled != null) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    origEnabled);
            } else {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "false");
            }
            if (origTtl != null) {
                Security.setProperty("wolfjce.keystore.kekCacheTtlSec",
                    origTtl);
            }
        }
    }

    @Test
    public void testKekCacheWorksForSecretKey() throws Exception {

        String origEnabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");

        try {
            /* Enable cache */
            Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");

            /* Use WolfSSLKeyStore directly to inspect KEK cache */
            WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
            wksSpi.engineLoad(null, storePass.toCharArray());

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            wksSpi.engineSetKeyEntry("aesKey", secretKey,
                storePass.toCharArray(), null);

            Map<?, ?> cache = getKekCacheMap(wksSpi);
            assertTrue("KEK cache should start empty", cache.isEmpty());

            /* First getKey() populates cache */
            Key key1 = wksSpi.engineGetKey("aesKey", storePass.toCharArray());
            assertNotNull(key1);
            assertEquals("KEK cache should hold one entry after getKey",
                1, cache.size());

            /* Cache hit, no new entry added */
            Key key2 = wksSpi.engineGetKey("aesKey", storePass.toCharArray());
            assertNotNull(key2);
            assertEquals(key1, key2);
            assertEquals("KEK cache should still hold one entry",
                1, cache.size());

        } finally {
            if (origEnabled != null) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    origEnabled);
            } else {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "false");
            }
        }
    }

    @Test
    public void testKekCacheInvalidateOnDeleteEntry() throws Exception {

        String origEnabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");

        try {
            /* Enable cache */
            Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");

            /* Use WolfSSLKeyStore directly to inspect KEK cache */
            WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
            wksSpi.engineLoad(null, storePass.toCharArray());
            wksSpi.engineSetKeyEntry("rsaKey1", serverKeyRsa,
                storePass.toCharArray(),
                new Certificate[] { serverCertRsa });
            wksSpi.engineSetKeyEntry("eccKey1", serverKeyEcc,
                storePass.toCharArray(), eccServerChain);

            /* Populate cache, one KEK per entry */
            Key key1 = wksSpi.engineGetKey("rsaKey1", storePass.toCharArray());
            assertNotNull(key1);
            Key key2 = wksSpi.engineGetKey("eccKey1", storePass.toCharArray());
            assertNotNull(key2);

            Map<?, ?> cache = getKekCacheMap(wksSpi);
            assertEquals("KEK cache should hold two entries",
                2, cache.size());

            /* Delete first entry - should clear entire cache */
            wksSpi.engineDeleteEntry("rsaKey1");
            assertFalse(wksSpi.engineContainsAlias("rsaKey1"));
            assertTrue("KEK cache should be empty after deleteEntry",
                cache.isEmpty());

            /* Second key still retrievable, repopulates cache */
            Key key2Again = wksSpi.engineGetKey("eccKey1",
                storePass.toCharArray());
            assertNotNull(key2Again);
            assertEquals("KEK cache should hold one entry after getKey",
                1, cache.size());

        } finally {
            if (origEnabled != null) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    origEnabled);
            } else {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "false");
            }
        }
    }

    @Test
    public void testKekCacheInvalidateOnSetKeyEntryOverwrite()
        throws Exception {

        String origEnabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");

        try {
            /* Enable cache */
            Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");

            /* Use WolfSSLKeyStore directly to inspect KEK cache */
            WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
            wksSpi.engineLoad(null, storePass.toCharArray());
            wksSpi.engineSetKeyEntry("rsaKey1", serverKeyRsa,
                storePass.toCharArray(),
                new Certificate[] { serverCertRsa });
            wksSpi.engineSetKeyEntry("eccKey1", serverKeyEcc,
                storePass.toCharArray(), eccServerChain);

            /* Populate cache, one KEK per entry */
            Key key1 = wksSpi.engineGetKey("rsaKey1", storePass.toCharArray());
            assertNotNull(key1);
            Key key2 = wksSpi.engineGetKey("eccKey1", storePass.toCharArray());
            assertNotNull(key2);

            Map<?, ?> cache = getKekCacheMap(wksSpi);
            assertEquals("KEK cache should hold two entries",
                2, cache.size());

            /* Overwrite first entry - should clear entire cache */
            wksSpi.engineSetKeyEntry("rsaKey1", serverKeyEcc,
                storePass.toCharArray(), eccServerChain);
            assertTrue("KEK cache should be empty after setKeyEntry",
                cache.isEmpty());

            /* Second key still retrievable, repopulates cache */
            Key key2Again = wksSpi.engineGetKey("eccKey1",
                storePass.toCharArray());
            assertNotNull(key2Again);
            assertEquals("KEK cache should hold one entry after getKey",
                1, cache.size());

        } finally {
            if (origEnabled != null) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    origEnabled);
            } else {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "false");
            }
        }
    }

    @Test
    public void testKekCacheInvalidateOnLoad() throws Exception {

        String origEnabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");

        try {
            /* Enable cache */
            Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");

            /* Use WolfSSLKeyStore directly to inspect KEK cache */
            WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
            wksSpi.engineLoad(null, storePass.toCharArray());
            wksSpi.engineSetKeyEntry("rsaKey", serverKeyRsa,
                storePass.toCharArray(),
                new Certificate[] { serverCertRsa });

            /* Populate cache */
            Key key1 = wksSpi.engineGetKey("rsaKey", storePass.toCharArray());
            assertNotNull(key1);

            Map<?, ?> cache = getKekCacheMap(wksSpi);
            assertEquals("KEK cache should hold one entry after getKey",
                1, cache.size());

            /* Save to byte array */
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            wksSpi.engineStore(baos, storePass.toCharArray());
            byte[] storeData = baos.toByteArray();

            /* Load from byte array - should clear cache */
            ByteArrayInputStream bais = new ByteArrayInputStream(storeData);
            wksSpi.engineLoad(bais, storePass.toCharArray());
            assertTrue("KEK cache should be empty after load",
                cache.isEmpty());

            /* Key should still be retrievable, repopulates cache */
            Key key2 = wksSpi.engineGetKey("rsaKey", storePass.toCharArray());
            assertNotNull(key2);
            assertEquals("KEK cache should hold one entry after getKey",
                1, cache.size());

        } finally {
            if (origEnabled != null) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    origEnabled);
            } else {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "false");
            }
        }
    }

    @Test
    public void testKekCacheWrongPasswordReturnsMiss() throws Exception {

        String origEnabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");

        try {
            /* Enable cache */
            Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");

            /* Create and populate KeyStore */
            KeyStore store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());
            store.setKeyEntry("rsaKey", serverKeyRsa, storePass.toCharArray(),
                new Certificate[] { serverCertRsa });

            /* Populate cache with correct password */
            Key key1 = store.getKey("rsaKey", storePass.toCharArray());
            assertNotNull(key1);

            /* Try wrong password - should fail, UnrecoverableKeyException */
            try {
                store.getKey("rsaKey", "wrongpassword".toCharArray());
                fail("Expected UnrecoverableKeyException for wrong password");
            } catch (UnrecoverableKeyException e) {
                /* Expected */
            }

            /* Correct password should still work */
            Key key2 = store.getKey("rsaKey", storePass.toCharArray());
            assertNotNull(key2);
            assertEquals(key1, key2);

        } finally {
            if (origEnabled != null) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    origEnabled);
            } else {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "false");
            }
        }
    }

    @Test
    public void testKekCacheMultipleEntriesSamePassword() throws Exception {

        String origEnabled = Security.getProperty(
            "wolfjce.keystore.kekCacheEnabled");

        try {
            /* Enable cache */
            Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");

            /* Use WolfSSLKeyStore directly to inspect KEK cache */
            WolfSSLKeyStore wksSpi = new WolfSSLKeyStore();
            wksSpi.engineLoad(null, storePass.toCharArray());

            wksSpi.engineSetKeyEntry("rsaKey", serverKeyRsa,
                storePass.toCharArray(),
                new Certificate[] { serverCertRsa });
            wksSpi.engineSetKeyEntry("eccKey", serverKeyEcc,
                storePass.toCharArray(), eccServerChain);

            /* Populate cache, one entry per KeyStore entry salt */
            Key rsaKey = wksSpi.engineGetKey("rsaKey",
                storePass.toCharArray());
            Key eccKey = wksSpi.engineGetKey("eccKey",
                storePass.toCharArray());
            assertNotNull(rsaKey);
            assertNotNull(eccKey);

            Map<?, ?> cache = getKekCacheMap(wksSpi);
            assertEquals("KEK cache should hold one entry per KeyStore " +
                "entry", 2, cache.size());

            /* Cache hits, no new entries */
            Key rsaKey2 = wksSpi.engineGetKey("rsaKey",
                storePass.toCharArray());
            Key eccKey2 = wksSpi.engineGetKey("eccKey",
                storePass.toCharArray());
            assertNotNull(rsaKey2);
            assertNotNull(eccKey2);
            assertEquals(rsaKey, rsaKey2);
            assertEquals(eccKey, eccKey2);
            assertEquals("KEK cache should still hold two entries",
                2, cache.size());

        } finally {
            if (origEnabled != null) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    origEnabled);
            } else {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "false");
            }
        }
    }

    /**
     * Test that RSASSA-PSS private keys can be stored and retrieved from
     * a WKS KeyStore.
     */
    @Test
    public void testRsaPssKeyStoreAndRetrieve()
        throws Exception {

        KeyStore store = null;
        PrivateKey keyOut = null;

        /* Skip if RSA-PSS key/cert not loaded (not available) */
        Assume.assumeTrue("RSA-PSS key not available",
            serverKeyRsaPss != null);
        Assume.assumeTrue("RSA-PSS cert not available",
            serverCertRsaPss != null);

        /* Verify key algorithm is RSASSA-PSS */
        assertEquals("RSASSA-PSS", serverKeyRsaPss.getAlgorithm());

        /* Store PSS key and cert in keystore */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("pssKey", serverKeyRsaPss,
            storePass.toCharArray(),
            new Certificate[] { serverCertRsaPss });
        assertEquals(1, store.size());

        /* Save keystore to byte array */
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        store.store(baos, storePass.toCharArray());
        byte[] storeBytes = baos.toByteArray();
        assertTrue("Stored keystore should have content",
            storeBytes.length > 0);

        /* Reload keystore from byte array */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(new ByteArrayInputStream(storeBytes),
            storePass.toCharArray());
        assertEquals(1, store.size());

        /* Retrieve the PSS private key */
        keyOut = (PrivateKey)store.getKey("pssKey", storePass.toCharArray());
        assertNotNull("Retrieved PSS key should not be null", keyOut);
        assertEquals("Retrieved key algorithm should be RSASSA-PSS",
            "RSASSA-PSS", keyOut.getAlgorithm());

        /* Verify the retrieved key matches the original */
        assertArrayEquals("Retrieved key encoding should match original",
            serverKeyRsaPss.getEncoded(), keyOut.getEncoded());

        /* Verify the certificate can also be retrieved */
        Certificate certOut = store.getCertificate("pssKey");
        assertNotNull("Retrieved PSS cert should not be null", certOut);
    }

    /* Tests for the case where a foreign Provider sits above wolfJCE in the
     * Provider list and returns degraded keys for "RSA"/"EC" lookups.
     * WolfSSLKeyStore.engineGetKey() must not fall through to that Provider
     * when reconstructing PrivateKey objects from PKCS#8.
     * See MockNonCrtProvider for details.
     *
     * WKS store + load + getKey on an RSA private key entry should return
     * an RSAPrivateCrtKey usable as a SHA256withRSA Signature input, even
     * with a degraded RSA KeyFactory installed at higher priority than
     * wolfJCE. */
    @Test
    public void testGetKeyRsaWhenMockRsaProviderIsHighest() throws Exception {

        Assume.assumeNotNull(serverKeyRsa, serverCertRsa);

        char[] pw = storePass.toCharArray();

        KeyStore ks = KeyStore.getInstance(storeType, storeProvider);
        ks.load(null, pw);
        ks.setKeyEntry("rsa-key", serverKeyRsa, pw,
            new Certificate[] { serverCertRsa });

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ks.store(bos, pw);
        bos.close();

        Closeable scope = MockNonCrtProvider.install();
        try {
            KeyStore loaded = KeyStore.getInstance(storeType, storeProvider);
            loaded.load(new ByteArrayInputStream(bos.toByteArray()), pw);

            PrivateKey priv = (PrivateKey) loaded.getKey("rsa-key", pw);
            assertNotNull(priv);
            assertTrue("Loaded RSA key must be RSAPrivateCrtKey: " +
                priv.getClass().getName(),
                priv instanceof RSAPrivateCrtKey);

            /* Sanity check, usable as a wolfJCE Signature input. */
            Signature signer =
                Signature.getInstance("SHA256withRSA", "wolfJCE");
            signer.initSign(priv);
            signer.update("ks-rsa".getBytes());
            assertNotNull(signer.sign());
        } finally {
            scope.close();
        }
    }

    /* WKS store + load + getKey on an EC private key entry should return an
     * ECPrivateKey with non-null params usable as a SHA256withECDSA Signature
     * input, even with a degraded EC KeyFactory installed at higher priority
     * than wolfJCE. */
    @Test
    public void testGetKeyEcWhenMockEcProviderIsHighest() throws Exception {

        Assume.assumeNotNull(serverKeyEcc, serverCertEcc);

        char[] pw = storePass.toCharArray();

        KeyStore ks = KeyStore.getInstance(storeType, storeProvider);
        ks.load(null, pw);
        ks.setKeyEntry("ec-key", serverKeyEcc, pw,
            new Certificate[] { serverCertEcc });

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ks.store(bos, pw);
        bos.close();

        Closeable scope = MockNonCrtProvider.install();
        try {
            KeyStore loaded = KeyStore.getInstance(storeType, storeProvider);
            loaded.load(new ByteArrayInputStream(bos.toByteArray()), pw);

            PrivateKey priv = (PrivateKey) loaded.getKey("ec-key", pw);
            assertNotNull(priv);
            assertTrue("Loaded EC key must be ECPrivateKey: " +
                priv.getClass().getName(),
                priv instanceof ECPrivateKey);
            ECPrivateKey ecPriv = (ECPrivateKey) priv;
            assertNotNull("Loaded EC key params must be non-null",
                ecPriv.getParams());

            Signature signer =
                Signature.getInstance("SHA256withECDSA", "wolfJCE");
            signer.initSign(priv);
            signer.update("ks-ec".getBytes());
            assertNotNull(signer.sign());
        } finally {
            scope.close();
        }
    }

    private void assumeMlDsaAvailable() {
        Assume.assumeTrue("ML-DSA not compiled in native wolfSSL",
            FeatureDetect.MlDsaEnabled());
        Assume.assumeNotNull("ML-DSA test PEM files not available "
            + "(see examples/certs/mldsa/)",
            serverKeyMlDsa44, serverKeyMlDsa65, serverKeyMlDsa87);
    }

    private void assumeSlhDsaAvailable() {
        Assume.assumeTrue("SLH-DSA not compiled in native wolfSSL",
            FeatureDetect.SlhDsaEnabled());
        Assume.assumeTrue("SLH-DSA test keys not loadable on this build "
            + "(see examples/certs/slhdsa/)",
            (keySlhDsaSha2 != null) || (keySlhDsaShake != null));
    }

    private void assumeMlDsaWksAvailable() {
        assumeMlDsaAvailable();
        File f = new File(serverMlDsa44WKS);
        Assume.assumeTrue(
            "ML-DSA WKS files not available (run update-jks-wks.sh): "
            + serverMlDsa44WKS, f.exists());
    }

    /**
     * Store a single ML-DSA private key and self-signed cert at each param
     * level (44/65/87), retrieve, verify objects match.
     */
    @Test
    public void testStoreSingleKeyAndCertMlDsa() throws Exception {

        assumeMlDsaAvailable();

        PrivateKey[]  keys  = { serverKeyMlDsa44, serverKeyMlDsa65,
                                serverKeyMlDsa87 };
        Certificate[] certs = { serverCertMlDsa44, serverCertMlDsa65,
                                serverCertMlDsa87 };
        String[] names = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

        for (int i = 0; i < 3; i++) {
            KeyStore store = KeyStore.getInstance(storeType, storeProvider);
            store.load(null, storePass.toCharArray());
            store.setKeyEntry("mldsaCert", keys[i], storePass.toCharArray(),
                new Certificate[]{ certs[i] });
            assertEquals(names[i], 1, store.size());

            PrivateKey keyOut = (PrivateKey) store.getKey("mldsaCert",
                storePass.toCharArray());
            assertNotNull(names[i] + " key", keyOut);
            assertEquals(names[i] + " key roundtrip", keys[i], keyOut);

            Certificate certOut = store.getCertificate("mldsaCert");
            assertNotNull(names[i] + " cert", certOut);
            assertEquals(names[i] + " cert roundtrip", certs[i], certOut);
        }
    }

    /**
     * Setting an ML-DSA private key with a non-matching cert (different
     * parameter set) must be rejected by setKeyEntry.
     */
    @Test
    public void testMlDsaKeyCertMismatchRejected() throws Exception {

        assumeMlDsaAvailable();

        /* ML-DSA-44 private + ML-DSA-87 cert (mismatch) */
        KeyStore store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        try {
            store.setKeyEntry("bad", serverKeyMlDsa44, storePass.toCharArray(),
                new Certificate[]{ serverCertMlDsa87 });
            fail("setKeyEntry should reject ML-DSA-44 key + ML-DSA-87 cert");
        }
        catch (KeyStoreException e) {
            /* expected */
        }
        assertEquals(0, store.size());

        /* ML-DSA-65 private + RSA cert: cross-algorithm mismatch */
        store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        try {
            store.setKeyEntry("bad", serverKeyMlDsa65, storePass.toCharArray(),
                new Certificate[]{ serverCertRsa });
            fail("setKeyEntry should reject ML-DSA-65 key + RSA cert");
        }
        catch (KeyStoreException e) {
            /* expected */
        }
        assertEquals(0, store.size());
    }

    /**
     * Set ML-DSA cert as a trust anchor (no private key). Verify
     * getCertificate returns the same cert and getCertificateAlias
     * can look it up by value.
     */
    @Test
    public void testStoreSingleCertOnlyMlDsa() throws Exception {

        assumeMlDsaAvailable();

        KeyStore store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setCertificateEntry("trustMlDsa65", serverCertMlDsa65);
        assertEquals(1, store.size());
        assertTrue(store.isCertificateEntry("trustMlDsa65"));
        assertFalse(store.isKeyEntry("trustMlDsa65"));

        Certificate out = store.getCertificate("trustMlDsa65");
        assertEquals(serverCertMlDsa65, out);
        assertEquals("trustMlDsa65",
            store.getCertificateAlias(serverCertMlDsa65));
    }

    /**
     * Store ML-DSA entries, then engineStore to a byte buffer, load back,
     * and verify keys and certs round-trip. Exercises the WKS on-disk format
     * with ML-DSA payloads.
     */
    @Test
    public void testStoreLoadByteBufferMlDsa() throws Exception {

        assumeMlDsaAvailable();

        KeyStore store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());
        store.setKeyEntry("k44", serverKeyMlDsa44, storePass.toCharArray(),
            new Certificate[]{ serverCertMlDsa44 });
        store.setKeyEntry("k65", serverKeyMlDsa65, storePass.toCharArray(),
            new Certificate[]{ serverCertMlDsa65 });
        store.setKeyEntry("k87", serverKeyMlDsa87, storePass.toCharArray(),
            new Certificate[]{ serverCertMlDsa87 });
        store.setCertificateEntry("trust", serverCertMlDsa65);
        assertEquals(4, store.size());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        store.store(baos, storePass.toCharArray());
        byte[] wksBytes = baos.toByteArray();
        assertTrue(wksBytes.length > 0);

        KeyStore reload = KeyStore.getInstance(storeType, storeProvider);
        reload.load(new ByteArrayInputStream(wksBytes),
            storePass.toCharArray());
        assertEquals(4, reload.size());

        assertEquals(serverKeyMlDsa44,
            reload.getKey("k44", storePass.toCharArray()));
        assertEquals(serverKeyMlDsa65,
            reload.getKey("k65", storePass.toCharArray()));
        assertEquals(serverKeyMlDsa87,
            reload.getKey("k87", storePass.toCharArray()));
        assertEquals(serverCertMlDsa44, reload.getCertificate("k44"));
        assertEquals(serverCertMlDsa65, reload.getCertificate("k65"));
        assertEquals(serverCertMlDsa87, reload.getCertificate("k87"));
        assertEquals(serverCertMlDsa65, reload.getCertificate("trust"));
        assertTrue(reload.isCertificateEntry("trust"));
    }

    /**
     * Store SLH-DSA private keys + self-signed certs into a WKS KeyStore,
     * write to a byte stream, reload, and verify keys and certs round trip.
     */
    @Test
    public void testStoreLoadByteBufferSlhDsa() throws Exception {

        int expected = 0;

        assumeSlhDsaAvailable();

        KeyStore store = KeyStore.getInstance(storeType, storeProvider);
        store.load(null, storePass.toCharArray());

        if (keySlhDsaSha2 != null) {
            store.setKeyEntry("slhSha2", keySlhDsaSha2, storePass.toCharArray(),
                new Certificate[]{ certSlhDsaSha2 });
            store.setCertificateEntry("trustSha2", certSlhDsaSha2);
            expected += 2;
        }
        if (keySlhDsaShake != null) {
            store.setKeyEntry("slhShake", keySlhDsaShake,
                storePass.toCharArray(), new Certificate[]{ certSlhDsaShake });
            expected += 1;
        }
        assertEquals(expected, store.size());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        store.store(baos, storePass.toCharArray());
        byte[] wksBytes = baos.toByteArray();
        assertTrue(wksBytes.length > 0);

        KeyStore reload = KeyStore.getInstance(storeType, storeProvider);
        reload.load(new ByteArrayInputStream(wksBytes),
            storePass.toCharArray());
        assertEquals(expected, reload.size());

        if (keySlhDsaSha2 != null) {
            assertEquals(keySlhDsaSha2,
                reload.getKey("slhSha2", storePass.toCharArray()));
            assertEquals(certSlhDsaSha2, reload.getCertificate("slhSha2"));
            assertEquals(certSlhDsaSha2,
                reload.getCertificate("trustSha2"));
            assertTrue(reload.isCertificateEntry("trustSha2"));
        }
        if (keySlhDsaShake != null) {
            assertEquals(keySlhDsaShake,
                reload.getKey("slhShake", storePass.toCharArray()));
            assertEquals(certSlhDsaShake,
                reload.getCertificate("slhShake"));
        }
    }

    /**
     * Load each prebuilt ML-DSA WKS keystore file from disk (built by
     * examples/certs/BuildMlDsaKeystores.java), retrieve the key and cert,
     * verify they can do a Signature round-trip.
     */
    @Test
    public void testLoadMlDsaWKSFromFile() throws Exception {

        assumeMlDsaWksAvailable();

        String[] wksPaths = {
            serverMlDsa44WKS, serverMlDsa65WKS, serverMlDsa87WKS };
        String[] aliases  = {
            "server-mldsa44", "server-mldsa65", "server-mldsa87" };
        String[] sigAlgs  = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
        char[] wksPassword = "wolfsslpassword".toCharArray();

        for (int i = 0; i < 3; i++) {
            FileInputStream fis = new FileInputStream(wksPaths[i]);
            KeyStore ks;
            try {
                ks = KeyStore.getInstance(storeType, storeProvider);
                ks.load(fis, wksPassword);
            }
            finally {
                fis.close();
            }

            PrivateKey priv = (PrivateKey) ks.getKey(aliases[i], wksPassword);
            assertNotNull(sigAlgs[i] + ": getKey", priv);
            assertEquals("ML-DSA", priv.getAlgorithm());

            Certificate cert = ks.getCertificate(aliases[i]);
            assertNotNull(sigAlgs[i] + ": getCertificate", cert);
            assertEquals("ML-DSA", cert.getPublicKey().getAlgorithm());

            /* Sign + verify with retrieved key */
            Signature s = Signature.getInstance(sigAlgs[i], "wolfJCE");
            s.initSign(priv);
            byte[] msg = ("file-load " + sigAlgs[i]).getBytes();
            s.update(msg);
            byte[] sig = s.sign();

            Signature v = Signature.getInstance(sigAlgs[i], "wolfJCE");
            v.initVerify(cert.getPublicKey());
            v.update(msg);
            assertTrue(sigAlgs[i] + ": sign/verify with loaded key",
                v.verify(sig));
        }
    }

    /**
     * Load each prebuilt CA truststore (ML-DSA cert as trust anchor),
     * verify isCertificateEntry true and the cert round-trips.
     */
    @Test
    public void testLoadMlDsaCaWKSFromFile() throws Exception {

        assumeMlDsaWksAvailable();

        String[] wksPaths = { caMlDsa44WKS, caMlDsa65WKS, caMlDsa87WKS };
        String[] aliases  = { "ca-mldsa44", "ca-mldsa65", "ca-mldsa87" };
        Certificate[] expectedCerts = {
            serverCertMlDsa44, serverCertMlDsa65, serverCertMlDsa87 };
        char[] wksPassword = "wolfsslpassword".toCharArray();

        for (int i = 0; i < 3; i++) {
            FileInputStream fis = new FileInputStream(wksPaths[i]);
            KeyStore ks;
            try {
                ks = KeyStore.getInstance(storeType, storeProvider);
                ks.load(fis, wksPassword);
            }
            finally {
                fis.close();
            }

            assertTrue(aliases[i] + ": isCertificateEntry",
                ks.isCertificateEntry(aliases[i]));
            assertFalse(aliases[i] + ": isKeyEntry",
                ks.isKeyEntry(aliases[i]));
            Certificate out = ks.getCertificate(aliases[i]);
            assertEquals(aliases[i] + ": cert roundtrip",
                expectedCerts[i], out);
        }
    }

    /**
     * Store an LMS/HSS-keyed X.509 certificate (from native wolfSSL
     * certs/lms/) in a WKS KeyStore as a trusted certificate entry, reload it,
     * and confirm it round-trips. Also confirms wolfJCE can import the
     * certificate LMS public key. wolfJCE WKS does not store stateful LMS
     * private keys, so only the certificate/public-key path is exercised.
     */
    @Test
    public void testLmsCertificateRoundTrip() throws Exception {

        Assume.assumeTrue("LMS not compiled in", FeatureDetect.LmsEnabled());

        Assume.assumeTrue("LMS test certificate not present",
            new File(lmsCertDer).exists());

        Certificate lmsCert = certFileToCertificate(lmsCertDer);

        KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
        store.load(null, storePass.toCharArray());
        store.setCertificateEntry("lms-root", lmsCert);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        store.store(bos, storePass.toCharArray());

        KeyStore reloaded = KeyStore.getInstance("WKS", "wolfJCE");
        reloaded.load(new ByteArrayInputStream(bos.toByteArray()),
            storePass.toCharArray());

        Certificate got = reloaded.getCertificate("lms-root");
        assertNotNull("LMS certificate missing after reload", got);
        assertTrue("LMS entry should be a certificate entry",
            reloaded.isCertificateEntry("lms-root"));
        assertArrayEquals("LMS certificate did not round-trip",
            lmsCert.getEncoded(), got.getEncoded());

        /* wolfJCE can import the certificate's LMS/HSS public key. The public
         * key materialization is guarded because older JDKs (< 21) cannot
         * expose an HSS/LMS certificate public key. */
        PublicKey certPub = null;
        try {
            certPub = got.getPublicKey();
        } catch (RuntimeException e) {
            certPub = null;
        }
        if (certPub != null && certPub.getEncoded() != null) {
            KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
            PublicKey wolfPub = null;
            try {
                wolfPub = kf.generatePublic(
                    new X509EncodedKeySpec(certPub.getEncoded()));
            } catch (InvalidKeySpecException e) {
                /* Test certificate uses an LMS SHA-256/256 parameter set,
                 * which native wolfCrypt may be built without. Treat that as
                 * a skip. */
                if (isNotCompiledIn(e)) {
                    Assume.assumeTrue(
                        "LMS SHA-256/256 parameter set not compiled in", false);
                }
                throw e;
            }
            assertEquals("HSS/LMS", wolfPub.getAlgorithm());
        }
    }

    /* True if throwable cause chain contains NOT_COMPILED_IN. */
    private static boolean isNotCompiledIn(Throwable t) {

        for (; t != null; t = t.getCause()) {
            if (t instanceof WolfCryptException &&
                ((WolfCryptException) t).getError() ==
                    WolfCryptError.NOT_COMPILED_IN) {
                return true;
            }
        }

        return false;
    }
}

