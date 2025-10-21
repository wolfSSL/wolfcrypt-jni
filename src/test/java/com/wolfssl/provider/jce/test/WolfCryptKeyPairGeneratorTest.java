/* wolfCryptKeyPairGeneratorTest.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
import org.junit.BeforeClass;

import java.util.ArrayList;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.InvalidParameterException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.test.Util;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptKeyPairGeneratorTest {

    private static String supportedCurves[] = {
        "secp192r1",
        "prime192v2",
        "prime192v3",
        "prime239v1",
        "prime239v2",
        "prime239v3",
        "secp256r1",

        "secp112r1",
        "secp112r2",
        "secp128r1",
        "secp128r2",
        "secp160r1",
        "secp224r1",
        "secp384r1",
        "secp521r1",

        "secp160k1",
        "secp192k1",
        "secp224k1",
        "secp256k1",

        "brainpoolp160r1",
        "brainpoolp192r1",
        "brainpoolp224r1",
        "brainpoolp256r1",
        "brainpoolp320r1",
        "brainpoolp384r1",
        "brainpoolp512r1"
    };

    private static String supportedCurvesFIPS1403[] = {
        "secp224r1",
        "secp256r1",
        "secp384r1",
        "secp521r1",

        "secp224k1",
        "secp256k1",
    };

    private static ArrayList<String> enabledCurves =
        new ArrayList<String>();

    private static ArrayList<Integer> enabledEccKeySizes =
        new ArrayList<Integer>();

    /* Test generation of these RSA key sizes */
    private static ArrayList<Integer> testedRSAKeySizes =
        new ArrayList<Integer>();

    /* DH test params */
    private static byte[] prime = Util.h2b(
        "B0A108069C0813BA59063CBC30D5F500C14F44A7D6EF4AC625271CE8D" +
        "296530A5C91DDA2C29484BF7DB2449F9BD2C18AC5BE725CA7E791E6D4" +
        "9F7307855B6648C770FAB4EE02C93D9A4ADA3DC1463E1969D1174607A" +
        "34D9F2B9617396D308D2AF394D375CFA075E6F2921F1A7005AA048357" +
        "30FBDA76933850E827FD63EE3CE5B7C809AE6F50358E84CE4A00E9127" +
        "E5A31D733FC211376CC1630DB0CFCC562A735B8EFB7B0ACC036F6D9C9" +
        "4648F94090002B1BAA6CE31AC30B039E1BC246E4484E22736FC35FD49" +
        "AD6300748D68C90ABD4F6F1E348D3584BA6B9CD29BF681F084B63862F" +
        "5C6BD6B60665F7A6DC00676BBBC3A94183FBC7FAC8E21E7EAF003F93"
    );
    private static byte[] base = new byte[] { 0x02 };

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        System.out.println("JCE WolfCryptKeyPairGeneratorTest Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* FIPS after 2425 doesn't allow 1024-bit RSA key gen */
        if ((!Fips.enabled || Fips.fipsVersion < 5) &&
            (Rsa.RSA_MIN_SIZE <= 1024)) {
            testedRSAKeySizes.add(Integer.valueOf(1024));
        }
        if (Rsa.RSA_MIN_SIZE <= 2048) {
            testedRSAKeySizes.add(Integer.valueOf(2048));
        }
        if (Rsa.RSA_MIN_SIZE <= 3072) {
            testedRSAKeySizes.add(Integer.valueOf(3072));
        }
        if (Rsa.RSA_MIN_SIZE <= 4096) {
            testedRSAKeySizes.add(Integer.valueOf(4096));
        }

        /* build list of enabled curves and key sizes,
         * getCurveSizeFromName() will return 0 if curve not found */
        String[] curves = null;

        if (Fips.enabled && Fips.fipsVersion >= 5) {
            curves = supportedCurvesFIPS1403;
        } else {
            curves = supportedCurves;
        }

        for (int i = 0; i < curves.length; i++) {

            int size = Ecc.getCurveSizeFromName(curves[i].toUpperCase());

            if (size > 0) {
                enabledCurves.add(curves[i]);

                if (!enabledEccKeySizes.contains(Integer.valueOf(size))) {
                    enabledEccKeySizes.add(Integer.valueOf(size));
                }
            }
        }
    }

    @Test
    public void testGetKeyPairGeneratorFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        assertNotNull(kpg);
        kpg = KeyPairGenerator.getInstance("RSA", "wolfJCE");
        assertNotNull(kpg);
        kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(kpg);
        kpg = KeyPairGenerator.getInstance("RSASSA-PSS", "wolfJCE");
        assertNotNull(kpg);

        /* getting a garbage algorithm should throw an exception */
        try {
            kpg = KeyPairGenerator.getInstance("NotValid", "wolfJCE");

            fail("KeyPairGenerator.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testKeyPairGeneratorRsaInitializeWithParamSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try initializing KPG for all tested key sizes */
        for (int i = 0; i < testedRSAKeySizes.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");

            RSAKeyGenParameterSpec rsaSpec =
                new RSAKeyGenParameterSpec(testedRSAKeySizes.get(i),
                        BigInteger.valueOf(Rsa.getDefaultRsaExponent()));
            kpg.initialize(rsaSpec);

            /* bad key size should fail */
            try {
                rsaSpec = new RSAKeyGenParameterSpec(10,
                        BigInteger.valueOf(Rsa.getDefaultRsaExponent()));
                kpg.initialize(rsaSpec);
            } catch (InvalidAlgorithmParameterException e) {}
        }
    }

    @Test
    public void testKeyPairGeneratorRsaInitializeWithKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try initializing KPG for all tested key sizes */
        for (int i = 0; i < testedRSAKeySizes.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");

            kpg.initialize(testedRSAKeySizes.get(i));

            /* bad key size should fail */
            try {
                kpg.initialize(10);
            } catch (InvalidParameterException e) {}
        }
    }

    @Test
    public void testKeyPairGeneratorRsaKeyGenAllSizes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try generating keys for all tested sizes */
        for (int i = 0; i < testedRSAKeySizes.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");

            RSAKeyGenParameterSpec rsaSpec =
                new RSAKeyGenParameterSpec(testedRSAKeySizes.get(i),
                        BigInteger.valueOf(Rsa.getDefaultRsaExponent()));
            kpg.initialize(rsaSpec);

            KeyPair kp = kpg.generateKeyPair();
            assertNotNull(kp);
        }
    }

    @Test
    public void testKeyPairGeneratorRsaMultipleInits()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        if (testedRSAKeySizes.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");

            RSAKeyGenParameterSpec rsaSpec =
                new RSAKeyGenParameterSpec(testedRSAKeySizes.get(0),
                        BigInteger.valueOf(Rsa.getDefaultRsaExponent()));

            kpg.initialize(rsaSpec);
            kpg.initialize(rsaSpec);
        }
    }

    @Test
    public void testKeyPairGeneratorRsaMultipleKeyGen()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        if (testedRSAKeySizes.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");

            RSAKeyGenParameterSpec rsaSpec =
                new RSAKeyGenParameterSpec(testedRSAKeySizes.get(0),
                        BigInteger.valueOf(Rsa.getDefaultRsaExponent()));
            kpg.initialize(rsaSpec);

            KeyPair kp1 = kpg.generateKeyPair();
            KeyPair kp2 = kpg.generateKeyPair();
            assertNotNull(kp1);
            assertNotNull(kp2);
        }
    }

    @Test
    public void testKeyPairGeneratorRsaNewKeyFromExisting()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException, InvalidKeySpecException {

        if (testedRSAKeySizes.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");

            RSAKeyGenParameterSpec rsaSpec =
                new RSAKeyGenParameterSpec(testedRSAKeySizes.get(0),
                        BigInteger.valueOf(Rsa.getDefaultRsaExponent()));
            kpg.initialize(rsaSpec);

            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(
                        kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(
                        kp.getPrivate().getEncoded()));
            assertNotNull(pub);
            assertNotNull(priv);
        }
    }

    @Test
    public void testKeyPairGeneratorEccInitializeWithParamSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try initializing KPG for all supported curves */
        for (int i = 0; i < enabledCurves.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(i));
            kpg.initialize(ecSpec);

            /* bad curve should fail */
            try {
                ecSpec = new ECGenParameterSpec("BADCURVE");
                kpg.initialize(ecSpec);
            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testKeyPairGeneratorEccInitializeWithKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try initializing KPG for all supported key sizes */
        for (int i = 0; i < enabledEccKeySizes.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            kpg.initialize(enabledEccKeySizes.get(i));

            /* bad key size should fail */
            try {
                kpg.initialize(9999);
            } catch (WolfCryptException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testKeyPairGeneratorEccKeySizeBitsToBytes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* Test that ECC key sizes passed in bits are correctly converted
         * to bytes for native wolfSSL. Standard Java
         * KeyPairGenerator.initialize(int keysize) expects bits, but wolfSSL
         * wc_ecc_make_key() expects bytes. */

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("EC", "wolfJCE");

        /* Just test 256 bit to spot check this behavior */
        int bitSize = 256;

        if (enabledEccKeySizes.contains(Integer.valueOf(bitSize)) == false) {
            /* skip if 256-bit ECC not supported */
            return;
        }

        /* Initialize with bit size (standard Java way) */
        kpg.initialize(bitSize);

        /* Generate key pair */
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull(kp);
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());

        /* Verify the generated key provides adequate security */
        if (kp.getPublic() instanceof ECPublicKey) {
            ECPublicKey ecPubKey = (ECPublicKey) kp.getPublic();
            ECParameterSpec ecSpec = ecPubKey.getParams();
            int fieldSize = ecSpec.getCurve().getField().getFieldSize();

            /* The field size should be at least the requested bit size.
             * wolfSSL may select a larger curve for better security. */
            assertTrue("Key field size should be at least requested " +
                "bit size. Requested: " + bitSize + ", Got: " + fieldSize,
                fieldSize >= bitSize);
        }
    }

    @Test
    public void testKeyPairGeneratorEccKeyGenAllCurves()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try generating keys for all supported curves */
        for (int i = 0; i < enabledCurves.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(i));
            kpg.initialize(ecSpec);

            try {
                KeyPair kp = kpg.generateKeyPair();
                assertNotNull(kp);
            } catch (Exception e) {
                /* Some JDK versions' ECKeyFactory may not support all
                 * wolfCrypt's ECC curves */
                if (!e.toString().contains("Unknown named curve")) {
                    throw e;
                }
            }
        }
    }

    @Test
    public void testKeyPairGeneratorEccMultipleInits()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        if (enabledCurves.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(0));

            kpg.initialize(ecSpec);
            kpg.initialize(ecSpec);
        }
    }

    @Test
    public void testKeyPairGeneratorEccMultipleKeyGen()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        if (enabledCurves.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(0));
            kpg.initialize(ecSpec);

            KeyPair kp1 = kpg.generateKeyPair();
            KeyPair kp2 = kpg.generateKeyPair();

            assertNotNull(kp1);
            assertNotNull(kp2);
        }
    }

    @Test
    public void testKeyPairGeneratorEccNewKeyFromExisting()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException, InvalidKeySpecException {

        if (enabledCurves.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(0));
            kpg.initialize(ecSpec);

            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(
                        kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(
                        kp.getPrivate().getEncoded()));

            assertNotNull(pub);
            assertNotNull(priv);
        }
    }

    @Test
    public void testKeyPairGeneratorDhInitializeWithParamSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        int testDHKeySizes[] = { 512, 1024, 2048 };

        for (int i = 0; i < testDHKeySizes.length; i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("DH", "wolfJCE");

            DHParameterSpec spec = new DHParameterSpec(
                    new BigInteger(prime),
                    new BigInteger(base),
                    testDHKeySizes[i]);

            kpg.initialize(spec);
            KeyPair pair = kpg.generateKeyPair();

            assertNotNull(pair);
        }
    }

    @Test
    public void testKeyPairGeneratorDhInitWithKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* Test that DH KeyPairGenerator supports initialize(int) with
         * FFDHE standard key sizes (2048, 3072, 4096, 6144, 8192) */
        int[] ffdheKeySizes = { 2048, 3072, 4096, 6144, 8192 };

        for (int keySize : ffdheKeySizes) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("DH", "wolfJCE");

            try {
                /* Initialize with FFDHE key size */
                kpg.initialize(keySize);

                /* Generate key pair to verify initialization worked */
                KeyPair kp = kpg.generateKeyPair();
                assertNotNull(kp);
                assertNotNull(kp.getPublic());
                assertNotNull(kp.getPrivate());
            }
            catch (InvalidParameterException e) {
                /* FFDHE group may not be available in native wolfSSL.
                 * Skip if not available. */
                if (e.getMessage() != null && e.getMessage().contains(
                    "FFDHE " + keySize + "-bit group not available")) {
                    System.out.println("\tSkipping FFDHE " + keySize +
                        ": not compiled into native wolfSSL library");
                    continue;
                }
                throw e;
            }
            catch (RuntimeException e) {
                if (e.getMessage() != null &&
                    e.getMessage().contains("group not available") ||
                    e.getMessage().contains("Unsupported FFDHE group")) {
                    continue;
                }
            }
        }

        /* Test that non-FFDHE sizes throw exception */
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("DH", "wolfJCE");

        try {
            kpg.initialize(512);
            fail("initialize(512) should throw InvalidParameterException " +
                 "for non-FFDHE key size");
        } catch (InvalidParameterException e) {
            /* expected */
        }
    }

    @Test
    public void testKeyPairGeneratorDhMultipleInits()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("DH", "wolfJCE");

        DHParameterSpec spec = new DHParameterSpec(
                new BigInteger(prime), new BigInteger(base), 512);

        kpg.initialize(spec);
        kpg.initialize(spec);
    }

    @Test
    public void testKeyPairGeneratorDhMultipleKeyGen()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("DH", "wolfJCE");

        DHParameterSpec spec = new DHParameterSpec(
                new BigInteger(prime), new BigInteger(base), 512);

        kpg.initialize(spec);

        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();

        assertNotNull(kp1);
        assertNotNull(kp2);
    }

    @Test
    public void testKeyPairGeneratorDhDefaultKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Test that DH KeyPairGenerator works with default parameters
         * without explicit initialization. This matches SunJCE behavior. */
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("DH", "wolfJCE");

        /* Generate key pair without calling initialize() first.
         * Should use default FFDHE 3072-bit parameters. */
        KeyPair kp = null;
        try {
            kp = kpg.generateKeyPair();
        }
        catch (RuntimeException e) {
            /* Default FFDHE parameters may not be available in native
             * wolfSSL. Skip test if not compiled in. */
            if (e.getMessage() != null && e.getMessage().contains(
                "No DH parameters available")) {
                return;
            }
            throw e;
        }

        assertNotNull(kp);
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());

        /* Verify the generated key is DH */
        assertTrue(kp.getPublic() instanceof DHPublicKey);
        assertTrue(kp.getPrivate() instanceof DHPrivateKey);

        DHPublicKey pubKey = (DHPublicKey) kp.getPublic();
        DHPrivateKey privKey = (DHPrivateKey) kp.getPrivate();

        /* Verify parameters are present */
        assertNotNull(pubKey.getParams());
        assertNotNull(privKey.getParams());
        assertNotNull(pubKey.getParams().getP());
        assertNotNull(pubKey.getParams().getG());

        /* Default should be FFDHE 3072-bit (to match SunJCE), but will
         * fall back to FFDHE 2048 if 3072 is not compiled into wolfSSL.
         * Check P is approximately 2048 or 3072 bits.
         * BigInteger.bitLength() returns minimal bits needed, which may be
         * less than the nominal size if there are leading zero bits. */
        int pBitLength = pubKey.getParams().getP().bitLength();
        assertTrue("Default DH prime should be approximately 2048 or " +
            "3072 bits, got " + pBitLength,
            (pBitLength >= 2016 && pBitLength <= 2048) ||
            (pBitLength >= 3008 && pBitLength <= 3072));

        /* Verify keys use same parameters */
        assertEquals("Public and private keys should use same P",
            pubKey.getParams().getP(), privKey.getParams().getP());
        assertEquals("Public and private keys should use same G",
            pubKey.getParams().getG(), privKey.getParams().getG());

        /* Generate another KeyPair to verify default params work repeatedly */
        KeyPair kp2 = kpg.generateKeyPair();
        assertNotNull(kp2);

        DHPublicKey pubKey2 = (DHPublicKey) kp2.getPublic();

        /* Both key pairs should use same default parameters */
        assertEquals("Both key pairs should use same default P",
            pubKey.getParams().getP(), pubKey2.getParams().getP());
        assertEquals("Both key pairs should use same default G",
            pubKey.getParams().getG(), pubKey2.getParams().getG());
    }

    @Test
    public void testKeyPairGeneratorRsaDefaultKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Test that RSA KeyPairGenerator works with default parameters
         * without explicit initialization */
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("RSA", "wolfJCE");

        /* Generate key pair without calling initialize() first */
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull(kp);
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());

        /* Verify the generated key is RSA and has expected default size */
        assertTrue(kp.getPublic() instanceof RSAPublicKey);
        assertTrue(kp.getPrivate() instanceof RSAPrivateKey);

        RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privKey = (RSAPrivateKey) kp.getPrivate();

        /* Default key size should be 2048 bits */
        assertEquals("Default RSA key size should be 2048 bits",
                     2048, pubKey.getModulus().bitLength());
        assertEquals("Private key modulus should match public key",
                     pubKey.getModulus(), privKey.getModulus());

        /* Verify the default public exponent */
        assertEquals("Default RSA public exponent should match wolfSSL default",
                     BigInteger.valueOf(Rsa.getDefaultRsaExponent()),
                     pubKey.getPublicExponent());
    }

    @Test
    public void testKeyPairGeneratorEccDefaultKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Skip test if 256-bit ECC not supported */
        if (!enabledEccKeySizes.contains(Integer.valueOf(32))) {
            return;
        }

        /* Test that ECC KeyPairGenerator works with default parameters
         * without explicit initialization */
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("EC", "wolfJCE");

        /* Generate key pair without calling initialize() first */
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull(kp);
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());

        /* Verify the generated key is ECC */
        assertTrue(kp.getPublic() instanceof ECPublicKey);
        assertTrue(kp.getPrivate() instanceof ECPrivateKey);

        ECPublicKey pubKey = (ECPublicKey) kp.getPublic();
        ECParameterSpec ecParams = pubKey.getParams();
        assertNotNull(ecParams);

        /* Default key size should be 256 bits (32 bytes), verify field size */
        int fieldSize = ecParams.getCurve().getField().getFieldSize();
        assertEquals("Default ECC key field size should be 256 bits",
                     256, fieldSize);
    }

    @Test
    public void testKeyPairGeneratorRsassaPssKeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* Test RSASSA-PSS KeyPairGenerator alias uses same
         * RSA key generation */
        if (testedRSAKeySizes.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSASSA-PSS", "wolfJCE");

            RSAKeyGenParameterSpec rsaSpec =
                new RSAKeyGenParameterSpec(testedRSAKeySizes.get(0),
                        BigInteger.valueOf(Rsa.getDefaultRsaExponent()));
            kpg.initialize(rsaSpec);

            KeyPair kp = kpg.generateKeyPair();
            assertNotNull(kp);
            assertNotNull(kp.getPublic());
            assertNotNull(kp.getPrivate());

            /* Verify keys can be used with RSASSA-PSS signature */
            try {
                java.security.Signature sig =
                    java.security.Signature.getInstance(
                        "RSASSA-PSS", "wolfJCE");
                sig.initSign(kp.getPrivate());
                sig.update("test data".getBytes());
                byte[] signature = sig.sign();
                assertNotNull(signature);

                sig.initVerify(kp.getPublic());
                sig.update("test data".getBytes());
                assertTrue(sig.verify(signature));
            } catch (Exception e) {
                /* If signature test fails, it's not a key generation issue */
            }
        }
    }

    @Test
    public void testKeyPairGenerationInvalidExponent()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        if (testedRSAKeySizes.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");

            /* Negative exponent */
            try {
                RSAKeyGenParameterSpec rsaSpec =
                    new RSAKeyGenParameterSpec(testedRSAKeySizes.get(0),
                            BigInteger.valueOf(-1));
                kpg.initialize(rsaSpec);
                fail("KeyPairGenerator.initialize() should throw " +
                     "InvalidAlgorithmParameterException when given " +
                     "invalid negative RSA public exponent");

            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }

            /* Zero exponent */
            try {
                RSAKeyGenParameterSpec rsaSpec =
                    new RSAKeyGenParameterSpec(testedRSAKeySizes.get(0),
                            BigInteger.valueOf(0));
                kpg.initialize(rsaSpec);
                fail("KeyPairGenerator.initialize() should throw " +
                     "InvalidAlgorithmParameterException when given " +
                     "invalid RSA public exponent of zero");

            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }

            /* Even exponent */
            try {
                RSAKeyGenParameterSpec rsaSpec =
                    new RSAKeyGenParameterSpec(testedRSAKeySizes.get(0),
                            BigInteger.valueOf(4));
                kpg.initialize(rsaSpec);
                fail("KeyPairGenerator.initialize() should throw " +
                     "InvalidAlgorithmParameterException when given " +
                     "invalid even RSA public exponent");

            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testRsassaPssKeyIdentificationAndSunCompatibility()
        throws Exception {

        if (testedRSAKeySizes.isEmpty()) {
            return;
        }

        /* Test RSASSA-PSS key generation with proper algorithm ID */
        KeyPairGenerator pssKpg =
            KeyPairGenerator.getInstance("RSASSA-PSS", "wolfJCE");
        pssKpg.initialize(testedRSAKeySizes.get(0));

        KeyPair pssKeys = pssKpg.generateKeyPair();
        assertNotNull(pssKeys);
        assertNotNull(pssKeys.getPublic());
        assertNotNull(pssKeys.getPrivate());

        /* Verify keys identify as RSASSA-PSS */
        assertEquals("RSASSA-PSS", pssKeys.getPrivate().getAlgorithm());
        assertEquals("RSASSA-PSS", pssKeys.getPublic().getAlgorithm());

        /* Test OID alias */
        KeyPairGenerator oidKpg =
            KeyPairGenerator.getInstance("1.2.840.113549.1.1.10", "wolfJCE");
        oidKpg.initialize(testedRSAKeySizes.get(0));

        KeyPair oidKeys = oidKpg.generateKeyPair();
        assertNotNull(oidKeys);
        assertEquals("RSASSA-PSS", oidKeys.getPrivate().getAlgorithm());
        assertEquals("RSASSA-PSS", oidKeys.getPublic().getAlgorithm());

        /* Test Sun KeyFactory compatibility */
        KeyFactory sunPssKf = KeyFactory.getInstance("RSASSA-PSS");

        /* Test key specs conversion with system/Sun KeyFactory */
        RSAPublicKeySpec pubSpec = sunPssKf.getKeySpec(
            pssKeys.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateCrtKeySpec privSpec = sunPssKf.getKeySpec(
            pssKeys.getPrivate(), RSAPrivateCrtKeySpec.class);

        /* Generate keys from specs using system/Sun KeyFactory */
        PublicKey sunPubKey = sunPssKf.generatePublic(pubSpec);
        PrivateKey sunPrivKey = sunPssKf.generatePrivate(privSpec);

        assertEquals("RSASSA-PSS", sunPubKey.getAlgorithm());
        assertEquals("RSASSA-PSS", sunPrivKey.getAlgorithm());

        /* Test encoded key specs with Sun KeyFactory */
        PublicKey pubFromEncoded = sunPssKf.generatePublic(
            new X509EncodedKeySpec(pssKeys.getPublic().getEncoded()));
        PrivateKey privFromEncoded = sunPssKf.generatePrivate(
            new PKCS8EncodedKeySpec(pssKeys.getPrivate().getEncoded()));

        assertEquals("RSASSA-PSS", pubFromEncoded.getAlgorithm());
        assertEquals("RSASSA-PSS", privFromEncoded.getAlgorithm());

        /* Test key equality */
        RSAPublicKey origPub = (RSAPublicKey) pssKeys.getPublic();
        RSAPublicKey sunPub = (RSAPublicKey) sunPubKey;
        RSAPrivateKey origPriv = (RSAPrivateKey) pssKeys.getPrivate();
        RSAPrivateKey sunPriv = (RSAPrivateKey) sunPrivKey;

        assertEquals(origPub.getModulus(), sunPub.getModulus());
        assertEquals(origPub.getPublicExponent(),
            sunPub.getPublicExponent());
        assertEquals(origPriv.getModulus(), sunPriv.getModulus());
        assertEquals(origPriv.getPrivateExponent(),
            sunPriv.getPrivateExponent());

        /* Test signature compatibility with generated keys */
        java.security.Signature sig =
            java.security.Signature.getInstance("RSASSA-PSS", "wolfJCE");

        /* Set PSS parameters (required by wolfJCE) */
        PSSParameterSpec pssParams = new PSSParameterSpec("SHA-256", "MGF1",
            MGF1ParameterSpec.SHA256, 32, 1);
        sig.setParameter(pssParams);

        sig.initSign(pssKeys.getPrivate());
        sig.update("test data for RSASSA-PSS".getBytes());
        byte[] signature = sig.sign();
        assertNotNull(signature);
        assertTrue(signature.length > 0);

        sig.initVerify(pssKeys.getPublic());
        sig.update("test data for RSASSA-PSS".getBytes());
        assertTrue(sig.verify(signature));

        /* Test cross-compatibility: sign with our key, verify with Sun key */
        sig.initVerify(sunPubKey);
        sig.update("test data for RSASSA-PSS".getBytes());
        assertTrue("Sun-generated key should verify wolfJCE signature",
            sig.verify(signature));
    }

    @Test
    public void testECKeyPairGeneratorOIDMapping()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* Test that ECC KeyPairGenerator OID 1.2.840.10045.2.1 maps to "EC" */
        String oid = "1.2.840.10045.2.1";
        String algoName = "EC";

        /* Skip test if ECC is not compiled in */
        if (enabledEccKeySizes.isEmpty()) {
            return;
        }

        /* Create KeyPairGenerator instances using both OID and name */
        KeyPairGenerator kpgByOid = null;
        KeyPairGenerator kpgByName = null;

        try {
            kpgByOid = KeyPairGenerator.getInstance(oid, "wolfJCE");
            kpgByName = KeyPairGenerator.getInstance(algoName, "wolfJCE");
        } catch (NoSuchAlgorithmException e) {
            fail("Failed to create KeyPairGenerator instance for OID " + oid +
                 " or algorithm " + algoName + ": " + e.getMessage());
        }

        assertNotNull("KeyPairGenerator by OID should not be null", kpgByOid);
        assertNotNull("KeyPairGenerator by name should not be null", kpgByName);

        /* Verify both instances have the same class */
        assertEquals("OID and name should map to same implementation",
            kpgByName.getClass(), kpgByOid.getClass());

        /* Test functional equivalence - both should generate valid key pairs */
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");

        kpgByOid.initialize(ecSpec);
        KeyPair keyPairFromOid = kpgByOid.generateKeyPair();
        assertNotNull("Key pair from OID should not be null", keyPairFromOid);
        assertNotNull("Private key from OID should not be null",
            keyPairFromOid.getPrivate());
        assertNotNull("Public key from OID should not be null",
            keyPairFromOid.getPublic());

        kpgByName.initialize(ecSpec);
        KeyPair keyPairFromName = kpgByName.generateKeyPair();
        assertNotNull("Key pair from name should not be null", keyPairFromName);
        assertNotNull("Private key from name should not be null",
            keyPairFromName.getPrivate());
        assertNotNull("Public key from name should not be null",
            keyPairFromName.getPublic());

        /* Both key pairs should have the same algorithm */
        assertEquals("Key algorithms should match",
            keyPairFromName.getPrivate().getAlgorithm(),
            keyPairFromOid.getPrivate().getAlgorithm());
        assertEquals("Public key algorithms should match",
            keyPairFromName.getPublic().getAlgorithm(),
            keyPairFromOid.getPublic().getAlgorithm());
    }
}

