/* EccTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.interfaces.ECPrivateKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class EccTest {
    private static Rng rng = new Rng();
    private static final Object rngLock = new Rng();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void setUpRng() {
        synchronized (rngLock) {
            rng.init();
        }
    }

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Ecc();
            System.out.println("JNI Ecc Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("Ecc test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new Ecc().getNativeStruct());
    }

    @Test
    public void sharedSecretShouldMatch() {
        Ecc alice = new Ecc();
        Ecc bob = new Ecc();
        Ecc aliceX963 = new Ecc();

        synchronized (rngLock) {
            alice.makeKey(rng, 66);
            bob.makeKey(rng, 66);
        }
        aliceX963.importX963(alice.exportX963());

        byte[] sharedSecretA = alice.makeSharedSecret(bob);
        byte[] sharedSecretB = bob.makeSharedSecret(aliceX963);

        assertArrayEquals(sharedSecretA, sharedSecretB);

        Ecc alice2 = new Ecc();

        alice2.importPrivate(alice.exportPrivate(), alice.exportX963());

        assertArrayEquals(sharedSecretA, alice2.makeSharedSecret(bob));
    }

    @Test
    public void signatureShouldMatchDecodingKeys() {
        Ecc alice = new Ecc();
        Ecc bob = new Ecc();
        Ecc aliceX963 = new Ecc();

        byte[] prvKey = Util.h2b("30770201010420F8CF92"
                + "6BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                + "F88F974DAF568965C7A00A06082A8648CE3D0301"
                + "07A1440342000455BFF40F44509A3DCE9BB7F0C5"
                + "4DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "F7BDA9B236225FC75D7FB4");

        byte[] pubKey = Util.h2b("3059301306072A8648CE"
                + "3D020106082A8648CE3D0301070342000455BFF4"
                + "0F44509A3DCE9BB7F0C54DF5707BD4EC248E1980"
                + "EC5A4CA22403622C9BDAEFA2351243847616C656"
                + "9506CC01A9BDF6751A42F7BDA9B236225FC75D7FB4");

        alice.privateKeyDecode(prvKey);
        bob.publicKeyDecode(pubKey);

        byte[] hash = "Everyone gets Friday off. ecc p".getBytes();

        byte[] signature = null;
        synchronized (rngLock) {
            signature = alice.sign(hash, rng);
        }

        assertTrue(bob.verify(hash, signature));

        aliceX963.importX963(alice.exportX963());

        assertTrue(aliceX963.verify(hash, signature));

        assertArrayEquals(prvKey, alice.privateKeyEncode());
        assertArrayEquals(pubKey, alice.publicKeyEncode());
        assertArrayEquals(pubKey, bob.publicKeyEncode());
        assertArrayEquals(pubKey, aliceX963.publicKeyEncode());

        Ecc alice2 = new Ecc();

        alice2.importPrivate(alice.exportPrivate(), alice.exportX963());

        assertTrue(alice2.verify(hash, signature));
    }

    @Test
    public void eccCurveSizeFromName() {
        int size = 0;

        /* valid case */
        size = Ecc.getCurveSizeFromName("secp256r1");
        assertEquals(size, 32);

        /* mixed case should work */
        size = Ecc.getCurveSizeFromName("SeCp256R1");
        assertEquals(size, 32);

        /* bad curve should return -1 */
        size = Ecc.getCurveSizeFromName("BADCURVE");
        assertEquals(size, -1);

        /* null should return BAD_FUNC_ARG */
        size = Ecc.getCurveSizeFromName(null);
        assertEquals(size, -173);
    }

    @Test
    public void eccMakeKeyOnCurve() {
        Ecc alice = new Ecc();
        synchronized (rngLock) {
            alice.makeKeyOnCurve(rng, 32, "secp256r1");
        }

        try {
            alice = new Ecc();
            synchronized (rngLock) {
                alice.makeKeyOnCurve(rng, 32, "BADCURVE");
            }
            fail("Creating ECC key on bad curve should fail with exception");
        } catch (WolfCryptException e) {
            /* should throw exception here */
        }
    }

    @Test
    public void eccPrivateToPkcs8() {
        Ecc alice = new Ecc();
        byte[] pkcs8;

        byte[] prvKey = Util.h2b("30770201010420F8CF92"
                + "6BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                + "F88F974DAF568965C7A00A06082A8648CE3D0301"
                + "07A1440342000455BFF40F44509A3DCE9BB7F0C5"
                + "4DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "F7BDA9B236225FC75D7FB4");

        byte[] expectedPkcs8 = Util.h2b("304D02010030130607"
                + "2A8648CE3D020106082A8648CE3D030107043330"
                + "310201010420F8CF926BBD1E28F1A8ABA1234F32"
                + "74188850AD7EC7EC92F88F974DAF568965C7A00A"
                + "06082A8648CE3D030107");

        alice.privateKeyDecode(prvKey);

        pkcs8 = alice.privateKeyEncodePKCS8();
        assertArrayEquals(pkcs8, expectedPkcs8);
    }

    @Test
    public void eccImportPrivateOnly() {

        byte[] prvKeyLeadingZero = Util.h2b("00B298F9A9874F4"
                + "F30A492429DE0CD2A575A132F24323EF79AD2EFFE"
                + "BF9D597620");

        byte[] prvKeyNoLeadingZero = Util.h2b("B298F9A9874"
                + "F4F30A492429DE0CD2A575A132F24323EF79AD2EF"
                + "FEBF9D597620");

        /* invalid key, size is > ECC_MAXSIZE (128 with enable-all) */
        byte[] prvKeyInvalid = Util.h2b("30770201010420F8CF92"
                + "6BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                + "F88F974DAF568965C7A00A06082A8648CE3D0301"
                + "07A1440342000455BFF40F44509A3DCE9BB7F0C5"
                + "4DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "F7BDA9B236225FC75D7FB4");

        /* with leading zero, as expected */
        Ecc alice = new Ecc();
        alice.importPrivate(prvKeyLeadingZero, null);

        /* without leading zero, may encounter but not proper */
        alice = new Ecc();
        alice.importPrivate(prvKeyNoLeadingZero, null);

        try {
            /* try invalid key, expect failure */
            alice = new Ecc();
            alice.importPrivate(prvKeyInvalid, null);
            fail("Importing invalid ECC private key should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

    }

    @Test
    public void eccImportPrivateOnlyOnCurve() {

        byte[] prvKeyLeadingZero = Util.h2b("00B298F9A9874F4"
                + "F30A492429DE0CD2A575A132F24323EF79AD2EFFE"
                + "BF9D597620");

        byte[] prvKeyNoLeadingZero = Util.h2b("B298F9A9874"
                + "F4F30A492429DE0CD2A575A132F24323EF79AD2EF"
                + "FEBF9D597620");

        /* invalid key, size is > ECC_MAXSIZE (128 with enable-all) */
        byte[] prvKeyInvalid = Util.h2b("30770201010420F8CF92"
                + "6BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                + "F88F974DAF568965C7A00A06082A8648CE3D0301"
                + "07A1440342000455BFF40F44509A3DCE9BB7F0C5"
                + "4DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "F7BDA9B236225FC75D7FB4");

        /* with leading zero, as expected */
        Ecc alice = new Ecc();
        alice.importPrivateOnCurve(prvKeyLeadingZero, null, "secp256r1");

        /* without leading zero, may encounter but not proper */
        alice = new Ecc();
        alice.importPrivateOnCurve(prvKeyNoLeadingZero, null, "secp256r1");

        /* try invalid key, expect failure */
        try {
            alice = new Ecc();
            alice.importPrivateOnCurve(prvKeyInvalid, null, "secp256r1");
            fail("Importing invalid ECC private key should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* try invalid curve, expect failure */
        try {
            alice = new Ecc();
            alice.importPrivateOnCurve(prvKeyLeadingZero, null, "BADCURVE");
            fail("Importing invalid ECC private curve should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }
    }

    @Test
    public void getEccCurveNameFromSpec()
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {

        /* generate key pair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec genSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(genSpec);

        KeyPair pair = kpg.genKeyPair();
        ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();

        ECParameterSpec spec = priv.getParams();

        String curveName = Ecc.getCurveName(spec);

        assertEquals(curveName, "SECP256R1");
    }

    @Test
    public void threadedEccSharedSecretTest() throws InterruptedException {

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();

        /* make sure alice and bob shared secret generation matches when done
         * in parallel over numThreads threads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int failed = 0;
                    Ecc alice = null;
                    Ecc bob = null;
                    Ecc aliceX963 = null;
                    Ecc alice2 = null;

                    try {
                        alice = new Ecc();
                        bob = new Ecc();
                        aliceX963 = new Ecc();

                        synchronized (rngLock) {
                            alice.makeKey(rng, 66);
                            bob.makeKey(rng, 66);
                        }
                        aliceX963.importX963(alice.exportX963());

                        byte[] sharedSecretA = alice.makeSharedSecret(bob);
                        byte[] sharedSecretB = bob.makeSharedSecret(aliceX963);

                        if (!Arrays.equals(sharedSecretA, sharedSecretB)) {
                            failed = 1;
                        }

                        if (failed == 0) {
                            alice2 = new Ecc();
                            alice2.importPrivate(alice.exportPrivate(),
                                alice.exportX963());

                            if (!Arrays.equals(sharedSecretA,
                                    alice2.makeSharedSecret(bob))) {
                                failed = 1;
                            }
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        failed = 1;

                    } finally {
                        alice.releaseNativeStruct();
                        alice2.releaseNativeStruct();
                        aliceX963.releaseNativeStruct();
                        bob.releaseNativeStruct();
                        latch.countDown();
                    }

                    if (failed == 1) {
                        results.add(1);
                    }
                    else {
                        results.add(0);
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* Look for any failures that happened */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in ECC shared secret thread test");
            }
        }
    }

    @Test
    public void threadedEccSignVerifyTest() throws InterruptedException {

        int numThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();

        final byte[] prvKey = Util.h2b("30770201010420F8CF92"
                + "6BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                + "F88F974DAF568965C7A00A06082A8648CE3D0301"
                + "07A1440342000455BFF40F44509A3DCE9BB7F0C5"
                + "4DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "F7BDA9B236225FC75D7FB4");

        final byte[] pubKey = Util.h2b("3059301306072A8648CE"
                + "3D020106082A8648CE3D0301070342000455BFF4"
                + "0F44509A3DCE9BB7F0C54DF5707BD4EC248E1980"
                + "EC5A4CA22403622C9BDAEFA2351243847616C656"
                + "9506CC01A9BDF6751A42F7BDA9B236225FC75D7FB4");

        final byte[] hash = "Everyone gets Friday off. ecc p".getBytes();

        /* Do sign/verify in each thread, in parallel across numThreads threads,
         * all operations should pass */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int failed = 0;
                    Ecc alice = null;
                    Ecc bob = null;
                    Ecc aliceX963 = null;
                    Ecc alice2 = null;

                    try {

                        alice = new Ecc();
                        bob = new Ecc();
                        aliceX963 = new Ecc();

                        /* import keys */
                        alice.privateKeyDecode(prvKey);
                        bob.publicKeyDecode(pubKey);

                        /* alice sign */
                        byte[] signature = null;
                        synchronized (rngLock) {
                            signature = alice.sign(hash, rng);
                        }

                        /* bob verify */
                        if (bob.verify(hash, signature) != true) {
                            failed = 1;
                        }

                        /* test alice verify with export/import pub key */
                        if (failed == 0) {
                            aliceX963.importX963(alice.exportX963());
                            if (aliceX963.verify(hash, signature) != true) {
                                failed = 1;
                            }
                        }

                        /* test alice verify with export/import priv key */
                        if (failed == 0) {
                            alice2 = new Ecc();
                            alice2.importPrivate(alice.exportPrivate(),
                                alice.exportX963());
                            if (alice2.verify(hash, signature) != true) {
                                failed = 1;
                            }
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        failed = 1;

                    } finally {
                        if (alice != null) {
                            alice.releaseNativeStruct();
                            alice = null;
                        }
                        if (alice2 != null) {
                            alice2.releaseNativeStruct();
                            alice2 = null;
                        }
                        if (aliceX963 != null) {
                            aliceX963.releaseNativeStruct();
                            aliceX963 = null;
                        }
                        if (bob != null) {
                            bob.releaseNativeStruct();
                            bob = null;
                        }
                        latch.countDown();
                    }

                    if (failed == 1) {
                        results.add(1);
                    }
                    else {
                        results.add(0);
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* Look for any failures that happened */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in ECC sign/verify thread test");
            }
        }
    }

    @Test
    public void getAllSupportedCurves() {

        /* Test that getAllSupportedCurves returns a non-null array */
        String[] curves = Ecc.getAllSupportedCurves();
        assertNotNull("getAllSupportedCurves should not return null", curves);

        /* Test that array is not empty */
        assertTrue("getAllSupportedCurves should return at least one curve",
            curves.length > 0);

        /* Test that all curve names are non-null and non-empty */
        for (String curveName : curves) {
            assertNotNull("Curve name should not be null", curveName);
            assertTrue("Curve name should not be empty",
                curveName.length() > 0);
        }

        /* Test that we get expected common curves */
        boolean foundSecp256r1 = false;
        for (String curveName : curves) {
            if ("SECP256R1".equals(curveName)) {
                foundSecp256r1 = true;
                break;
            }
        }
        assertTrue("Should find SECP256R1 in supported curves",
            foundSecp256r1);
    }

    @Test
    public void getCurveParametersValidCurves() {

        /* Get all supported curves first */
        String[] curves = Ecc.getAllSupportedCurves();
        assertNotNull("getAllSupportedCurves should not return null", curves);
        assertTrue("Should have at least one curve", curves.length > 0);

        /* Test getCurveParameters for each supported curve */
        for (String curveName : curves) {
            String[] params = Ecc.getCurveParameters(curveName);

            assertNotNull("getCurveParameters should not return null for " +
                curveName, params);
            assertEquals("getCurveParameters should return 7 parameters for " +
                curveName, 7, params.length);

            /* Verify all parameters are non-null hex strings */
            for (int i = 0; i < 6; i++) { /* first 6 are hex strings */
                assertNotNull("Parameter " + i + " should not be null for " +
                    curveName, params[i]);
                assertTrue("Parameter " + i + " should not be empty for " +
                    curveName, params[i].length() > 0);

                /* Verify it's valid hex using regex */
                assertTrue("Parameter " + i +
                    " is not a valid hex string for " +
                    curveName, params[i].matches("^[0-9a-fA-F]+$"));
            }

            /* Verify cofactor (last parameter) is a valid integer */
            assertNotNull("Cofactor should not be null for " + curveName,
                params[6]);
            assertTrue("Cofactor should not be empty for " + curveName,
                params[6].length() > 0);

            Integer.parseInt(params[6]); /* should not throw */
        }
    }

    @Test
    public void getCurveParametersSecp256r1() {

        /* Test specific known curve parameters for SECP256R1 */
        String[] params = Ecc.getCurveParameters("SECP256R1");

        assertNotNull("getCurveParameters should not return null", params);
        assertEquals("Should return 7 parameters", 7, params.length);

        /* Verify we can parse all parameters as BigIntegers:
         * params[0] - a (prime)
         * params[1] - b
         * params[2] - p (order)
         * params[3] - n (order)
         * params[4] - Gx (generator x)
         * params[5] - Gy (generator y)
         * params[6] - cofactor (int) */
        java.math.BigInteger p = new java.math.BigInteger(params[0], 16);
        java.math.BigInteger a = new java.math.BigInteger(params[1], 16);
        java.math.BigInteger b = new java.math.BigInteger(params[2], 16);
        java.math.BigInteger n = new java.math.BigInteger(params[3], 16);
        java.math.BigInteger gx = new java.math.BigInteger(params[4], 16);
        java.math.BigInteger gy = new java.math.BigInteger(params[5], 16);
        int cofactor = Integer.parseInt(params[6]);

        /* Verify reasonable field size for secp256r1 (should be 256 bits) */
        assertEquals("SECP256R1 prime should be 256 bits", 256, p.bitLength());

        /* Verify cofactor is 1 for secp256r1 */
        assertEquals("SECP256R1 cofactor should be 1", 1, cofactor);

        /* Verify generator point coordinates are reasonable size */
        assertTrue("Generator X should be positive",
            gx.compareTo(java.math.BigInteger.ZERO) > 0);
        assertTrue("Generator Y should be positive",
            gy.compareTo(java.math.BigInteger.ZERO) > 0);
        assertTrue("Generator X should be less than prime",
            gx.compareTo(p) < 0);
        assertTrue("Generator Y should be less than prime",
            gy.compareTo(p) < 0);
    }

    @Test
    public void getCurveParametersInvalidCurve() {

        /* Test with invalid curve name */
        try {
            Ecc.getCurveParameters("INVALID_CURVE_NAME");
            fail("getCurveParameters should throw exception for invalid curve");
        } catch (WolfCryptException e) {
            /* Expected exception */
        }

        /* Test with null curve name */
        try {
            Ecc.getCurveParameters(null);
            fail("getCurveParameters should throw exception for null curve");
        } catch (IllegalArgumentException e) {
            /* Expected exception for null input */
        }

        /* Test with clearly invalid curve names */
        try {
            Ecc.getCurveParameters("NOT_A_REAL_CURVE_NAME_12345");
            fail("getCurveParameters should throw exception for " +
                 "clearly invalid curve");
        } catch (WolfCryptException e) {
            /* Expected exception */
        }

        try {
            Ecc.getCurveParameters("XYZ_FAKE_CURVE");
            fail("getCurveParameters should throw exception for fake curve");
        } catch (WolfCryptException e) {
            /* Expected exception */
        }
    }

    @Test
    public void getCurveParametersCaseInsensitive() {

        /* Test that curve name lookup is case insensitive */
        String[] paramsUpper = Ecc.getCurveParameters("SECP256R1");
        String[] paramsLower = Ecc.getCurveParameters("secp256r1");
        String[] paramsMixed = Ecc.getCurveParameters("SeCp256R1");

        assertNotNull("Upper case should work", paramsUpper);
        assertNotNull("Lower case should work", paramsLower);
        assertNotNull("Mixed case should work", paramsMixed);

        /* All should return the same parameters */
        assertArrayEquals("Upper and lower case should return same parameters",
            paramsUpper, paramsLower);
        assertArrayEquals("Upper and mixed case should return same parameters",
            paramsUpper, paramsMixed);
    }

    @Test
    public void threadedGetAllSupportedCurves() throws InterruptedException {

        /* Test that getAllSupportedCurves is thread-safe */
        int numThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<String[]> results =
            new LinkedBlockingQueue<>();

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    try {
                        String[] curves = Ecc.getAllSupportedCurves();
                        results.add(curves);
                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(null);
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        /* Wait for all threads to complete */
        latch.await();

        /* Verify all results are consistent */
        String[] firstResult = results.poll();
        assertNotNull("First result should not be null", firstResult);

        while (!results.isEmpty()) {
            String[] result = results.poll();
            assertNotNull("Result should not be null", result);
            assertArrayEquals("All threads should return same curve list",
                firstResult, result);
        }
    }

    @Test
    public void threadedGetCurveParameters() throws InterruptedException {

        /* Test that getCurveParameters is thread-safe */
        int numThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<String[]> results =
            new LinkedBlockingQueue<>();
        final String testCurveName = "SECP256R1";

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    try {
                        String[] params = Ecc.getCurveParameters(testCurveName);
                        results.add(params);
                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(null);
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        /* Wait for all threads to complete */
        latch.await();

        /* Verify all results are consistent */
        String[] firstResult = results.poll();
        assertNotNull("First result should not be null", firstResult);

        while (!results.isEmpty()) {
            String[] result = results.poll();
            assertNotNull("Result should not be null", result);
            assertArrayEquals("All threads should return same parameters",
                             firstResult, result);
        }
    }
}

