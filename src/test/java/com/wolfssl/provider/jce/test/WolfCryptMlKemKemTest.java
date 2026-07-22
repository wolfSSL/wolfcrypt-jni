/* WolfCryptMlKemKemTest.java
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

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.security.Security;
import java.security.Provider;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.InvalidKeyException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.SecretKey;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit tests for the wolfJCE ML-KEM Key Encapsulation Mechanism, including
 * interop with the JDK's built-in (SunJCE) ML-KEM.
 *
 * The javax.crypto.KEM API is only present on JDK 21+. To keep this test
 * source compilable on Java 8, all KEM API access is done via reflection and
 * the tests skip when the KEM API or wolfJCE's KEM service is unavailable.
 */
public class WolfCryptMlKemKemTest {

    private static boolean wolfKemEnabled = false;
    private static boolean sunMlKemAvailable = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {

        boolean kemApiPresent;

        System.out.println("JCE WolfCryptMlKemKemTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        try {
            Class.forName("javax.crypto.KEM");
            kemApiPresent = true;
        } catch (Throwable t) {
            kemApiPresent = false;
        }

        Provider p = Security.getProvider("wolfJCE");
        if (kemApiPresent && p != null &&
            p.getService("KEM", "ML-KEM") != null) {
            wolfKemEnabled = true;
        }
        else {
            System.out.println("ML-KEM KEM test skipped " +
                "(KEM API present: " + kemApiPresent + ")");
        }

        /* Detect JDK built-in ML-KEM for interop tests. */
        try {
            KeyPairGenerator.getInstance("ML-KEM-768", "SunJCE");
            sunMlKemAvailable = true;
        } catch (Throwable t) {
            sunMlKemAvailable = false;
        }
    }

    private void assumeWolfKem() {
        Assume.assumeTrue("wolfJCE ML-KEM KEM not available", wolfKemEnabled);
    }

    private void assumeInterop() {
        assumeWolfKem();
        Assume.assumeTrue("JDK built-in ML-KEM not available",
            sunMlKemAvailable);
    }

    /**
     * Reflection helpers for javax.crypto.KEM (JDK 21+)
     */
    private static Object kemGetInstance(String alg, String provider)
        throws Exception {

        Class<?> kemCls = Class.forName("javax.crypto.KEM");
        Method getInstance = kemCls.getMethod("getInstance", String.class,
            String.class);

        return getInstance.invoke(null, alg, provider);
    }

    /* Encapsulate to 'pub' using KEM instance 'kem'. Returns
     * {sharedSecretBytes, ciphertext}. */
    private static byte[][] encapsulate(Object kem, PublicKey pub)
        throws Exception {

        Object encapsulator = kem.getClass()
            .getMethod("newEncapsulator", PublicKey.class).invoke(kem, pub);
        Object encapsulated = encapsulator.getClass()
            .getMethod("encapsulate").invoke(encapsulator);
        SecretKey key = (SecretKey) encapsulated.getClass()
            .getMethod("key").invoke(encapsulated);
        byte[] ct = (byte[]) encapsulated.getClass()
            .getMethod("encapsulation").invoke(encapsulated);

        return new byte[][] { key.getEncoded(), ct };
    }

    /* Decapsulate 'ct' using 'priv' and KEM instance 'kem'; returns shared
     * secret bytes. */
    private static byte[] decapsulate(Object kem, PrivateKey priv, byte[] ct)
        throws Exception {

        Object decapsulator = kem.getClass()
            .getMethod("newDecapsulator", PrivateKey.class).invoke(kem, priv);
        SecretKey key = (SecretKey) decapsulator.getClass()
            .getMethod("decapsulate", byte[].class)
            .invoke(decapsulator, (Object) ct);

        return key.getEncoded();
    }

    /* Reflectively create a KEM.Encapsulator for 'pub'. */
    private static Object newEncapsulator(Object kem, PublicKey pub)
        throws Exception {

        return kem.getClass().getMethod("newEncapsulator", PublicKey.class)
            .invoke(kem, pub);
    }

    /* Reflectively create a KEM.Decapsulator for 'priv'. */
    private static Object newDecapsulator(Object kem, PrivateKey priv)
        throws Exception {

        return kem.getClass().getMethod("newDecapsulator", PrivateKey.class)
            .invoke(kem, priv);
    }

    /* Full round trip: encapsulate with encProvider, decapsulate with
     * decProvider. Assert the shared secrets match and are 32 bytes. */
    private void roundTrip(KeyPair kp, String encProvider, String decProvider)
        throws Exception {

        Object encKem = kemGetInstance("ML-KEM", encProvider);
        byte[][] e = encapsulate(encKem, kp.getPublic());
        byte[] secretEnc = e[0];
        byte[] ct = e[1];

        Object decKem = kemGetInstance("ML-KEM", decProvider);
        byte[] secretDec = decapsulate(decKem, kp.getPrivate(), ct);

        assertEquals(32, secretEnc.length);
        assertArrayEquals("secret mismatch enc=" + encProvider + " dec=" +
            decProvider, secretEnc, secretDec);
    }

    @Test
    public void testWolfJceKemRoundTrip() throws Exception {
        assumeWolfKem();

        String[] names = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
        for (String name : names) {
            KeyPair kp = KeyPairGenerator.getInstance(name, "wolfJCE")
                .generateKeyPair();
            roundTrip(kp, "wolfJCE", "wolfJCE");
        }
    }

    @Test
    public void testInteropWolfKeyWithSunKem() throws Exception {
        assumeInterop();

        for (String set : new String[] {
                "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" }) {
            KeyPair kp = KeyPairGenerator.getInstance(set, "wolfJCE")
                .generateKeyPair();
            /* wolfJCE-generated key: encapsulate with SunJCE, decapsulate
             * with wolfJCE, and the reverse. */
            roundTrip(kp, "SunJCE", "wolfJCE");
            roundTrip(kp, "wolfJCE", "SunJCE");
        }
    }

    @Test
    public void testInteropSunKeyWithWolfKem() throws Exception {
        assumeInterop();

        for (String set : new String[] {
                "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" }) {
            KeyPair kp = KeyPairGenerator.getInstance(set, "SunJCE")
                .generateKeyPair();
            /* SunJCE-generated key: encapsulate with wolfJCE, decapsulate
             * with SunJCE, and the reverse. */
            roundTrip(kp, "wolfJCE", "SunJCE");
            roundTrip(kp, "SunJCE", "wolfJCE");
        }
    }

    @Test
    public void testInteropCrossKeyFactory() throws Exception {
        assumeInterop();

        /* Generate with SunJCE, re-import both keys via wolfJCE KeyFactory,
         * then run a KEM round trip with SunJCE on the decapsulation side. */
        KeyPair sun = KeyPairGenerator.getInstance("ML-KEM-1024", "SunJCE")
            .generateKeyPair();

        KeyFactory wkf = KeyFactory.getInstance("ML-KEM", "wolfJCE");
        PublicKey wpub = wkf.generatePublic(
            new X509EncodedKeySpec(sun.getPublic().getEncoded()));
        PrivateKey wpriv = wkf.generatePrivate(
            new PKCS8EncodedKeySpec(sun.getPrivate().getEncoded()));

        roundTrip(new KeyPair(wpub, wpriv), "wolfJCE", "SunJCE");
    }

    @Test
    public void testInteropEncodingByteEquality() throws Exception {
        assumeInterop();

        /* Force expandedKey on both providers so the comparison is
         * deterministic across JDK versions (newer JDKs default to seed). */
        String prop = "jdk.mlkem.pkcs8.encoding";
        String saved = System.getProperty(prop);
        System.setProperty(prop, "expandedKey");

        try {
            String[] sets = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
            for (String set : sets) {
                /* wolfJCE-generated key must encode the same as SunJCE
                 * produces for that same key. */
                KeyPair w = KeyPairGenerator.getInstance(set, "wolfJCE")
                    .generateKeyPair();
                KeyFactory sunKf = KeyFactory.getInstance("ML-KEM", "SunJCE");
                PublicKey sPub = sunKf.generatePublic(
                    new X509EncodedKeySpec(w.getPublic().getEncoded()));
                PrivateKey sPriv = sunKf.generatePrivate(
                    new PKCS8EncodedKeySpec(w.getPrivate().getEncoded()));
                assertArrayEquals(w.getPublic().getEncoded(),
                    sPub.getEncoded());
                assertArrayEquals(w.getPrivate().getEncoded(),
                    sPriv.getEncoded());

                /* and the reverse: a SunJCE key re-encodes identically via
                 * wolfJCE. */
                KeyPair s = KeyPairGenerator.getInstance(set, "SunJCE")
                    .generateKeyPair();
                KeyFactory wKf = KeyFactory.getInstance("ML-KEM", "wolfJCE");
                PublicKey wPub = wKf.generatePublic(
                    new X509EncodedKeySpec(s.getPublic().getEncoded()));
                PrivateKey wPriv = wKf.generatePrivate(
                    new PKCS8EncodedKeySpec(s.getPrivate().getEncoded()));
                assertArrayEquals(s.getPublic().getEncoded(),
                    wPub.getEncoded());
                assertArrayEquals(s.getPrivate().getEncoded(),
                    wPriv.getEncoded());
            }
        } finally {
            if (saved == null) {
                System.clearProperty(prop);
            }
            else {
                System.setProperty(prop, saved);
            }
        }
    }

    @Test
    public void testKemSubRangeSecret() throws Exception {
        assumeWolfKem();

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair();
        Object kem = kemGetInstance("ML-KEM", "wolfJCE");

        Object enc = newEncapsulator(kem, kp.getPublic());
        Object encd = enc.getClass()
            .getMethod("encapsulate", int.class, int.class, String.class)
            .invoke(enc, 0, 16, "AES");
        SecretKey k1 = (SecretKey) encd.getClass().getMethod("key")
            .invoke(encd);
        byte[] ct = (byte[]) encd.getClass().getMethod("encapsulation")
            .invoke(encd);
        assertEquals(16, k1.getEncoded().length);
        assertEquals("AES", k1.getAlgorithm());

        Object dec = newDecapsulator(kem, kp.getPrivate());
        SecretKey k2 = (SecretKey) dec.getClass().getMethod("decapsulate",
            byte[].class, int.class, int.class, String.class)
            .invoke(dec, ct, 0, 16, "AES");
        assertArrayEquals(k1.getEncoded(), k2.getEncoded());
    }

    @Test
    public void testKemInvalidRangeRejected() throws Exception {
        assumeWolfKem();

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair();
        Object kem = kemGetInstance("ML-KEM", "wolfJCE");
        Object enc = newEncapsulator(kem, kp.getPublic());
        Method m = enc.getClass()
            .getMethod("encapsulate", int.class, int.class, String.class);

        /* 'to' beyond the 32-byte shared secret */
        try {
            m.invoke(enc, 0, 33, "Generic");
            fail("Expected IndexOutOfBoundsException");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IndexOutOfBoundsException);
        }

        /* null algorithm */
        try {
            m.invoke(enc, 0, 16, null);
            fail("Expected NullPointerException");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof NullPointerException);
        }
    }

    @Test
    public void testKemDecapsulateBadCiphertext() throws Exception {
        assumeWolfKem();

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair();
        Object kem = kemGetInstance("ML-KEM", "wolfJCE");
        Object dec = newDecapsulator(kem, kp.getPrivate());
        Method m = dec.getClass().getMethod("decapsulate", byte[].class);

        try {
            m.invoke(dec, (Object) new byte[10]);
            fail("Expected DecapsulateException");
        } catch (InvocationTargetException e) {
            assertEquals("javax.crypto.DecapsulateException",
                e.getCause().getClass().getName());
        }
    }

    @Test
    public void testKemSeedOnlyForeignKeyDecapsulates() throws Exception {
        assumeWolfKem();

        /* Produce a seed-form PKCS#8 via wolfJCE, then wrap it in a foreign
         * (non-wolfJCE) PrivateKey so the KEM decapsulator must parse and
         * expand the seed itself rather than downcast. */
        String prop = "jdk.mlkem.pkcs8.encoding";
        String saved = System.getProperty(prop);
        KeyPair kp;
        byte[] tmp;
        System.setProperty(prop, "seed");

        try {
            kp = KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
                .generateKeyPair();
            tmp = kp.getPrivate().getEncoded();

        } finally {
            if (saved == null) {
                System.clearProperty(prop);
            }
            else {
                System.setProperty(prop, saved);
            }
        }

        final byte[] seedP8 = tmp;

        PrivateKey foreign = new PrivateKey() {
            public String getAlgorithm() { return "ML-KEM"; }
            public String getFormat() { return "PKCS#8"; }
            public byte[] getEncoded() { return seedP8.clone(); }
        };

        Object kem = kemGetInstance("ML-KEM", "wolfJCE");
        byte[][] e = encapsulate(kem, kp.getPublic());
        byte[] ssDec = decapsulate(kem, foreign, e[1]);
        assertArrayEquals(e[0], ssDec);
    }

    @Test
    public void testKemLevelMismatchRejected() throws Exception {
        assumeWolfKem();

        KeyPair kp768 = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair();
        /* The ML-KEM-512-locked KEM must reject a 768 key. */
        Object kem512 = kemGetInstance("ML-KEM-512", "wolfJCE");

        try {
            newEncapsulator(kem512, kp768.getPublic());
            fail("Expected InvalidKeyException");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof InvalidKeyException);
        }
    }
}
