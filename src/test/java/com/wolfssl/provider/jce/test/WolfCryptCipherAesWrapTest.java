/* WolfCryptCipherAesWrapTest.java
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
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.AesKeyWrap;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * Test AES Key Wrap (RFC 3394 / NIST SP 800-38F KW) Cipher services:
 * "AESWrap", "AES/KW/NoPadding", "AESWrap_128/192/256",
 * "AES/KW/PKCS5Padding", and interop.
 */
public class WolfCryptCipherAesWrapTest {

    private static final String jceProvider = "wolfJCE";

    /* Native wolfSSL built with HAVE_AES_KEYWRAP */
    private static boolean aesWrapEnabled = false;

    /* Interop provider, first of SunJCE, AndroidOpenSSL, BC found */
    private static String interopProvider = null;

    /* Interop provider offers a Cipher named "AESWrap" */
    private static boolean interopHasAesWrap = false;

    /* Interop Cipher name that accepts ENCRYPT_MODE plus an 8-byte
     * IvParameterSpec or null if interop provider supports neither. */
    private static String interopModernName = null;

    /* Interop provider offers "AES/KW/PKCS5Padding" (JDK 17+) */
    private static boolean interopHasKwPkcs5 = false;

    /* One static SecureRandom to share */
    private static SecureRandom secureRandom = new SecureRandom();

    /* RFC 3394 Section 4 test vectors */
    private static final byte[] KEK_128 = Util.h2b(
        "000102030405060708090A0B0C0D0E0F");
    private static final byte[] KEK_192 = Util.h2b(
        "000102030405060708090A0B0C0D0E0F1011121314151617");
    private static final byte[] KEK_256 = Util.h2b(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

    private static final byte[] DATA_128 = Util.h2b(
        "00112233445566778899AABBCCDDEEFF");
    private static final byte[] DATA_192 = Util.h2b(
        "00112233445566778899AABBCCDDEEFF0001020304050607");
    private static final byte[] DATA_256 = Util.h2b(
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

    /* 4.1 Wrap 128 bits of Key Data with a 128-bit KEK */
    private static final byte[] WRAP_128_KEK128 = Util.h2b(
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    /* 4.2 Wrap 128 bits of Key Data with a 192-bit KEK */
    private static final byte[] WRAP_128_KEK192 = Util.h2b(
        "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D");
    /* 4.3 Wrap 128 bits of Key Data with a 256-bit KEK */
    private static final byte[] WRAP_128_KEK256 = Util.h2b(
        "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");
    /* 4.4 Wrap 192 bits of Key Data with a 192-bit KEK */
    private static final byte[] WRAP_192_KEK192 = Util.h2b(
        "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2");
    /* 4.5 Wrap 192 bits of Key Data with a 256-bit KEK */
    private static final byte[] WRAP_192_KEK256 = Util.h2b(
        "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1");
    /* 4.6 Wrap 256 bits of Key Data with a 256-bit KEK */
    private static final byte[] WRAP_256_KEK256 = Util.h2b(
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43B" +
        "FB988B9B7A02DD21");

    /* RFC 3394 default IV (integrity check value) */
    private static final byte[] DEFAULT_IV = Util.h2b("A6A6A6A6A6A6A6A6");

    /* Alternative 8-byte IV */
    private static final byte[] ALT_IV = Util.h2b("0011223344556677");

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptCipher AES Key Wrap Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider(jceProvider);
        assertNotNull(p);

        aesWrapEnabled = FeatureDetect.AesKeyWrapEnabled();
        if (!aesWrapEnabled) {
            System.out.println("AES Key Wrap not compiled in, " +
                "WolfCryptCipherAesWrapTest tests will skip");
        }

        /* try to set up interop provider, if available */
        if (Security.getProvider("SunJCE") != null) {
            interopProvider = "SunJCE";
        }
        else if (Security.getProvider("AndroidOpenSSL") != null) {
            interopProvider = "AndroidOpenSSL";
        }
        else if (Security.getProvider("BC") != null) {
            interopProvider = "BC";
        }

        if (interopProvider != null) {
            SecretKeySpec probeKek = new SecretKeySpec(KEK_128, "AES");

            /* Classic "AESWrap" name, WRAP/UNWRAP only on JDK 8 */
            try {
                Cipher c = Cipher.getInstance("AESWrap", interopProvider);
                c.init(Cipher.WRAP_MODE, probeKek);
                c.wrap(new SecretKeySpec(DATA_128, "AES"));
                interopHasAesWrap = true;
            } catch (Exception e) {
                /* Conscrypt has no key wrap Cipher at all */
            }

            /* Name that supports ENCRYPT_MODE and an 8-byte IV */
            for (String name : new String[] {"AES/KW/NoPadding", "AESWrap"}) {
                try {
                    Cipher c = Cipher.getInstance(name, interopProvider);
                    c.init(Cipher.ENCRYPT_MODE, probeKek,
                        new IvParameterSpec(ALT_IV));
                    c.doFinal(DATA_128);
                    interopModernName = name;
                    break;
                } catch (Exception e) {
                    /* JDK 8 rejects params and non-wrap opmodes */
                }
            }

            /* JDK 17 SunJCE pads AES/KW/PKCS5Padding to 16-byte blocks,
             * JDK 21+ to 8-byte blocks like wolfJCE. Only the latter is
             * interoperable, 16 bytes must wrap to 32 not 40. */
            try {
                Cipher c = Cipher.getInstance("AES/KW/PKCS5Padding",
                    interopProvider);
                c.init(Cipher.ENCRYPT_MODE, probeKek);
                interopHasKwPkcs5 = (c.doFinal(new byte[16]).length == 32);
            } catch (Exception e) {
                /* only JDK 17+ SunJCE has this */
            }
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("AES Key Wrap not compiled in", aesWrapEnabled);
    }

    private void assumeAes128() {
        assumeEnabled();
        Assume.assumeTrue("AES-128 not compiled in",
            FeatureDetect.Aes128Enabled());
    }

    private static SecretKeySpec aesKey(byte[] raw) {
        return new SecretKeySpec(raw, "AES");
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        secureRandom.nextBytes(b);
        return b;
    }

    /**
     * Names SunJCE (JDK 8 and 17+), Bouncy Castle, and NIST OID callers
     * expect to resolve, plus transformation forms that exercise
     * engineSetMode()/engineSetPadding().
     */
    private static List<String> expectedServiceNames() {
        List<String> names = new ArrayList<String>();

        names.add("AESWrap");
        names.add("AESWRAP");
        names.add("aeswrap");
        names.add("AESKW");
        names.add("AES/KW/NoPadding");
        names.add("AESWrap/ECB/NoPadding");
        names.add("AESWrap/KW/NoPadding");
        names.add("AES/KW/PKCS5Padding");
        names.add("AESWrap/KW/PKCS5Padding");
        names.add("AESWrap/ECB/PKCS5Padding");

        if (FeatureDetect.Aes128Enabled()) {
            names.add("AESWrap_128");
            names.add("AESWrap_128/KW/NoPadding");
            names.add("AES_128/KW/NoPadding");
            names.add("2.16.840.1.101.3.4.1.5");
            names.add("OID.2.16.840.1.101.3.4.1.5");
            names.add("AES_128/KW/PKCS5Padding");
        }
        if (FeatureDetect.Aes192Enabled()) {
            names.add("AESWrap_192");
            names.add("AES_192/KW/NoPadding");
            names.add("2.16.840.1.101.3.4.1.25");
            names.add("OID.2.16.840.1.101.3.4.1.25");
            names.add("AES_192/KW/PKCS5Padding");
        }
        if (FeatureDetect.Aes256Enabled()) {
            names.add("AESWrap_256");
            names.add("AES_256/KW/NoPadding");
            names.add("2.16.840.1.101.3.4.1.45");
            names.add("OID.2.16.840.1.101.3.4.1.45");
            names.add("AES_256/KW/PKCS5Padding");
        }

        return names;
    }

    /** Cipher names and aliases the provider registered for AES Key Wrap */
    private static List<String> registeredKeyWrapNames(Provider p) {
        List<String> names = new ArrayList<String>();
        final String cipherPrefix = "Cipher.";
        final String aliasPrefix = "Alg.Alias.Cipher.";

        for (Object k : p.keySet()) {
            String key = String.valueOf(k);
            String name = null;
            String impl = null;

            if (key.startsWith(cipherPrefix)) {
                name = key.substring(cipherPrefix.length());
                if (name.contains(" ")) {
                    /* skip attribute entries */
                    continue;
                }
                impl = p.getProperty(key);
            }
            else if (key.startsWith(aliasPrefix)) {
                name = key.substring(aliasPrefix.length());
                /* resolve alias target class, getService() is
                 * case-insensitive unlike getProperty() */
                Provider.Service svc =
                    p.getService("Cipher", p.getProperty(key));
                impl = (svc == null) ? null : svc.getClassName();
            }

            if (name != null && impl != null &&
                impl.contains("WolfCryptCipher$wc") && impl.contains("KW")) {
                names.add(name);
            }
        }

        return names;
    }

    /** One RFC 3394 vector through wrap/unwrap and encrypt/decrypt */
    private void runKat(byte[] kek, byte[] data, byte[] expected)
        throws Exception {

        SecretKeySpec kekSpec = aesKey(kek);

        /* WRAP_MODE / UNWRAP_MODE */
        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, kekSpec);
        byte[] wrapped = wrap.wrap(aesKey(data));
        assertArrayEquals("wrap() does not match RFC 3394 vector",
            expected, wrapped);

        Cipher unwrap = Cipher.getInstance("AESWrap", jceProvider);
        unwrap.init(Cipher.UNWRAP_MODE, kekSpec);
        Key k = unwrap.unwrap(expected, "AES", Cipher.SECRET_KEY);
        assertNotNull(k);
        assertEquals("AES", k.getAlgorithm());
        assertTrue(k instanceof SecretKey);
        assertArrayEquals("unwrap() does not match RFC 3394 vector",
            data, k.getEncoded());

        /* ENCRYPT_MODE / DECRYPT_MODE, one shot */
        Cipher enc = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, kekSpec);
        assertEquals(expected.length, enc.getOutputSize(data.length));
        assertArrayEquals("doFinal() encrypt does not match vector",
            expected, enc.doFinal(data));

        Cipher dec = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        dec.init(Cipher.DECRYPT_MODE, kekSpec);
        assertEquals(data.length, dec.getOutputSize(expected.length));
        assertArrayEquals("doFinal() decrypt does not match vector",
            data, dec.doFinal(expected));

        /* ENCRYPT_MODE / DECRYPT_MODE, update() then doFinal() */
        byte[] part = enc.update(data, 0, 8);
        assertTrue("update() must buffer, not emit output",
            part == null || part.length == 0);
        part = enc.update(data, 8, data.length - 8);
        assertTrue(part == null || part.length == 0);
        assertArrayEquals("update()+doFinal() encrypt does not match",
            expected, enc.doFinal());

        part = dec.update(expected, 0, 8);
        assertTrue(part == null || part.length == 0);
        assertArrayEquals("update()+doFinal() decrypt does not match",
            data, dec.doFinal(expected, 8, expected.length - 8));
    }

    @Test
    public void testServiceRegistrationMatchesFeatureDetect()
        throws NoSuchProviderException, NoSuchPaddingException {

        Provider p = Security.getProvider(jceProvider);
        assertNotNull(p);

        for (String name : new String[] { "AESWrap", "AES/KW/NoPadding",
            "AESKW", "AES/KW/PKCS5Padding", "AESWrap_128",
            "AESWrap_192", "AESWrap_256", "2.16.840.1.101.3.4.1.5" }) {

            boolean registered;
            try {
                Cipher.getInstance(name, jceProvider);
                registered = true;
            } catch (NoSuchAlgorithmException e) {
                registered = false;
            }

            if (aesWrapEnabled) {
                boolean expected;
                if (name.equals("AESWrap_128") ||
                    name.equals("2.16.840.1.101.3.4.1.5")) {
                    expected = FeatureDetect.Aes128Enabled();
                }
                else if (name.equals("AESWrap_192")) {
                    expected = FeatureDetect.Aes192Enabled();
                }
                else if (name.equals("AESWrap_256")) {
                    expected = FeatureDetect.Aes256Enabled();
                }
                else {
                    expected = true;
                }
                assertEquals(name + " registration mismatch", expected,
                    registered);
            }
            else {
                assertFalse(name + " must not be registered without " +
                    "HAVE_AES_KEYWRAP", registered);
            }
        }

        if (aesWrapEnabled) {
            assertNotNull("Cipher.AESWrap service expected with " +
                "HAVE_AES_KEYWRAP", p.getService("Cipher", "AESWrap"));
        }
        else {
            assertNull("no Cipher.AESWrap service expected without " +
                "HAVE_AES_KEYWRAP", p.getService("Cipher", "AESWrap"));
        }
    }

    @Test
    public void testGetCipherFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException {
        assumeEnabled();

        for (String name : expectedServiceNames()) {
            Cipher c = Cipher.getInstance(name, jceProvider);
            assertNotNull(name, c);
            assertEquals("provider for " + name, jceProvider,
                c.getProvider().getName());
            assertEquals("block size for " + name,
                AesKeyWrap.KEYWRAP_BLOCK_SIZE, c.getBlockSize());
        }

        /* With wolfJCE at position 1, the plain lookup resolves to us */
        assertEquals(jceProvider,
            Cipher.getInstance("AESWrap").getProvider().getName());
        assertEquals(jceProvider,
            Cipher.getInstance("AES/KW/NoPadding").getProvider().getName());

        /* Unsupported mode / padding combinations must not resolve */
        String[] bad = {
            "AESWrap/CBC/NoPadding",
            "AESWrap/GCM/NoPadding",
            "AESWrap/ECB/PKCS7Padding",
            "AESWrap/ECB/ISO10126Padding",
            "AES/KW/ISO10126Padding",
            "AESWrapPad",
            "AES/KWP/NoPadding"
        };
        for (String name : bad) {
            try {
                Cipher.getInstance(name, jceProvider);
                fail("Cipher.getInstance(" + name + ") should fail");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testRegisteredNamesAreExpected() throws Exception {
        assumeAes128();

        Provider p = Security.getProvider(jceProvider);
        assertNotNull(p);

        Set<String> expected = new HashSet<String>();
        for (String name : expectedServiceNames()) {
            expected.add(name.toUpperCase());
        }

        List<String> registered = registeredKeyWrapNames(p);
        assertFalse("provider registered no AES Key Wrap Cipher entries",
            registered.isEmpty());

        for (String name : registered) {
            assertTrue("provider registers AES Key Wrap name '" + name +
                "' that expectedServiceNames() does not list",
                expected.contains(name.toUpperCase()));

            Cipher c = Cipher.getInstance(name, jceProvider);
            assertEquals("block size for registered name " + name,
                AesKeyWrap.KEYWRAP_BLOCK_SIZE, c.getBlockSize());
        }

        /* every expected plain registration must be registered */
        Set<String> registeredUpper = new HashSet<String>();
        for (String name : registered) {
            registeredUpper.add(name.toUpperCase());
        }
        for (String name : expectedServiceNames()) {
            boolean transformation = name.startsWith("AESWrap/") ||
                name.startsWith("AESWrap_128/");
            if (!transformation) {
                assertTrue("expected name '" + name + "' is not a " +
                    "registered service or alias",
                    registeredUpper.contains(name.toUpperCase()));
            }
        }
    }

    @Test
    public void testGetBlockSizeAndOutputSize() throws Exception {
        assumeAes128();

        Cipher c = Cipher.getInstance("AESWrap", jceProvider);
        assertEquals(8, c.getBlockSize());

        try {
            c.getOutputSize(16);
            fail("getOutputSize() before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        c.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        assertEquals(24, c.getOutputSize(16));
        assertEquals(40, c.getOutputSize(32));
        assertEquals(8, c.getOutputSize(0));

        c.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        assertEquals(24, c.getOutputSize(16));
        c.update(new byte[8]);
        assertEquals("buffered data must count", 24, c.getOutputSize(8));
        c.doFinal(new byte[8]);

        c.init(Cipher.UNWRAP_MODE, aesKey(KEK_128));
        assertEquals(16, c.getOutputSize(24));
        assertEquals(0, c.getOutputSize(8));
        assertEquals(0, c.getOutputSize(0));

        c.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        assertEquals(32, c.getOutputSize(40));

        /* PKCS5Padding pads up to the next 8-byte boundary, then + 8 */
        Cipher p = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        p.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        assertEquals(32, p.getOutputSize(16));
        assertEquals(32, p.getOutputSize(17));
        assertEquals(32, p.getOutputSize(23));
        assertEquals(40, p.getOutputSize(24));
        assertEquals(16, p.getOutputSize(0));
        assertEquals(24, p.getOutputSize(8));

        p.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        assertEquals(24, p.getOutputSize(32));
    }

    @Test
    public void testRfc3394Vector41() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());
        runKat(KEK_128, DATA_128, WRAP_128_KEK128);
    }

    @Test
    public void testRfc3394Vector42() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes192Enabled());
        runKat(KEK_192, DATA_128, WRAP_128_KEK192);
    }

    @Test
    public void testRfc3394Vector43() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());
        runKat(KEK_256, DATA_128, WRAP_128_KEK256);
    }

    @Test
    public void testRfc3394Vector44() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes192Enabled());
        runKat(KEK_192, DATA_192, WRAP_192_KEK192);
    }

    @Test
    public void testRfc3394Vector45() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());
        runKat(KEK_256, DATA_192, WRAP_192_KEK256);
    }

    @Test
    public void testRfc3394Vector46() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());
        runKat(KEK_256, DATA_256, WRAP_256_KEK256);
    }

    @Test
    public void testTransformationForms() throws Exception {
        assumeAes128();

        SecretKeySpec kek = aesKey(KEK_128);
        SecretKeySpec key20 = new SecretKeySpec(randomBytes(20), "RAW");

        /* NoPadding forms all match the RFC 3394 vector, in any case */
        for (String name : new String[] { "AESWrap/ECB/NoPadding",
            "AESWrap/KW/NoPadding", "AESWrap_128/KW/NoPadding",
            "aeswrap/kw/nopadding", "AESWrap_128/ecb/NOPADDING" }) {

            Cipher c = Cipher.getInstance(name, jceProvider);
            c.init(Cipher.WRAP_MODE, kek);
            assertArrayEquals(name, WRAP_128_KEK128, c.wrap(aesKey(DATA_128)));

            /* and reject a 20 byte key, no padding was selected */
            try {
                c.wrap(key20);
                fail(name + " should reject a 20 byte key");
            } catch (IllegalBlockSizeException e) {
                /* expected */
            }
        }

        /* PKCS5Padding via transformation equals AES/KW/PKCS5Padding */
        Cipher ref = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        ref.init(Cipher.WRAP_MODE, kek);
        byte[] expected = ref.wrap(key20);
        assertEquals(32, expected.length);

        for (String name : new String[] { "AESWrap/KW/PKCS5Padding",
            "AESWrap/ECB/PKCS5Padding", "AESWrap/kw/pkcs5padding" }) {

            Cipher c = Cipher.getInstance(name, jceProvider);
            assertEquals(8, c.getBlockSize());
            c.init(Cipher.WRAP_MODE, kek);
            assertArrayEquals(name, expected, c.wrap(key20));

            c.init(Cipher.UNWRAP_MODE, kek);
            assertArrayEquals(name, key20.getEncoded(),
                c.unwrap(expected, "RAW", Cipher.SECRET_KEY).getEncoded());
        }
    }

    @Test
    public void testUpdateOutputFormAndAad() throws Exception {
        assumeAes128();

        Cipher c = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        c.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));

        /* update() only buffers, so an empty output buffer is enough */
        assertEquals(0, c.update(DATA_128, 0, 8, new byte[0], 0));
        assertArrayEquals(WRAP_128_KEK128,
            c.doFinal(DATA_128, 8, DATA_128.length - 8));

        try {
            c.updateAAD(new byte[8]);
            fail("updateAAD() should be rejected for AES Key Wrap");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testSizeLockedServicesMatchGeneric() throws Exception {
        assumeEnabled();

        if (FeatureDetect.Aes128Enabled()) {
            for (String name : new String[] { "AESWrap_128",
                "AES_128/KW/NoPadding", "2.16.840.1.101.3.4.1.5" }) {

                Cipher c = Cipher.getInstance(name, jceProvider);
                c.init(Cipher.WRAP_MODE, aesKey(KEK_128));
                assertArrayEquals(name, WRAP_128_KEK128,
                    c.wrap(aesKey(DATA_128)));
            }
        }
        if (FeatureDetect.Aes192Enabled()) {
            for (String name : new String[] { "AESWrap_192",
                "AES_192/KW/NoPadding", "2.16.840.1.101.3.4.1.25" }) {

                Cipher c = Cipher.getInstance(name, jceProvider);
                c.init(Cipher.WRAP_MODE, aesKey(KEK_192));
                assertArrayEquals(name, WRAP_192_KEK192,
                    c.wrap(aesKey(DATA_192)));
            }
        }
        if (FeatureDetect.Aes256Enabled()) {
            for (String name : new String[] { "AESWrap_256",
                "AES_256/KW/NoPadding", "2.16.840.1.101.3.4.1.45" }) {

                Cipher c = Cipher.getInstance(name, jceProvider);
                c.init(Cipher.WRAP_MODE, aesKey(KEK_256));
                assertArrayEquals(name, WRAP_256_KEK256,
                    c.wrap(aesKey(DATA_256)));
            }
        }
    }

    @Test
    public void testWrapUnwrapAllKeySizes() throws Exception {
        assumeEnabled();

        int[] kekSizes = { 16, 24, 32 };
        int[] keySizes = { 16, 24, 32 };
        boolean[] enabled = {
            FeatureDetect.Aes128Enabled(),
            FeatureDetect.Aes192Enabled(),
            FeatureDetect.Aes256Enabled()
        };

        KeyGenerator kg = KeyGenerator.getInstance("AES", jceProvider);

        for (int k = 0; k < kekSizes.length; k++) {
            if (!enabled[k]) {
                continue;
            }

            kg.init(kekSizes[k] * 8);
            SecretKey kek = kg.generateKey();

            for (int j = 0; j < keySizes.length; j++) {
                if (!enabled[j]) {
                    continue;
                }

                kg.init(keySizes[j] * 8);
                SecretKey toWrap = kg.generateKey();

                Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
                wrap.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped = wrap.wrap(toWrap);
                assertEquals(keySizes[j] + 8, wrapped.length);

                Cipher unwrap = Cipher.getInstance("AESWrap", jceProvider);
                unwrap.init(Cipher.UNWRAP_MODE, kek);
                Key out = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

                assertEquals("AES", out.getAlgorithm());
                assertArrayEquals("KEK " + kekSizes[k] + " key " +
                    keySizes[j], toWrap.getEncoded(), out.getEncoded());
            }
        }
    }

    @Test
    public void testEncryptDecryptRoundTripVariousLengths()
        throws Exception {
        assumeEnabled();

        Assume.assumeTrue(FeatureDetect.Aes256Enabled());

        int[] sizes = { 16, 24, 32, 40, 48, 64, 128, 256, 1024, 8192 };

        Cipher enc = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        Cipher dec = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_256));
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_256));

        for (int sz : sizes) {
            byte[] data = randomBytes(sz);

            byte[] ct = enc.doFinal(data);
            assertEquals(sz + 8, ct.length);

            byte[] pt = dec.doFinal(ct);
            assertArrayEquals("round trip size " + sz, data, pt);

            /* two-arg doFinal with exact output sizes */
            byte[] ctBuf = new byte[enc.getOutputSize(sz)];
            int ctLen = enc.doFinal(data, 0, sz, ctBuf, 0);
            assertEquals(ct.length, ctLen);
            assertArrayEquals(ct, ctBuf);

            byte[] ptBuf = new byte[dec.getOutputSize(ct.length)];
            int ptLen = dec.doFinal(ct, 0, ct.length, ptBuf, 0);
            assertEquals(sz, ptLen);
            assertArrayEquals(data, ptBuf);

            /* chunked update() */
            int half = (sz / 2) & ~7;
            byte[] u = enc.update(data, 0, half);
            assertTrue(u == null || u.length == 0);
            assertArrayEquals(ct, enc.doFinal(data, half, sz - half));
        }
    }

    @Test
    public void testShortOutputBuffer() throws Exception {
        assumeAes128();

        Cipher enc = Cipher.getInstance("AESWrap", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));

        try {
            enc.doFinal(DATA_128, 0, DATA_128.length, new byte[23], 0);
            fail("short output buffer should throw ShortBufferException");
        } catch (ShortBufferException e) {
            /* expected */
        }

        /* still usable, exact size works */
        byte[] out = new byte[24];
        assertEquals(24, enc.doFinal(DATA_128, 0, DATA_128.length, out, 0));
        assertArrayEquals(WRAP_128_KEK128, out);

        Cipher dec = Cipher.getInstance("AESWrap", jceProvider);
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));

        try {
            dec.doFinal(WRAP_128_KEK128, 0, WRAP_128_KEK128.length,
                new byte[15], 0);
            fail("short output buffer should throw ShortBufferException");
        } catch (ShortBufferException e) {
            /* expected */
        }

        byte[] pt = new byte[16];
        assertEquals(16, dec.doFinal(WRAP_128_KEK128, 0,
            WRAP_128_KEK128.length, pt, 0));
        assertArrayEquals(DATA_128, pt);
    }

    @Test
    public void testWrapUnwrapResetsState() throws Exception {
        assumeAes128();

        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128));

        Cipher unwrap = Cipher.getInstance("AESWrap", jceProvider);
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128));

        /* Repeated wrap/unwrap on the same Cipher objects, no re-init */
        for (int i = 0; i < 5; i++) {
            SecretKeySpec key = aesKey(randomBytes(32));
            byte[] wrapped = wrap.wrap(key);
            Key out = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            assertArrayEquals("iteration " + i, key.getEncoded(),
                out.getEncoded());
        }

        /* Known vector still correct after the loop above */
        assertArrayEquals(WRAP_128_KEK128, wrap.wrap(aesKey(DATA_128)));

        /* Re-init with a different KEK switches keys cleanly */
        if (FeatureDetect.Aes256Enabled()) {
            wrap.init(Cipher.WRAP_MODE, aesKey(KEK_256));
            assertArrayEquals(WRAP_256_KEK256, wrap.wrap(aesKey(DATA_256)));

            unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_256));
            assertArrayEquals(DATA_256, unwrap.unwrap(WRAP_256_KEK256,
                "AES", Cipher.SECRET_KEY).getEncoded());
        }

        /* Switching a single Cipher between directions */
        Cipher both = Cipher.getInstance("AESWrap", jceProvider);
        both.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        byte[] w = both.wrap(aesKey(DATA_128));
        both.init(Cipher.UNWRAP_MODE, aesKey(KEK_128));
        assertArrayEquals(DATA_128,
            both.unwrap(w, "AES", Cipher.SECRET_KEY).getEncoded());
        both.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        assertArrayEquals(w, both.doFinal(DATA_128));
        both.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        assertArrayEquals(DATA_128, both.doFinal(w));
    }

    @Test
    public void testUninitializedCipherThrows() throws Exception {
        assumeAes128();

        Cipher c = Cipher.getInstance("AESWrap", jceProvider);

        try {
            c.wrap(aesKey(DATA_128));
            fail("wrap() before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            c.doFinal(DATA_128);
            fail("doFinal() before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            c.update(DATA_128);
            fail("update() before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* wrap() on a Cipher initialized for a different opmode */
        c.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        try {
            c.wrap(aesKey(DATA_128));
            fail("wrap() in ENCRYPT_MODE should throw");
        } catch (IllegalStateException e) {
            /* expected, enforced by javax.crypto.Cipher */
        }
        c.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        try {
            c.unwrap(WRAP_128_KEK128, "AES", Cipher.SECRET_KEY);
            fail("unwrap() in WRAP_MODE should throw");
        } catch (IllegalStateException e) {
            /* expected, enforced by javax.crypto.Cipher */
        }
    }

    @Test
    public void testDefaultIvIsRfc3394Default() throws Exception {
        assumeAes128();

        Cipher c = Cipher.getInstance("AESWrap", jceProvider);

        c.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        assertNull("getIV() must be null when no IV was set", c.getIV());
        assertNull("getParameters() must be null when no IV was set",
            c.getParameters());
        byte[] a = c.wrap(aesKey(DATA_128));

        c.init(Cipher.WRAP_MODE, aesKey(KEK_128),
            new IvParameterSpec(DEFAULT_IV));
        assertArrayEquals(DEFAULT_IV, c.getIV());
        byte[] b = c.wrap(aesKey(DATA_128));

        c.init(Cipher.WRAP_MODE, aesKey(KEK_128),
            (AlgorithmParameterSpec)null);
        assertNull(c.getIV());
        byte[] d = c.wrap(aesKey(DATA_128));

        assertArrayEquals(WRAP_128_KEK128, a);
        assertArrayEquals(WRAP_128_KEK128, b);
        assertArrayEquals(WRAP_128_KEK128, d);

        /* A SecureRandom must never be used to invent an IV */
        c.init(Cipher.WRAP_MODE, aesKey(KEK_128), secureRandom);
        assertNull(c.getIV());
        assertArrayEquals(WRAP_128_KEK128, c.wrap(aesKey(DATA_128)));

        c.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128), secureRandom);
        assertNull(c.getIV());
        assertArrayEquals(WRAP_128_KEK128, c.doFinal(DATA_128));
    }

    @Test
    public void testExplicitIv() throws Exception {
        assumeAes128();

        IvParameterSpec altSpec = new IvParameterSpec(ALT_IV);

        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128), altSpec);

        /* getIV() returns a copy of the IV that was set */
        byte[] iv = wrap.getIV();
        assertArrayEquals(ALT_IV, iv);
        iv[0] ^= 0x01;
        assertArrayEquals("getIV() must return a copy", ALT_IV,
            wrap.getIV());

        byte[] wrappedAlt = wrap.wrap(aesKey(DATA_128));
        assertEquals(24, wrappedAlt.length);
        assertFalse("alternative IV must change the output",
            Arrays.equals(WRAP_128_KEK128, wrappedAlt));

        /* IV survives repeated use without re-init */
        assertArrayEquals(wrappedAlt, wrap.wrap(aesKey(DATA_128)));
        assertArrayEquals(ALT_IV, wrap.getIV());

        /* Matching IV unwraps */
        Cipher unwrap = Cipher.getInstance("AESWrap", jceProvider);
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128), altSpec);
        assertArrayEquals(DATA_128, unwrap.unwrap(wrappedAlt, "AES",
            Cipher.SECRET_KEY).getEncoded());

        /* Default IV against alternative-IV data fails */
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128));
        try {
            unwrap.unwrap(wrappedAlt, "AES", Cipher.SECRET_KEY);
            fail("default IV should not unwrap alternative IV data");
        } catch (InvalidKeyException e) {
            /* expected */
        }

        /* Wrong alternative IV fails */
        byte[] otherIv = ALT_IV.clone();
        otherIv[3] ^= (byte)0x80;
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128),
            new IvParameterSpec(otherIv));
        try {
            unwrap.unwrap(wrappedAlt, "AES", Cipher.SECRET_KEY);
            fail("wrong IV should not unwrap");
        } catch (InvalidKeyException e) {
            /* expected */
        }

        /* ENCRYPT/DECRYPT with IV */
        Cipher enc = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128), altSpec);
        assertArrayEquals(wrappedAlt, enc.doFinal(DATA_128));

        Cipher dec = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128), altSpec);
        assertArrayEquals(DATA_128, dec.doFinal(wrappedAlt));

        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        try {
            dec.doFinal(wrappedAlt);
            fail("default IV decrypt of alternative IV data should fail");
        } catch (BadPaddingException e) {
            /* expected, integrity check failure */
        }
    }

    @Test
    public void testAlgorithmParameters() throws Exception {
        assumeAes128();

        IvParameterSpec altSpec = new IvParameterSpec(ALT_IV);

        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128), altSpec);
        byte[] wrappedAlt = wrap.wrap(aesKey(DATA_128));

        /* getParameters() reflects the explicit IV */
        AlgorithmParameters params = wrap.getParameters();
        assertNotNull("getParameters() must not be null with explicit IV",
            params);
        IvParameterSpec back = params.getParameterSpec(IvParameterSpec.class);
        assertArrayEquals(ALT_IV, back.getIV());

        /* and can be used to init another Cipher */
        Cipher unwrap = Cipher.getInstance("AESWrap", jceProvider);
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128), params);
        assertArrayEquals(ALT_IV, unwrap.getIV());
        assertArrayEquals(DATA_128, unwrap.unwrap(wrappedAlt, "AES",
            Cipher.SECRET_KEY).getEncoded());

        /* Cipher accepts wolfJCE AES AlgorithmParameters holding a KW IV,
         * the AlgorithmParameters encoding itself is covered in
         * WolfCryptAlgorithmParametersTest */
        AlgorithmParameters wolfParams =
            AlgorithmParameters.getInstance("AES", jceProvider);
        wolfParams.init(altSpec);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128), wolfParams);
        assertArrayEquals(wrappedAlt, wrap.wrap(aesKey(DATA_128)));
    }

    @Test
    public void testInvalidParameters() throws Exception {
        assumeAes128();

        Cipher c = Cipher.getInstance("AESWrap", jceProvider);

        int[] badIvSizes = { 0, 1, 4, 7, 9, 12, 16 };
        for (int sz : badIvSizes) {
            try {
                c.init(Cipher.WRAP_MODE, aesKey(KEK_128),
                    new IvParameterSpec(new byte[sz]));
                fail("IV size " + sz + " should be rejected");
            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }
        }

        try {
            c.init(Cipher.WRAP_MODE, aesKey(KEK_128),
                new GCMParameterSpec(128, new byte[12]));
            fail("GCMParameterSpec should be rejected");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }

        try {
            c.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128),
                new IvParameterSpec(new byte[16]));
            fail("16-byte IV should be rejected for AES Key Wrap");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }

        /* A failed init must not leave the Cipher usable */
        try {
            c.wrap(aesKey(DATA_128));
            fail("wrap() after failed init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testInvalidKeys() throws Exception {
        assumeEnabled();

        Cipher c = Cipher.getInstance("AESWrap", jceProvider);

        /* SecretKeySpec itself rejects empty keys, so start at 1 */
        int[] badSizes = { 1, 8, 15, 17, 20, 31, 33, 64 };
        for (int sz : badSizes) {
            try {
                c.init(Cipher.WRAP_MODE, aesKey(new byte[sz]));
                fail("key size " + sz + " should be rejected");
            } catch (InvalidKeyException e) {
                /* expected */
            }
        }

        try {
            c.init(Cipher.WRAP_MODE, (Key)null);
            fail("null key should be rejected");
        } catch (InvalidKeyException e) {
            /* expected */
        }

        /* Non-SecretKey keys are rejected */
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC",
                jceProvider);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            try {
                c.init(Cipher.WRAP_MODE, kp.getPublic());
                fail("PublicKey should be rejected as KEK");
            } catch (InvalidKeyException e) {
                /* expected */
            }
            try {
                c.init(Cipher.UNWRAP_MODE, kp.getPrivate());
                fail("PrivateKey should be rejected as KEK");
            } catch (InvalidKeyException e) {
                /* expected */
            }
        } catch (NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException e) {
            /* ECC not compiled in, skip this part */
        }

        /* Size-locked services enforce the key size */
        if (FeatureDetect.Aes128Enabled()) {
            Cipher c128 = Cipher.getInstance("AESWrap_128", jceProvider);
            c128.init(Cipher.WRAP_MODE, aesKey(KEK_128));
            for (byte[] kek : new byte[][] { KEK_192, KEK_256 }) {
                try {
                    c128.init(Cipher.WRAP_MODE, aesKey(kek));
                    fail("AESWrap_128 should reject a " + kek.length +
                        " byte key");
                } catch (InvalidKeyException e) {
                    /* expected */
                }
            }
            Cipher p128 = Cipher.getInstance("AES_128/KW/PKCS5Padding",
                jceProvider);
            try {
                p128.init(Cipher.WRAP_MODE, aesKey(KEK_256));
                fail("AES_128/KW/PKCS5Padding should reject 32 byte key");
            } catch (InvalidKeyException e) {
                /* expected */
            }
        }
        if (FeatureDetect.Aes192Enabled()) {
            Cipher c192 = Cipher.getInstance("AESWrap_192", jceProvider);
            c192.init(Cipher.WRAP_MODE, aesKey(KEK_192));
            for (byte[] kek : new byte[][] { KEK_128, KEK_256 }) {
                try {
                    c192.init(Cipher.WRAP_MODE, aesKey(kek));
                    fail("AESWrap_192 should reject a " + kek.length +
                        " byte key");
                } catch (InvalidKeyException e) {
                    /* expected */
                }
            }
        }
        if (FeatureDetect.Aes256Enabled()) {
            Cipher c256 = Cipher.getInstance("AESWrap_256", jceProvider);
            c256.init(Cipher.WRAP_MODE, aesKey(KEK_256));
            for (byte[] kek : new byte[][] { KEK_128, KEK_192 }) {
                try {
                    c256.init(Cipher.WRAP_MODE, aesKey(kek));
                    fail("AESWrap_256 should reject a " + kek.length +
                        " byte key");
                } catch (InvalidKeyException e) {
                    /* expected */
                }
            }
        }
    }

    @Test
    public void testWrapInputLengthFailures() throws Exception {
        assumeAes128();

        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128));

        int[] badSizes = { 1, 7, 8, 15, 17, 20, 23, 25 };
        for (int sz : badSizes) {
            try {
                wrap.wrap(new SecretKeySpec(new byte[sz], "RAW"));
                fail("wrap() of " + sz + " bytes should throw");
            } catch (IllegalBlockSizeException e) {
                /* expected, matches SunJCE */
            }
        }

        try {
            wrap.wrap(null);
            fail("wrap(null) should throw");
        } catch (InvalidKeyException e) {
            /* expected */
        }

        /* still works afterwards */
        assertArrayEquals(WRAP_128_KEK128, wrap.wrap(aesKey(DATA_128)));

        Cipher enc = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        for (int sz : new int[] { 0, 1, 8, 15, 17, 20 }) {
            try {
                enc.doFinal(new byte[sz]);
                fail("encrypt of " + sz + " bytes should throw");
            } catch (IllegalBlockSizeException e) {
                /* expected */
            }
            /* re-init clears anything buffered from the failed call */
            enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        }
        assertArrayEquals(WRAP_128_KEK128, enc.doFinal(DATA_128));
    }

    @Test
    public void testDecryptFailures() throws Exception {
        assumeAes128();

        Cipher dec = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));

        /* Bad lengths are IllegalBlockSizeException */
        for (int sz : new int[] { 0, 8, 16, 23, 25, 31 }) {
            try {
                dec.doFinal(new byte[sz]);
                fail("decrypt of " + sz + " bytes should throw");
            } catch (IllegalBlockSizeException e) {
                /* expected */
            }
            dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        }

        /* Integrity failures are BadPaddingException */
        for (int i = 0; i < WRAP_128_KEK128.length; i++) {
            byte[] corrupt = WRAP_128_KEK128.clone();
            corrupt[i] ^= 0x01;
            try {
                dec.doFinal(corrupt);
                fail("corrupted byte " + i + " should fail decrypt");
            } catch (BadPaddingException e) {
                assertEquals("Integrity check failed", e.getMessage());
            }
            dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        }

        /* Wrong KEK */
        byte[] wrongKek = KEK_128.clone();
        wrongKek[5] ^= 0x10;
        dec.init(Cipher.DECRYPT_MODE, aesKey(wrongKek));
        try {
            dec.doFinal(WRAP_128_KEK128);
            fail("wrong KEK should fail decrypt");
        } catch (BadPaddingException e) {
            /* expected */
        }

        /* Correct data still decrypts after failures */
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        assertArrayEquals(DATA_128, dec.doFinal(WRAP_128_KEK128));
    }

    /** A failed doFinal() must discard buffered update() data */
    @Test
    public void testFailedDoFinalDiscardsBufferedInput() throws Exception {
        assumeAes128();

        Cipher enc = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));

        /* 8 buffered bytes, below the 16 byte minimum */
        enc.update(new byte[8]);
        try {
            enc.doFinal();
            fail("8 byte total should fail");
        } catch (IllegalBlockSizeException e) {
            /* expected */
        }

        /* no re-init, the stale 8 bytes must not be prepended */
        byte[] ct = enc.doFinal(DATA_128);
        assertEquals(24, ct.length);
        assertArrayEquals(WRAP_128_KEK128, ct);

        /* decrypt side, after an integrity failure ... */
        Cipher dec = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        byte[] tampered = WRAP_128_KEK128.clone();
        tampered[0] ^= 0x01;
        dec.update(tampered, 0, 8);
        try {
            dec.doFinal(tampered, 8, tampered.length - 8);
            fail("tampered data should fail");
        } catch (BadPaddingException e) {
            /* expected */
        }
        assertArrayEquals(DATA_128, dec.doFinal(WRAP_128_KEK128));

        /* ... and after a length failure */
        dec.update(new byte[8]);
        try {
            dec.doFinal();
            fail("8 byte total should fail");
        } catch (IllegalBlockSizeException e) {
            /* expected */
        }
        assertArrayEquals(DATA_128, dec.doFinal(WRAP_128_KEK128));

        /* PKCS5Padding too */
        Cipher penc = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        penc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        penc.update(new byte[3]);
        try {
            penc.doFinal();
            fail("3 byte total should fail");
        } catch (IllegalBlockSizeException e) {
            /* expected */
        }
        Cipher fresh = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        fresh.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        byte[] expectedPkcs5 = fresh.doFinal(DATA_128);
        assertEquals(32, expectedPkcs5.length);
        assertArrayEquals(expectedPkcs5, penc.doFinal(DATA_128));
    }

    @Test
    public void testUnwrapFailuresAreNotDistinguishable() throws Exception {
        assumeAes128();

        Set<String> outcomes = new HashSet<String>();

        byte[] tampered = WRAP_128_KEK128.clone();
        tampered[9] ^= 0x01;

        byte[] wrongKek = KEK_128.clone();
        wrongKek[0] ^= 0x01;

        /* null, empty, short, non-multiple, tampered */
        outcomes.add(unwrapFailure(KEK_128, null, null));
        outcomes.add(unwrapFailure(KEK_128, null, new byte[0]));
        outcomes.add(unwrapFailure(KEK_128, null, new byte[16]));
        outcomes.add(unwrapFailure(KEK_128, null, new byte[25]));
        outcomes.add(unwrapFailure(KEK_128, null, tampered));
        /* wrong KEK, wrong IV */
        outcomes.add(unwrapFailure(wrongKek, null, WRAP_128_KEK128));
        outcomes.add(unwrapFailure(KEK_128, ALT_IV, WRAP_128_KEK128));

        assertEquals("AES Key Wrap unwrap failures must not be " +
            "distinguishable: " + outcomes, 1, outcomes.size());

        /* Same for the PKCS5Padding service, including a bad pad */
        outcomes.clear();
        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        /* 16 bytes whose last byte is not a valid PKCS#5 pad value */
        byte[] badPadPlain = new byte[16];
        badPadPlain[15] = 0x09;
        byte[] badPadWrapped = wrap.wrap(new SecretKeySpec(badPadPlain,
            "RAW"));

        outcomes.add(unwrapPkcs5Failure(KEK_128, badPadWrapped));
        outcomes.add(unwrapPkcs5Failure(KEK_128, tampered));
        outcomes.add(unwrapPkcs5Failure(KEK_128, new byte[16]));
        outcomes.add(unwrapPkcs5Failure(wrongKek, WRAP_128_KEK128));

        assertEquals("AES/KW/PKCS5Padding unwrap failures must not be " +
            "distinguishable: " + outcomes, 1, outcomes.size());
    }

    private String unwrapFailure(byte[] kek, byte[] iv, byte[] wrapped)
        throws Exception {

        Cipher c = Cipher.getInstance("AESWrap", jceProvider);
        if (iv == null) {
            c.init(Cipher.UNWRAP_MODE, aesKey(kek));
        } else {
            c.init(Cipher.UNWRAP_MODE, aesKey(kek), new IvParameterSpec(iv));
        }

        try {
            c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            fail("Malformed wrapped key must not unwrap successfully");
            throw new AssertionError("unreachable");

        } catch (InvalidKeyException e) {
            return e.getClass().getName() + ":" + e.getMessage();
        }
    }

    private String unwrapPkcs5Failure(byte[] kek, byte[] wrapped)
        throws Exception {

        Cipher c = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        c.init(Cipher.UNWRAP_MODE, aesKey(kek));

        try {
            c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            fail("Malformed wrapped key must not unwrap successfully");
            throw new AssertionError("unreachable");

        } catch (InvalidKeyException e) {
            return e.getClass().getName() + ":" + e.getMessage();
        }
    }

    @Test
    public void testPkcs5PaddingRoundTrip() throws Exception {
        assumeAes128();

        Cipher enc = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        Cipher dec = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        Cipher raw = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        raw.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));

        for (int sz = 0; sz <= 70; sz++) {
            byte[] data = randomBytes(sz);

            if (sz < 8) {
                /* Padded to 8 bytes, below the 16 byte KW minimum */
                try {
                    enc.doFinal(data);
                    fail("PKCS5Padding encrypt of " + sz +
                        " bytes should throw");
                } catch (IllegalBlockSizeException e) {
                    /* expected, SunJCE behaves the same */
                }
                enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
                continue;
            }

            int paddedLen = ((sz / 8) + 1) * 8;
            assertEquals(paddedLen + 8, enc.getOutputSize(sz));

            byte[] ct = enc.doFinal(data);
            assertEquals("ciphertext size for " + sz, paddedLen + 8,
                ct.length);

            byte[] pt = dec.doFinal(ct);
            assertArrayEquals("PKCS5 round trip size " + sz, data, pt);

            /* The padding is standard PKCS#5/#7 over 8-byte blocks */
            byte[] padded = raw.doFinal(ct);
            assertEquals(paddedLen, padded.length);
            int padVal = padded[paddedLen - 1] & 0xFF;
            assertEquals(paddedLen - sz, padVal);
            for (int i = sz; i < paddedLen; i++) {
                assertEquals((byte)padVal, padded[i]);
            }
            assertArrayEquals(data, Arrays.copyOf(padded, sz));
        }
    }

    @Test
    public void testPkcs5PaddingWrapUnwrapSecretKey() throws Exception {
        assumeAes128();

        Cipher wrap = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        Cipher unwrap = Cipher.getInstance("AES/KW/PKCS5Padding",
            jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128));

        /* Odd-sized raw keys that AESWrap itself can not handle */
        for (int sz : new int[] { 8, 13, 20, 21, 33, 100 }) {
            SecretKeySpec key = new SecretKeySpec(randomBytes(sz), "Hmac");
            byte[] wrapped = wrap.wrap(key);
            assertEquals(((sz / 8) + 1) * 8 + 8, wrapped.length);

            Key out = unwrap.unwrap(wrapped, "Hmac", Cipher.SECRET_KEY);
            assertEquals("Hmac", out.getAlgorithm());
            assertArrayEquals("size " + sz, key.getEncoded(),
                out.getEncoded());
        }

        /* And the plain AES key sizes */
        for (byte[] data : new byte[][] { DATA_128, DATA_192, DATA_256 }) {
            byte[] wrapped = wrap.wrap(aesKey(data));
            assertEquals(data.length + 16, wrapped.length);
            assertArrayEquals(data, unwrap.unwrap(wrapped, "AES",
                Cipher.SECRET_KEY).getEncoded());
        }

        /* size-locked PKCS5Padding services match the generic one */
        String[] sized = { "AES_128/KW/PKCS5Padding",
            "AES_192/KW/PKCS5Padding", "AES_256/KW/PKCS5Padding" };
        byte[][] keks = { KEK_128, KEK_192, KEK_256 };
        boolean[] enabled = {
            FeatureDetect.Aes128Enabled(),
            FeatureDetect.Aes192Enabled(),
            FeatureDetect.Aes256Enabled()
        };
        SecretKeySpec key21 = new SecretKeySpec(randomBytes(21), "RAW");

        for (int i = 0; i < sized.length; i++) {
            if (!enabled[i]) {
                continue;
            }

            Cipher generic = Cipher.getInstance("AES/KW/PKCS5Padding",
                jceProvider);
            generic.init(Cipher.WRAP_MODE, aesKey(keks[i]));
            byte[] expected = generic.wrap(key21);

            Cipher locked = Cipher.getInstance(sized[i], jceProvider);
            locked.init(Cipher.WRAP_MODE, aesKey(keks[i]));
            assertArrayEquals(sized[i], expected, locked.wrap(key21));

            locked.init(Cipher.UNWRAP_MODE, aesKey(keks[i]));
            assertArrayEquals(sized[i], key21.getEncoded(),
                locked.unwrap(expected, "RAW",
                    Cipher.SECRET_KEY).getEncoded());
        }
    }

    @Test
    public void testUnwrapArgumentFailures() throws Exception {
        assumeAes128();

        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        byte[] wrapped = wrap.wrap(aesKey(DATA_128));

        Cipher unwrap = Cipher.getInstance("AESWrap", jceProvider);
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128));

        /* null or empty algorithm name is rejected up front for every key
         * type, before any unwrap is attempted */
        for (int type : new int[] { Cipher.SECRET_KEY, Cipher.PUBLIC_KEY,
                Cipher.PRIVATE_KEY }) {
            for (String alg : new String[] { null, "" }) {
                try {
                    unwrap.unwrap(wrapped, alg, type);
                    fail("null/empty wrapped key algorithm should throw");
                } catch (NoSuchAlgorithmException e) {
                    /* expected */
                }
            }
        }

        /* bad wrappedKeyType, rejected by javax.crypto.Cipher itself */
        try {
            unwrap.unwrap(wrapped, "AES", 99);
            fail("invalid wrappedKeyType should throw");
        } catch (InvalidParameterException e) {
            /* expected */
        }

        /* PUBLIC_KEY / PRIVATE_KEY with an algorithm no KeyFactory knows */
        try {
            unwrap.unwrap(wrapped, "NotAnAlgorithm", Cipher.PUBLIC_KEY);
            fail("unknown public key algorithm should throw");
        } catch (NoSuchAlgorithmException e) {
            /* expected */
        }
        try {
            unwrap.unwrap(wrapped, "NotAnAlgorithm", Cipher.PRIVATE_KEY);
            fail("unknown private key algorithm should throw");
        } catch (NoSuchAlgorithmException e) {
            /* expected */
        }

        /* A 16 byte AES key is not an EC public key encoding */
        try {
            unwrap.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
            fail("AES key bytes should not parse as an EC public key");
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            /* expected, NoSuchAlgorithmException only if no EC factory */
        }

        /* still usable */
        assertArrayEquals(DATA_128, unwrap.unwrap(wrapped, "AES",
            Cipher.SECRET_KEY).getEncoded());
    }

    @Test
    public void testPkcs5PaddingWrapUnwrapAsymmetricKeys() throws Exception {
        assumeAes128();

        KeyPair kp = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC",
                jceProvider);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException e) {
            /* ECC not compiled in */
        }
        Assume.assumeNotNull(kp);

        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        /* encodings are not 8-byte multiples, plain AESWrap refuses them ... */
        Cipher plain = Cipher.getInstance("AESWrap", jceProvider);
        plain.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        Assume.assumeTrue("X.509 encoding happens to be an 8-byte " +
            "multiple", (pub.getEncoded().length % 8) != 0);
        try {
            plain.wrap(pub);
            fail("AESWrap should reject an X.509 encoding that is not a " +
                "multiple of 8 bytes");
        } catch (IllegalBlockSizeException e) {
            /* expected */
        }

        /* ... while AES/KW/PKCS5Padding handles them */
        Cipher wrap = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        Cipher unwrap = Cipher.getInstance("AES/KW/PKCS5Padding",
            jceProvider);
        wrap.init(Cipher.WRAP_MODE, aesKey(KEK_128));
        unwrap.init(Cipher.UNWRAP_MODE, aesKey(KEK_128));

        byte[] wrappedPub = wrap.wrap(pub);
        Key pubOut = unwrap.unwrap(wrappedPub, "EC", Cipher.PUBLIC_KEY);
        assertTrue(pubOut instanceof PublicKey);
        assertArrayEquals(pub.getEncoded(), pubOut.getEncoded());

        byte[] wrappedPriv = wrap.wrap(priv);
        Key privOut = unwrap.unwrap(wrappedPriv, "EC", Cipher.PRIVATE_KEY);
        assertTrue(privOut instanceof PrivateKey);
        assertArrayEquals(priv.getEncoded(), privOut.getEncoded());

        /* Wrong key type for the blob */
        try {
            unwrap.unwrap(wrappedPub, "EC", Cipher.PRIVATE_KEY);
            fail("unwrapping a public key as PRIVATE_KEY should fail");
        } catch (InvalidKeyException e) {
            /* expected */
        }
        try {
            unwrap.unwrap(wrappedPriv, "EC", Cipher.PUBLIC_KEY);
            fail("unwrapping a private key as PUBLIC_KEY should fail");
        } catch (InvalidKeyException e) {
            /* expected */
        }

        /* Wrong algorithm for the blob, RSA KeyFactory can not parse EC */
        try {
            unwrap.unwrap(wrappedPub, "RSA", Cipher.PUBLIC_KEY);
            fail("unwrapping an EC key as RSA should fail");
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            /* expected, NoSuchAlgorithmException only without RSA */
        }

        /* Corrupted blob for an asymmetric type is still uniform */
        byte[] corrupt = wrappedPub.clone();
        corrupt[corrupt.length - 1] ^= 0x01;
        try {
            unwrap.unwrap(corrupt, "EC", Cipher.PUBLIC_KEY);
            fail("corrupted wrapped public key should fail");
        } catch (InvalidKeyException e) {
            assertEquals("Failed to unwrap key", e.getMessage());
        }
    }

    @Test
    public void testPkcs5PaddingBadPadding() throws Exception {
        assumeAes128();

        /* wrap an invalid pad with NoPadding, PKCS5Padding must reject it */
        Cipher raw = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        raw.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));

        byte[] badPad = new byte[16];
        Arrays.fill(badPad, (byte)0x09); /* 9 > 8 byte block, invalid */
        byte[] ct = raw.doFinal(badPad);

        Cipher dec = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        try {
            dec.doFinal(ct);
            fail("invalid PKCS#5 padding should throw");
        } catch (BadPaddingException e) {
            /* expected */
        }

        /* Pad byte 0 is invalid too */
        Arrays.fill(badPad, (byte)0x00);
        ct = raw.doFinal(badPad);
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        try {
            dec.doFinal(ct);
            fail("zero PKCS#5 padding should throw");
        } catch (BadPaddingException e) {
            /* expected */
        }

        /* a valid full pad block is stripped, leaving the first 8 bytes */
        Arrays.fill(badPad, (byte)0x08);
        ct = raw.doFinal(badPad);
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));
        assertArrayEquals(Arrays.copyOf(badPad, 8), dec.doFinal(ct));
    }

    @Test
    public void testInteropWrapUnwrap() throws Exception {
        assumeEnabled();

        Assume.assumeTrue("no interop provider with AESWrap",
            interopHasAesWrap);

        byte[][] keks = { KEK_128, KEK_192, KEK_256 };
        boolean[] enabled = {
            FeatureDetect.Aes128Enabled(),
            FeatureDetect.Aes192Enabled(),
            FeatureDetect.Aes256Enabled()
        };

        for (int k = 0; k < keks.length; k++) {
            if (!enabled[k]) {
                continue;
            }
            SecretKeySpec kek = aesKey(keks[k]);

            for (int sz : new int[] { 16, 24, 32 }) {
                SecretKeySpec key = aesKey(randomBytes(sz));

                /* wolfJCE wrap -> interop unwrap */
                Cipher wolfWrap = Cipher.getInstance("AESWrap", jceProvider);
                wolfWrap.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped = wolfWrap.wrap(key);

                Cipher otherUnwrap = Cipher.getInstance("AESWrap",
                    interopProvider);
                otherUnwrap.init(Cipher.UNWRAP_MODE, kek);
                Key out = otherUnwrap.unwrap(wrapped, "AES",
                    Cipher.SECRET_KEY);
                assertArrayEquals("wolfJCE wrap -> " + interopProvider +
                    " unwrap, KEK " + keks[k].length, key.getEncoded(),
                    out.getEncoded());

                /* interop wrap -> wolfJCE unwrap */
                Cipher otherWrap = Cipher.getInstance("AESWrap",
                    interopProvider);
                otherWrap.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped2 = otherWrap.wrap(key);
                assertArrayEquals("both providers must produce identical " +
                    "wrapped output", wrapped, wrapped2);

                Cipher wolfUnwrap = Cipher.getInstance("AESWrap",
                    jceProvider);
                wolfUnwrap.init(Cipher.UNWRAP_MODE, kek);
                Key out2 = wolfUnwrap.unwrap(wrapped2, "AES",
                    Cipher.SECRET_KEY);
                assertArrayEquals(interopProvider + " wrap -> wolfJCE " +
                    "unwrap, KEK " + keks[k].length, key.getEncoded(),
                    out2.getEncoded());
            }
        }
    }

    @Test
    public void testInteropSizeLockedNames() throws Exception {
        assumeEnabled();

        Assume.assumeTrue("no interop provider with AESWrap",
            interopHasAesWrap);

        String[][] cases = {
            { "AESWrap_128", "2.16.840.1.101.3.4.1.5",
              "AES_128/KW/NoPadding" },
            { "AESWrap_192", "2.16.840.1.101.3.4.1.25",
              "AES_192/KW/NoPadding" },
            { "AESWrap_256", "2.16.840.1.101.3.4.1.45",
              "AES_256/KW/NoPadding" }
        };
        byte[][] keks = { KEK_128, KEK_192, KEK_256 };
        boolean[] enabled = {
            FeatureDetect.Aes128Enabled(),
            FeatureDetect.Aes192Enabled(),
            FeatureDetect.Aes256Enabled()
        };
        for (int k = 0; k < cases.length; k++) {
            if (!enabled[k]) {
                continue;
            }
            for (String name : cases[k]) {
                Cipher other = null;
                try {
                    other = Cipher.getInstance(name, interopProvider);
                } catch (NoSuchAlgorithmException e) {
                    /* name not offered by this provider, skip */
                    continue;
                }

                SecretKeySpec kek = aesKey(keks[k]);
                SecretKeySpec key = aesKey(randomBytes(32));

                Cipher wolf = Cipher.getInstance(name, jceProvider);
                wolf.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped = wolf.wrap(key);

                other.init(Cipher.UNWRAP_MODE, kek);
                assertArrayEquals(name, key.getEncoded(),
                    other.unwrap(wrapped, "AES",
                        Cipher.SECRET_KEY).getEncoded());

                other.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped2 = other.wrap(key);
                wolf.init(Cipher.UNWRAP_MODE, kek);
                assertArrayEquals(name, key.getEncoded(),
                    wolf.unwrap(wrapped2, "AES",
                        Cipher.SECRET_KEY).getEncoded());
            }
        }
    }

    @Test
    public void testInteropEncryptDecryptAndIv() throws Exception {
        assumeAes128();

        Assume.assumeTrue("interop provider lacks ENCRYPT_MODE / IV " +
            "support for AES Key Wrap", interopModernName != null);

        SecretKeySpec kek = aesKey(KEK_128);
        byte[] data = randomBytes(64);

        /* ENCRYPT / DECRYPT, default IV, both directions */
        Cipher wolfEnc = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        wolfEnc.init(Cipher.ENCRYPT_MODE, kek);
        byte[] ct = wolfEnc.doFinal(data);

        Cipher otherDec = Cipher.getInstance(interopModernName,
            interopProvider);
        otherDec.init(Cipher.DECRYPT_MODE, kek);
        assertArrayEquals("wolfJCE encrypt -> " + interopProvider +
            " decrypt", data, otherDec.doFinal(ct));

        Cipher otherEnc = Cipher.getInstance(interopModernName,
            interopProvider);
        otherEnc.init(Cipher.ENCRYPT_MODE, kek);
        byte[] ct2 = otherEnc.doFinal(data);
        assertArrayEquals("identical ciphertext", ct, ct2);

        Cipher wolfDec = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        wolfDec.init(Cipher.DECRYPT_MODE, kek);
        assertArrayEquals(interopProvider + " encrypt -> wolfJCE decrypt",
            data, wolfDec.doFinal(ct2));

        /* Explicit IV, both directions, encrypt and wrap */
        IvParameterSpec altSpec = new IvParameterSpec(ALT_IV);

        wolfEnc.init(Cipher.ENCRYPT_MODE, kek, altSpec);
        byte[] ctIv = wolfEnc.doFinal(data);
        otherDec.init(Cipher.DECRYPT_MODE, kek, altSpec);
        assertArrayEquals("IV: wolfJCE encrypt -> " + interopProvider,
            data, otherDec.doFinal(ctIv));

        otherEnc.init(Cipher.ENCRYPT_MODE, kek, altSpec);
        byte[] ctIv2 = otherEnc.doFinal(data);
        assertArrayEquals(ctIv, ctIv2);
        wolfDec.init(Cipher.DECRYPT_MODE, kek, altSpec);
        assertArrayEquals("IV: " + interopProvider + " encrypt -> wolfJCE",
            data, wolfDec.doFinal(ctIv2));

        SecretKeySpec key = aesKey(randomBytes(32));
        Cipher wolfWrap = Cipher.getInstance("AESWrap", jceProvider);
        wolfWrap.init(Cipher.WRAP_MODE, kek, altSpec);
        byte[] wrapped = wolfWrap.wrap(key);

        Cipher otherUnwrap = Cipher.getInstance(interopModernName,
            interopProvider);
        otherUnwrap.init(Cipher.UNWRAP_MODE, kek, altSpec);
        assertArrayEquals("IV: wolfJCE wrap -> " + interopProvider +
            " unwrap", key.getEncoded(), otherUnwrap.unwrap(wrapped, "AES",
            Cipher.SECRET_KEY).getEncoded());

        Cipher otherWrap = Cipher.getInstance(interopModernName,
            interopProvider);
        otherWrap.init(Cipher.WRAP_MODE, kek, altSpec);
        byte[] wrapped2 = otherWrap.wrap(key);
        Cipher wolfUnwrap = Cipher.getInstance("AESWrap", jceProvider);
        wolfUnwrap.init(Cipher.UNWRAP_MODE, kek, altSpec);
        assertArrayEquals("IV: " + interopProvider + " wrap -> wolfJCE " +
            "unwrap", key.getEncoded(), wolfUnwrap.unwrap(wrapped2, "AES",
            Cipher.SECRET_KEY).getEncoded());

        /* AlgorithmParameters from the interop provider initialize us */
        AlgorithmParameters otherParams = otherEnc.getParameters();
        if (otherParams != null) {
            wolfDec.init(Cipher.DECRYPT_MODE, kek, otherParams);
            assertArrayEquals("init from " + interopProvider +
                " AlgorithmParameters", data, wolfDec.doFinal(ctIv2));
        }

        /* and ours initialize the interop provider (Cipher.init() uses
         * getParameterSpec(), not the DER encoding) */
        AlgorithmParameters wolfParams = wolfEnc.getParameters();
        assertNotNull(wolfParams);
        otherDec.init(Cipher.DECRYPT_MODE, kek, wolfParams);
        assertArrayEquals(interopProvider + " init from wolfJCE " +
            "AlgorithmParameters", data, otherDec.doFinal(ctIv));
    }

    @Test
    public void testInteropPkcs5Padding() throws Exception {
        assumeEnabled();

        Assume.assumeTrue("interop provider lacks AES/KW/PKCS5Padding",
            interopHasKwPkcs5);

        SecretKeySpec kek = aesKey(KEK_256);
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());

        for (int sz : new int[] { 8, 13, 16, 20, 33, 100 }) {
            byte[] data = randomBytes(sz);

            Cipher wolfEnc = Cipher.getInstance("AES/KW/PKCS5Padding",
                jceProvider);
            wolfEnc.init(Cipher.ENCRYPT_MODE, kek);
            byte[] ct = wolfEnc.doFinal(data);

            Cipher otherDec = Cipher.getInstance("AES/KW/PKCS5Padding",
                interopProvider);
            otherDec.init(Cipher.DECRYPT_MODE, kek);
            assertArrayEquals("PKCS5 size " + sz + ": wolfJCE -> " +
                interopProvider, data, otherDec.doFinal(ct));

            Cipher otherEnc = Cipher.getInstance("AES/KW/PKCS5Padding",
                interopProvider);
            otherEnc.init(Cipher.ENCRYPT_MODE, kek);
            byte[] ct2 = otherEnc.doFinal(data);
            assertArrayEquals("PKCS5 size " + sz + ": identical output",
                ct, ct2);

            Cipher wolfDec = Cipher.getInstance("AES/KW/PKCS5Padding",
                jceProvider);
            wolfDec.init(Cipher.DECRYPT_MODE, kek);
            assertArrayEquals("PKCS5 size " + sz + ": " + interopProvider +
                " -> wolfJCE", data, wolfDec.doFinal(ct2));

            /* wrap()/unwrap() of an odd-sized SecretKey */
            SecretKeySpec key = new SecretKeySpec(data, "RAW");
            Cipher wolfWrap = Cipher.getInstance("AES/KW/PKCS5Padding",
                jceProvider);
            wolfWrap.init(Cipher.WRAP_MODE, kek);
            Cipher otherUnwrap = Cipher.getInstance("AES/KW/PKCS5Padding",
                interopProvider);
            otherUnwrap.init(Cipher.UNWRAP_MODE, kek);
            assertArrayEquals(data, otherUnwrap.unwrap(wolfWrap.wrap(key),
                "RAW", Cipher.SECRET_KEY).getEncoded());

            Cipher otherWrap = Cipher.getInstance("AES/KW/PKCS5Padding",
                interopProvider);
            otherWrap.init(Cipher.WRAP_MODE, kek);
            Cipher wolfUnwrap = Cipher.getInstance("AES/KW/PKCS5Padding",
                jceProvider);
            wolfUnwrap.init(Cipher.UNWRAP_MODE, kek);
            assertArrayEquals(data, wolfUnwrap.unwrap(otherWrap.wrap(key),
                "RAW", Cipher.SECRET_KEY).getEncoded());
        }
    }

    @Test
    public void testInteropKeyObjectsFromOtherProvider() throws Exception {
        assumeAes128();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());

        Assume.assumeTrue("no interop provider", interopProvider != null);

        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance("AES", interopProvider);
        } catch (NoSuchAlgorithmException e) {
            Assume.assumeNoException(e);
            return;
        }

        kg.init(256);
        SecretKey kek = kg.generateKey();
        kg.init(128);
        SecretKey key = kg.generateKey();

        Cipher wrap = Cipher.getInstance("AESWrap", jceProvider);
        wrap.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = wrap.wrap(key);

        Cipher unwrap = Cipher.getInstance("AESWrap", jceProvider);
        unwrap.init(Cipher.UNWRAP_MODE, kek);
        Key out = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        assertArrayEquals(key.getEncoded(), out.getEncoded());

        /* and the unwrapped key is usable by the other provider */
        Cipher other = Cipher.getInstance("AES/CBC/PKCS5Padding",
            interopProvider);
        other.init(Cipher.ENCRYPT_MODE, out, new IvParameterSpec(
            new byte[16]));
        byte[] ct = other.doFinal(DATA_128);
        other.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(
            new byte[16]));
        assertArrayEquals(DATA_128, other.doFinal(ct));
    }

    @Test
    public void testByteBufferDoFinal() throws Exception {
        assumeAes128();

        Cipher enc = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        Cipher dec = Cipher.getInstance("AES/KW/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        dec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));

        for (boolean direct : new boolean[] { false, true }) {
            int outSz = enc.getOutputSize(DATA_128.length);
            ByteBuffer in = direct ?
                ByteBuffer.allocateDirect(DATA_128.length) :
                ByteBuffer.allocate(DATA_128.length);
            ByteBuffer out = direct ?
                ByteBuffer.allocateDirect(outSz) : ByteBuffer.allocate(outSz);

            in.put(DATA_128);
            in.flip();
            int n = enc.doFinal(in, out);
            assertEquals(WRAP_128_KEK128.length, n);
            assertEquals(0, in.remaining());

            out.flip();
            byte[] ct = new byte[out.remaining()];
            out.get(ct);
            assertArrayEquals("direct=" + direct, WRAP_128_KEK128, ct);

            ByteBuffer ctBuf = ByteBuffer.wrap(ct);
            ByteBuffer ptBuf = ByteBuffer.allocate(
                dec.getOutputSize(ct.length));
            n = dec.doFinal(ctBuf, ptBuf);
            assertEquals(DATA_128.length, n);
            ptBuf.flip();
            byte[] pt = new byte[ptBuf.remaining()];
            ptBuf.get(pt);
            assertArrayEquals("direct=" + direct, DATA_128, pt);

            /* short output ByteBuffer */
            in.rewind();
            ByteBuffer small =
                ByteBuffer.allocate(WRAP_128_KEK128.length - 1);
            try {
                enc.doFinal(in, small);
                fail("short output ByteBuffer should throw");
            } catch (ShortBufferException e) {
                /* expected */
            }
        }

        /* PKCS5Padding through ByteBuffers, odd sized input */
        Cipher penc = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        Cipher pdec = Cipher.getInstance("AES/KW/PKCS5Padding", jceProvider);
        penc.init(Cipher.ENCRYPT_MODE, aesKey(KEK_128));
        pdec.init(Cipher.DECRYPT_MODE, aesKey(KEK_128));

        byte[] data = randomBytes(21);
        ByteBuffer pin = ByteBuffer.wrap(data);
        ByteBuffer pout = ByteBuffer.allocate(penc.getOutputSize(data.length));
        assertEquals(32, penc.doFinal(pin, pout));
        pout.flip();
        ByteBuffer pback = ByteBuffer.allocate(pdec.getOutputSize(32));
        assertEquals(21, pdec.doFinal(pout, pback));
        pback.flip();
        byte[] back = new byte[pback.remaining()];
        pback.get(back);
        assertArrayEquals(data, back);
    }

    @Test
    public void testGetParametersWithoutRegisteredProvider()
        throws Exception {
        assumeAes128();

        /* Mutates global Security state, restored in finally. Not safe if
         * other tests run concurrently in this JVM (the JUnit 4 runner is
         * sequential by default and the ant junit task forks per suite). */

        Provider saved = Security.getProvider(jceProvider);
        assertNotNull(saved);
        int savedPos = 1;
        Provider[] installed = Security.getProviders();
        for (int i = 0; i < installed.length; i++) {
            if (installed[i] == saved) {
                savedPos = i + 1;
                break;
            }
        }
        Security.removeProvider(jceProvider);

        try {
            assertNull(Security.getProvider(jceProvider));

            WolfCryptProvider unregistered = new WolfCryptProvider();
            Cipher c = Cipher.getInstance("AESWrap", unregistered);
            c.init(Cipher.WRAP_MODE, aesKey(KEK_128),
                new IvParameterSpec(ALT_IV));

            AlgorithmParameters params = c.getParameters();
            assertNotNull("explicit IV must be reported even when wolfJCE " +
                "is not registered", params);
            assertEquals(jceProvider, params.getProvider().getName());
            assertArrayEquals(ALT_IV,
                params.getParameterSpec(IvParameterSpec.class).getIV());
            assertArrayEquals(ALT_IV, c.getIV());

            byte[] wrapped = c.wrap(aesKey(DATA_128));

            Cipher u = Cipher.getInstance("AESWrap", unregistered);
            u.init(Cipher.UNWRAP_MODE, aesKey(KEK_128),
                new IvParameterSpec(ALT_IV));
            assertArrayEquals(DATA_128, u.unwrap(wrapped, "AES",
                Cipher.SECRET_KEY).getEncoded());

            /* no IV set, no parameters regardless of provider lookup */
            c.init(Cipher.WRAP_MODE, aesKey(KEK_128));
            assertNull(c.getParameters());

        } finally {
            Security.insertProviderAt(saved, savedPos);
        }

        assertEquals(jceProvider,
            Cipher.getInstance("AESWrap").getProvider().getName());
    }

    @Test
    public void testAesWrapThreaded() throws InterruptedException {
        assumeEnabled();

        Assume.assumeTrue(FeatureDetect.Aes256Enabled());

        int numThreads = 30;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    int ret = 0;

                    try {
                        Cipher wrap = Cipher.getInstance("AESWrap",
                            jceProvider);
                        Cipher unwrap = Cipher.getInstance("AESWrap",
                            jceProvider);
                        SecretKeySpec kek = aesKey(KEK_256);
                        wrap.init(Cipher.WRAP_MODE, kek);
                        unwrap.init(Cipher.UNWRAP_MODE, kek);

                        for (int j = 0; j < 20; j++) {
                            byte[] wrapped = wrap.wrap(aesKey(DATA_256));
                            if (!Arrays.equals(WRAP_256_KEK256, wrapped)) {
                                ret = 1;
                            }
                            Key out = unwrap.unwrap(wrapped, "AES",
                                Cipher.SECRET_KEY);
                            if (!Arrays.equals(DATA_256, out.getEncoded())) {
                                ret = 1;
                            }

                            SecretKeySpec rnd = aesKey(randomBytes(32));
                            byte[] w2 = wrap.wrap(rnd);
                            Key o2 = unwrap.unwrap(w2, "AES",
                                Cipher.SECRET_KEY);
                            if (!Arrays.equals(rnd.getEncoded(),
                                    o2.getEncoded())) {
                                ret = 1;
                            }
                        }

                    } catch (Throwable t) {
                        t.printStackTrace();
                        ret = 1;
                    } finally {
                        results.add(ret);
                        latch.countDown();
                    }
                }
            });
        }

        boolean finished = latch.await(60, TimeUnit.SECONDS);
        service.shutdown();
        assertTrue("worker threads did not finish", finished);

        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in AES Key Wrap Cipher thread test");
            }
        }
    }
}
