/* wolfCryptCipherTest.java
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
import java.util.HashMap;
import java.util.Random;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.AEADBadTagException;

import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.AlgorithmParameters;
import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.AlgorithmParameters;

import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class WolfCryptCipherTest {

    /* all supported algos from wolfJCE provider, if enabled */
    private static String supportedJCEAlgos[] = {
        "AES/CBC/NoPadding",
        "AES/CBC/PKCS5Padding",
        "AES/CCM/NoPadding",
        "AES/CTR/NoPadding",
        "AES/ECB/NoPadding",
        "AES", /* maps to AES/ECB/PKCS5Padding */
        "AES/ECB/PKCS5Padding",
        "AES/GCM/NoPadding",
        "AES/OFB/NoPadding",
        "DESede/CBC/NoPadding",
        "RSA",
        "RSA/ECB/PKCS1Padding"
    };

    /* JCE provider to run below tests against */
    private static final String jceProvider = "wolfJCE";

    /* Interop provider, may be changed in testProviderInstallationAtRuntime */
    private static String interopProvider = null;

    /* populated with all enabled algos (some could have been compiled out) */
    private static ArrayList<String> enabledJCEAlgos =
        new ArrayList<String>();

    private static HashMap<String, Integer> expectedBlockSizes =
        new HashMap<String, Integer>();

    /* One static SecureRandom to share */
    private static SecureRandom secureRandom = new SecureRandom();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException, NoSuchPaddingException {

        System.out.println("JCE WolfCryptCipher Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider(jceProvider);
        assertNotNull(p);

        /* populate enabledJCEAlgos to test */
        for (int i = 0; i < supportedJCEAlgos.length; i++) {
            try {
                Cipher.getInstance(supportedJCEAlgos[i], jceProvider);
                enabledJCEAlgos.add(supportedJCEAlgos[i]);

            } catch (NoSuchAlgorithmException e) {
                /* algorithm not enabled */
            }
        }

        /* fill expected block size HashMap */
        expectedBlockSizes.put("AES/CBC/NoPadding", 16);
        expectedBlockSizes.put("AES/CBC/PKCS5Padding", 16);
        expectedBlockSizes.put("AES/CCM/NoPadding", 16);
        expectedBlockSizes.put("AES/CTR/NoPadding", 16);
        expectedBlockSizes.put("AES/ECB/NoPadding", 16);
        expectedBlockSizes.put("AES", 16);
        expectedBlockSizes.put("AES/ECB/PKCS5Padding", 16);
        expectedBlockSizes.put("AES/GCM/NoPadding", 16);
        expectedBlockSizes.put("AES/OFB/NoPadding", 16);
        expectedBlockSizes.put("DESede/CBC/NoPadding", 8);
        expectedBlockSizes.put("RSA", 0);
        expectedBlockSizes.put("RSA/ECB/PKCS1Padding", 0);

        /* try to set up interop provider, if available */
        /* NOTE: add other platform providers here if needed */
        p = Security.getProvider("SunJCE");
        if (p != null) {
            interopProvider = "SunJCE";
        }
    }

    @Test
    public void testGetCipherFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException {

        /* try to get all available options we expect to have */
        for (int i = 0; i < enabledJCEAlgos.size(); i++) {
            Cipher.getInstance(enabledJCEAlgos.get(i), jceProvider);
        }

        /* getting a garbage algorithm should throw
         * a NoSuchAlgorithmException */
        try {
            Cipher.getInstance("NotValid", jceProvider);

            fail("Cipher.getInstance should throw NoSuchAlgorithmException " +
                 "when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testGetBlockSize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException {

        Cipher cipher;

        for (int i = 0; i < enabledJCEAlgos.size(); i++) {
            cipher = Cipher.getInstance(enabledJCEAlgos.get(i), jceProvider);

            if (cipher.getBlockSize() !=
                    expectedBlockSizes.get((enabledJCEAlgos.get(i)))) {
                fail("Expected Cipher block size did not match, " +
                        "algo = " + enabledJCEAlgos.get(i));
            }
        }
    }

    @Test
    public void testAesInvalidModeThrowsInvalidParameterException()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        Cipher cipher;

        try {
            cipher = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
        } catch (NoSuchAlgorithmException e) {
            /* skip if AES-CBC is not enabled */
            return;
        }

        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);

        int invalidMode = 100;

        try {
            cipher.init(invalidMode, keySpec, ivSpec);
            fail("Cipher.init() with invalid mode should throw " +
                 "InvalidParameterException");
        } catch (InvalidParameterException e) {
            /* expected */
        }
    }

    @Test
    public void testAesCbcNoPadding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector vectors[] = new CipherVector[] {
            /* test vectors {key, iv, input, output, tag, aad } */
            new CipherVector(
                new byte[] {
                    (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
                    (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
                    (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
                    (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
                },
                new byte[] {
                    (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                    (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                    (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
                    (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
                },
                new byte[] {
                    (byte)0x6e, (byte)0x6f, (byte)0x77, (byte)0x20,
                    (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
                    (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
                    (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20
                },
                new byte[] {
                    (byte)0x95, (byte)0x94, (byte)0x92, (byte)0x57,
                    (byte)0x5f, (byte)0x42, (byte)0x81, (byte)0x53,
                    (byte)0x2c, (byte)0xcc, (byte)0x9d, (byte)0x46,
                    (byte)0x77, (byte)0xa2, (byte)0x33, (byte)0xcb
                },
                null, null
            )
        };

        byte output[];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);

        for (int i = 0; i < vectors.length; i++) {

            SecretKeySpec key = new SecretKeySpec(vectors[i].getKey(), "AES");
            IvParameterSpec spec = new IvParameterSpec(vectors[i].getIV());

            /* getOutputSize() before init() should throw exception */
            try {
                cipher.getOutputSize(vectors[i].getInput().length);
                fail("getOutputSize() before init() should fail");
            } catch (IllegalStateException e) {
                /* expected, continue */
            }

            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            assertEquals(vectors[i].getOutput().length,
                cipher.getOutputSize(vectors[i].getInput().length));

            output = cipher.doFinal(vectors[i].input);

            assertArrayEquals(output, vectors[i].output);
        }
    }

    @Test
    public void testAesCbcNoPaddingWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte key[] = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte iv[] = new byte[] {
            (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
            (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
            (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte input[] = new byte[] {
            (byte)0x6e, (byte)0x6f, (byte)0x77, (byte)0x20,
            (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
            (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
            (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20
        };

        byte expected[] = new byte[] {
            (byte)0x95, (byte)0x94, (byte)0x92, (byte)0x57,
            (byte)0x5f, (byte)0x42, (byte)0x81, (byte)0x53,
            (byte)0x2c, (byte)0xcc, (byte)0x9d, (byte)0x46,
            (byte)0x77, (byte)0xa2, (byte)0x33, (byte)0xcb
        };

        byte tmp[];
        byte output[];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        /* test encrypt processing input in 4 byte chunks */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(input, 0, 4));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 4, 8));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 12));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 12, 16));
        assertEquals(tmp.length, 16);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, expected);

        /* test decrypt processing input in 4 byte chunks */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(expected, 0, 4));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(expected, 4, 8));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(expected, 8, 12));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(expected, 12, 16));
        assertEquals(tmp.length, 16);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, input);

        /* test encrypt processing in 1 byte chunks */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        for (int i = 1; i < input.length + 1; i++) {
            tmp = cipher.update(Arrays.copyOfRange(input, i-1, i));
            if ((i % 16) != 0) {
                assertNotNull(tmp);
                assertEquals(tmp.length, 0);
            } else {
                assertEquals(tmp.length, 16);
                output = Arrays.copyOfRange(tmp, 0, 16);
            }
        }

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, expected);

        /* test decrypt processing in 1 byte chunks */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        for (int i = 1; i < expected.length + 1; i++) {
            tmp = cipher.update(Arrays.copyOfRange(expected, i-1, i));
            if ((i % 16) != 0) {
                assertNotNull(tmp);
                assertEquals(tmp.length, 0);
            } else {
                assertEquals(tmp.length, 16);
                output = Arrays.copyOfRange(tmp, 0, 16);
            }
        }

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, input);
    }

    @Test
    public void testAesCbcNoPaddingWithOddUpdateFail()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte key[] = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte iv[] = new byte[] {
            (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
            (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
            (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte input[] = new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
            (byte)0x09, (byte)0x10, (byte)0x11, (byte)0x12,
            (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16,
            (byte)0x17, (byte)0x18, (byte)0x19, (byte)0x20,
        };

        byte tmp[];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        /* test that doFinal on non-block size input fails */
        tmp = cipher.update(Arrays.copyOfRange(input, 0, 8));        /* 8 */
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 12));       /* 4 */
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 12, 16));      /* 4 */
        assertEquals(tmp.length, 16);

        try {
            tmp = cipher.doFinal(Arrays.copyOfRange(input, 16, 20)); /* 4 */
            fail("cipher.doFinal on odd size block cipher input should " +
                 "throw exception");
        } catch (IllegalBlockSizeException e) {
            assertTrue(e.getMessage().contains("not multiple of 16 bytes"));
        }
    }

    @Test
    public void testAesCbcNoPaddingWithOddUpdateSuccess()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte key[] = new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
        };

        byte iv[] = new byte[] {
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
        };

        byte input[] = new byte[] {
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
        };

        byte expected[] = new byte[] {
            (byte) 0x8d, (byte) 0xda, (byte) 0x93, (byte) 0x7a,
            (byte) 0x61, (byte) 0xf5, (byte) 0xc9, (byte) 0x98,
            (byte) 0x19, (byte) 0x67, (byte) 0xe2, (byte) 0xd3,
            (byte) 0x5a, (byte) 0xa9, (byte) 0x4e, (byte) 0x4f,
            (byte) 0x1a, (byte) 0x52, (byte) 0x0c, (byte) 0xab,
            (byte) 0x0c, (byte) 0xcc, (byte) 0xb7, (byte) 0x59,
            (byte) 0x4c, (byte) 0xe6, (byte) 0x71, (byte) 0x4e,
            (byte) 0x2a, (byte) 0x60, (byte) 0x71, (byte) 0x70,
            (byte) 0x56, (byte) 0x69, (byte) 0xeb, (byte) 0x20,
            (byte) 0xea, (byte) 0xf1, (byte) 0xfe, (byte) 0x75,
            (byte) 0x9a, (byte) 0x08, (byte) 0x17, (byte) 0xd3,
            (byte) 0xa3, (byte) 0x8e, (byte) 0x04, (byte) 0x8c,
        };

        byte tmp[];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(input, 0, 16));       /* 16 */
        assertArrayEquals(tmp, Arrays.copyOfRange(expected, 0, 16));

        tmp = cipher.update(Arrays.copyOfRange(input, 16, 17));      /* 1 */
        assertNotNull(tmp);
        assertEquals(0, tmp.length);

        tmp = cipher.update(Arrays.copyOfRange(input, 17, 33));      /* 16 */
        assertArrayEquals(tmp, Arrays.copyOfRange(expected, 16, 32));

        tmp = cipher.update(Arrays.copyOfRange(input, 33, 34));      /* 1 */
        assertNotNull(tmp);
        assertEquals(0, tmp.length);

        tmp = cipher.doFinal(Arrays.copyOfRange(input, 34, 48));     /* 14 */
        assertArrayEquals(tmp, Arrays.copyOfRange(expected, 32, 48));
    }

    @Test
    public void testAesCbcNoPaddingWithUpdateVerifyFinalResetsState()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte key[] = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte iv[] = new byte[] {
            (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
            (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
            (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte input[] = new byte[] {
            (byte)0x6e, (byte)0x6f, (byte)0x77, (byte)0x20,
            (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
            (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
            (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20
        };

        byte expected[] = new byte[] {
            (byte)0x95, (byte)0x94, (byte)0x92, (byte)0x57,
            (byte)0x5f, (byte)0x42, (byte)0x81, (byte)0x53,
            (byte)0x2c, (byte)0xcc, (byte)0x9d, (byte)0x46,
            (byte)0x77, (byte)0xa2, (byte)0x33, (byte)0xcb
        };

        byte tmp[];
        byte output[];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        /* test encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(input, 0, 8));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 16));
        assertEquals(tmp.length, 16);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, expected);

        /* doFinal should have reset our state, try to encrypt again no init */
        tmp = cipher.update(Arrays.copyOfRange(input, 0, 8));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 16));
        assertEquals(tmp.length, 16);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, expected);

        /* test decrypt */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(expected, 0, 8));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(expected, 8, 16));
        assertEquals(tmp.length, 16);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, input);

        /* doFinal should have reset our state, try to decrypt again no init */
        tmp = cipher.update(Arrays.copyOfRange(expected, 0, 8));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(expected, 8, 16));
        assertEquals(tmp.length, 16);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(output, input);
    }

    @Test
    public void testAesCbcNoPaddingBigMessage()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        final byte input[] = new byte[] {
            /* "All work and no play makes Jack a dull boy. " */
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20
        };

        final byte key[] = "0123456789abcdeffedcba9876543210".getBytes();
        final byte iv[]  = "1234567890abcdef".getBytes();

        byte cipher[] = new byte[input.length];
        byte plain[]  = new byte[input.length];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher ciph = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
        SecretKeySpec secretkey = new SecretKeySpec(key, "AES");
        IvParameterSpec spec = new IvParameterSpec(iv);

        /* encrypt big message */
        ciph.init(Cipher.ENCRYPT_MODE, secretkey, spec);
        cipher = ciph.doFinal(input);

        /* decrypt cipher */
        ciph.init(Cipher.DECRYPT_MODE, secretkey, spec);
        plain = ciph.doFinal(cipher);

        assertArrayEquals(plain, input);
    }

    /* Cipher.getInstance("AES") is just AES/ECB/PKCS5Padding, so we
     * do one test that here. */
    @Test
    public void testAesGeneric()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!FeatureDetect.AesEcbEnabled()) {
            /* skip if AES is not enabled */
            return;
        }

        byte key[] = new byte[] {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        /* Test with data that needs padding.
         * 12 bytes, needs 4 bytes padding */
        byte input[] = "Hello World!".getBytes();

        Cipher cipher = Cipher.getInstance("AES", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        /* Test encryption */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ciphertext = cipher.doFinal(input);

        /* Ciphertext should be block-aligned (16 bytes) */
        assertEquals(16, ciphertext.length);

        /* Test decryption */
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals(input, decrypted);

        /* Test with exact block size data */
        byte blockSizeInput[] = new byte[16];
        Arrays.fill(blockSizeInput, (byte)0x41); /* Fill with 'A' */

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] blockCiphertext = cipher.doFinal(blockSizeInput);

        /* Should be 32 bytes (original 16 + 16 bytes padding) */
        assertEquals(32, blockCiphertext.length);

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] blockDecrypted = cipher.doFinal(blockCiphertext);

        assertArrayEquals(blockSizeInput, blockDecrypted);
    }

    @Test
    public void testAesCbcPKCS5Padding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector vectors[] = new CipherVector[] {
            /* test vectors {key, iv, input, output } */
            new CipherVector(
                new byte[] {
                    (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
                    (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
                    (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
                    (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
                },
                new byte[] {
                    (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                    (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                    (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
                    (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
                },
                new byte[] {
                    (byte)0x6e, (byte)0x6f, (byte)0x77, (byte)0x20,
                    (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
                    (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
                    (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20
                },
                new byte[] {
                    (byte)0x95, (byte)0x94, (byte)0x92, (byte)0x57,
                    (byte)0x5f, (byte)0x42, (byte)0x81, (byte)0x53,
                    (byte)0x2c, (byte)0xcc, (byte)0x9d, (byte)0x46,
                    (byte)0x77, (byte)0xa2, (byte)0x33, (byte)0xcb,
                    (byte)0x7d, (byte)0x37, (byte)0x7b, (byte)0x0b,
                    (byte)0x44, (byte)0xaa, (byte)0xb5, (byte)0xf0,
                    (byte)0x5f, (byte)0x34, (byte)0xb4, (byte)0xde,
                    (byte)0xb5, (byte)0xbd, (byte)0x2a, (byte)0xbb
                },
                null, null
            )
        };

        byte output[];

        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);

        for (int i = 0; i < vectors.length; i++) {

            SecretKeySpec key = new SecretKeySpec(vectors[i].getKey(), "AES");
            IvParameterSpec spec = new IvParameterSpec(vectors[i].getIV());

            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            output = cipher.doFinal(vectors[i].input);

            assertArrayEquals(output, vectors[i].output);
        }
    }

    @Test
    public void testAesCbcPKCS5PaddingWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte[] key = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte[] iv = new byte[] {
            (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
            (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
            (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte[] input = new byte[] {
            (byte)0x6e, (byte)0x6f, (byte)0x77, (byte)0x20,
            (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
            (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
            (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20
        };

        byte[] expected = new byte[] {
            (byte)0x95, (byte)0x94, (byte)0x92, (byte)0x57,
            (byte)0x5f, (byte)0x42, (byte)0x81, (byte)0x53,
            (byte)0x2c, (byte)0xcc, (byte)0x9d, (byte)0x46,
            (byte)0x77, (byte)0xa2, (byte)0x33, (byte)0xcb,
            (byte)0x7d, (byte)0x37, (byte)0x7b, (byte)0x0b,
            (byte)0x44, (byte)0xaa, (byte)0xb5, (byte)0xf0,
            (byte)0x5f, (byte)0x34, (byte)0xb4, (byte)0xde,
            (byte)0xb5, (byte)0xbd, (byte)0x2a, (byte)0xbb
        };

        byte[] tmp = null;
        byte[] output = null;
        byte[] finalOutput = null;

        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        /* test encrypt processing input in 4 byte chunks */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(input, 0, 4));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(input, 4, 8));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 12));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(input, 12, 16));
        assertEquals(16, tmp.length);
        output = Arrays.copyOfRange(tmp, 0, 16);

        /* final should add extra block of encrypted padding with PKCS5 pad */
        tmp = cipher.doFinal();
        assertEquals(16, tmp.length);

        /* put together full output and compare to expected */
        finalOutput = new byte[output.length + tmp.length];
        System.arraycopy(output, 0, finalOutput, 0, output.length);
        System.arraycopy(tmp, 0, finalOutput, output.length, tmp.length);
        assertArrayEquals(finalOutput, expected);

        /* test decrypt processing input in 4 byte chunks */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(expected, 0, 4));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 4, 8));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 8, 12));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 12, 16));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 16, 20));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 20, 24));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 24, 28));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 28, 32));
        /* since encrypted had 16 bytes of padding added internally, once
         * reaching 32-bytes, 16 should be returned (without padding) */
        assertEquals(16, tmp.length);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertEquals(0, tmp.length);
        assertArrayEquals(output, input);

        /* test encrypt processing in 1 byte chunks */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        for (int i = 1; i < input.length + 1; i++) {
            tmp = cipher.update(Arrays.copyOfRange(input, i-1, i));
            if ((i % 16) != 0) {
                assertNotNull(tmp);
                assertEquals(0, tmp.length);
            } else {
                assertEquals(16, tmp.length);
                output = Arrays.copyOfRange(tmp, 0, 16);
            }
        }

        /* final should add extra block of encrypted padding with PKCS5 pad */
        tmp = cipher.doFinal();
        assertEquals(16, tmp.length);

        /* put together full output and compare to expected */
        finalOutput = new byte[output.length + tmp.length];
        System.arraycopy(output, 0, finalOutput, 0, output.length);
        System.arraycopy(tmp, 0, finalOutput, output.length, tmp.length);
        assertArrayEquals(finalOutput, expected);

        /* test decrypt processing in 1 byte chunks */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        finalOutput = new byte[0];

        for (int i = 0; i < expected.length; i++) {
            tmp = cipher.update(Arrays.copyOfRange(expected, i, i+1));
            if (tmp != null && tmp.length > 0) {
                /* append data to final output buffer */
                output = new byte[finalOutput.length + tmp.length];
                System.arraycopy(finalOutput, 0, output, 0, finalOutput.length);
                System.arraycopy(tmp, 0, output, finalOutput.length,
                    tmp.length);
                finalOutput = output;
            }
        }

        tmp = cipher.doFinal();
        assertEquals(tmp.length, 0);
        assertArrayEquals(input, finalOutput);
    }

    @Test
    public void testAesCbcPKCS5PaddingWithOddUpdateFail()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte[] key = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte[] iv = new byte[] {
            (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
            (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
            (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte[] input = new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
            (byte)0x09, (byte)0x10, (byte)0x11, (byte)0x12,
            (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16,
            (byte)0x17, (byte)0x18, (byte)0x19, (byte)0x20,
        };

        byte[] expected = new byte[] {
            (byte)0xb3, (byte)0xc2, (byte)0x53, (byte)0x43,
            (byte)0x64, (byte)0xa6, (byte)0x19, (byte)0x8d,
            (byte)0x9c, (byte)0x05, (byte)0x7e, (byte)0xf0,
            (byte)0xaa, (byte)0x20, (byte)0x13, (byte)0x7f,
            (byte)0x15, (byte)0x66, (byte)0x51, (byte)0xf5,
            (byte)0x27, (byte)0x3b, (byte)0xea, (byte)0xc4,
            (byte)0xcf, (byte)0xb5, (byte)0xcc, (byte)0xfa,
            (byte)0x9e, (byte)0xc2, (byte)0xcc, (byte)0x37
        };

        byte[] tmp = null;
        byte[] output = null;
        byte[] finalOutput = null;

        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        /* test that doFinal on non-block size input correctly pads */
        tmp = cipher.update(Arrays.copyOfRange(input, 0, 8));        /* 8 */
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 12));       /* 4 */
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        output = cipher.update(Arrays.copyOfRange(input, 12, 16));   /* 4 */
        assertEquals(output.length, 16);

        /* partial last block, total message size of 20 bytes */
        tmp = cipher.doFinal(Arrays.copyOfRange(input, 16, 20));     /* 4 */
        assertNotNull(tmp);
        assertEquals(tmp.length, 16);

        finalOutput = new byte[output.length + tmp.length];
        System.arraycopy(output, 0, finalOutput, 0, output.length);
        System.arraycopy(tmp, 0, finalOutput, output.length, tmp.length);

        assertArrayEquals(expected, finalOutput);
    }

    @Test
    public void testAesCbcPKCS5PaddingWithOddUpdateSuccess()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte key[] = new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
        };

        byte iv[] = new byte[] {
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
        };

        byte input[] = new byte[] {
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
        };

        byte expected[] = new byte[] {
            (byte) 0x8d, (byte) 0xda, (byte) 0x93, (byte) 0x7a,
            (byte) 0x61, (byte) 0xf5, (byte) 0xc9, (byte) 0x98,
            (byte) 0x19, (byte) 0x67, (byte) 0xe2, (byte) 0xd3,
            (byte) 0x5a, (byte) 0xa9, (byte) 0x4e, (byte) 0x4f,
            (byte) 0x1a, (byte) 0x52, (byte) 0x0c, (byte) 0xab,
            (byte) 0x0c, (byte) 0xcc, (byte) 0xb7, (byte) 0x59,
            (byte) 0x4c, (byte) 0xe6, (byte) 0x71, (byte) 0x4e,
            (byte) 0x2a, (byte) 0x60, (byte) 0x71, (byte) 0x70,
            (byte) 0x56, (byte) 0x69, (byte) 0xeb, (byte) 0x20,
            (byte) 0xea, (byte) 0xf1, (byte) 0xfe, (byte) 0x75,
            (byte) 0x9a, (byte) 0x08, (byte) 0x17, (byte) 0xd3,
            (byte) 0xa3, (byte) 0x8e, (byte) 0x04, (byte) 0x8c,
            (byte) 0x06, (byte) 0x60, (byte) 0xe6, (byte) 0x90,
            (byte) 0x6b, (byte) 0xa4, (byte) 0x0a, (byte) 0xe9,
            (byte) 0x36, (byte) 0x62, (byte) 0xef, (byte) 0xf2,
            (byte) 0x0f, (byte) 0x77, (byte) 0x1c, (byte) 0xff
        };

        byte tmp[];

        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(input, 0, 16));       /* 16 */
        assertArrayEquals(tmp, Arrays.copyOfRange(expected, 0, 16));

        tmp = cipher.update(Arrays.copyOfRange(input, 16, 17));      /* 1 */
        assertNotNull(tmp);
        assertEquals(0, tmp.length);

        tmp = cipher.update(Arrays.copyOfRange(input, 17, 33));      /* 16 */
        assertArrayEquals(tmp, Arrays.copyOfRange(expected, 16, 32));

        tmp = cipher.update(Arrays.copyOfRange(input, 33, 34));      /* 1 */
        assertNotNull(tmp);
        assertEquals(0, tmp.length);

        tmp = cipher.doFinal(Arrays.copyOfRange(input, 34, 48));     /* 14 */
        assertArrayEquals(tmp, Arrays.copyOfRange(expected, 32, 64));
    }

    @Test
    public void testAesCbcPKCS5PaddingWithUpdateVerifyFinalResetsState()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte[] key = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte[] iv = new byte[] {
            (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
            (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
            (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        byte[] input = new byte[] {
            (byte)0x6e, (byte)0x6f, (byte)0x77, (byte)0x20,
            (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
            (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
            (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20
        };

        byte[] expected = new byte[] {
            (byte)0x95, (byte)0x94, (byte)0x92, (byte)0x57,
            (byte)0x5f, (byte)0x42, (byte)0x81, (byte)0x53,
            (byte)0x2c, (byte)0xcc, (byte)0x9d, (byte)0x46,
            (byte)0x77, (byte)0xa2, (byte)0x33, (byte)0xcb,
            (byte)0x7d, (byte)0x37, (byte)0x7b, (byte)0x0b,
            (byte)0x44, (byte)0xaa, (byte)0xb5, (byte)0xf0,
            (byte)0x5f, (byte)0x34, (byte)0xb4, (byte)0xde,
            (byte)0xb5, (byte)0xbd, (byte)0x2a, (byte)0xbb
        };

        byte[] tmp = null;
        byte[] output = null;
        byte[] finalOutput = null;

        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        /* test encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(input, 0, 8));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 16));
        assertEquals(16, tmp.length);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertNotNull(tmp);
        assertEquals(16, tmp.length);

        /* put together full output and compare to expected */
        finalOutput = new byte[output.length + tmp.length];
        System.arraycopy(output, 0, finalOutput, 0, output.length);
        System.arraycopy(tmp, 0, finalOutput, output.length, tmp.length);
        assertArrayEquals(finalOutput, expected);

        /* doFinal should have reset our state, try to encrypt again no init */
        tmp = cipher.update(Arrays.copyOfRange(input, 0, 8));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(input, 8, 16));
        assertEquals(16, tmp.length);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertNotNull(tmp);
        assertEquals(16, tmp.length);

        /* put together full output and compare to expected */
        finalOutput = new byte[output.length + tmp.length];
        System.arraycopy(output, 0, finalOutput, 0, output.length);
        System.arraycopy(tmp, 0, finalOutput, output.length, tmp.length);
        assertArrayEquals(finalOutput, expected);

        /* test decrypt */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        tmp = cipher.update(Arrays.copyOfRange(expected, 0, 8));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 8, 16));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 16, 24));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 24, 32));
        assertNotNull(tmp);
        assertEquals(16, tmp.length);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        assertArrayEquals(input, output);

        /* doFinal should have reset our state, try to decrypt again no init */
        tmp = cipher.update(Arrays.copyOfRange(expected, 0, 8));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 8, 16));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 16, 24));
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        tmp = cipher.update(Arrays.copyOfRange(expected, 24, 32));
        assertNotNull(tmp);
        assertEquals(16, tmp.length);
        output = Arrays.copyOfRange(tmp, 0, 16);

        tmp = cipher.doFinal();
        assertNotNull(tmp);
        assertEquals(0, tmp.length);
        assertArrayEquals(input, output);
    }

    @Test
    public void testAesCbcPKCS5PaddingBigMessage()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        final byte[] input = new byte[] {
            /* "All work and no play makes Jack a dull boy. " */
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20,
            (byte)0x61, (byte)0x20, (byte)0x64, (byte)0x75,
            (byte)0x6c, (byte)0x6c, (byte)0x20, (byte)0x62,
            (byte)0x6f, (byte)0x79, (byte)0x2e, (byte)0x20,
            (byte)0x41, (byte)0x6c, (byte)0x6c, (byte)0x20,
            (byte)0x77, (byte)0x6f, (byte)0x72, (byte)0x6b,
            (byte)0x20, (byte)0x61, (byte)0x6e, (byte)0x64,
            (byte)0x20, (byte)0x6e, (byte)0x6f, (byte)0x20,
            (byte)0x70, (byte)0x6c, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6d, (byte)0x61, (byte)0x6b,
            (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4a,
            (byte)0x61, (byte)0x63, (byte)0x6b, (byte)0x20
        };

        final byte[] key = "0123456789abcdeffedcba9876543210".getBytes();
        final byte[] iv  = "1234567890abcdef".getBytes();

        byte[] cipher = null;
        byte[] plain  = null;

        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher ciph = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
        SecretKeySpec secretkey = new SecretKeySpec(key, "AES");
        IvParameterSpec spec = new IvParameterSpec(iv);

        /* encrypt big message */
        ciph.init(Cipher.ENCRYPT_MODE, secretkey, spec);
        cipher = ciph.doFinal(input);

        /* decrypt cipher */
        ciph.init(Cipher.DECRYPT_MODE, secretkey, spec);
        plain = ciph.doFinal(cipher);

        assertArrayEquals(plain, input);
    }

    @Test
    public void testAesCbcThreaded() throws InterruptedException {

        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();
        final byte[] rand2kBuf = new byte[2048];

        final byte[] key = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };
        final byte[] iv = new byte[] {
            (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
            (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
            (byte)0x39, (byte)0x30, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* skip if AES/CBC/NoPadding is not enabled */
            return;
        }

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand2kBuf);

        /* encrypt / decrypt input data, make sure decrypted matches original */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int ret = 0;

                    try {
                        Cipher enc = Cipher.getInstance(
                            "AES/CBC/NoPadding", jceProvider);
                        enc.init(Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(key, "AES"),
                            new IvParameterSpec(iv));

                        Cipher dec = Cipher.getInstance(
                            "AES/CBC/NoPadding", jceProvider);
                        dec.init(Cipher.DECRYPT_MODE,
                            new SecretKeySpec(key, "AES"),
                            new IvParameterSpec(iv));

                        byte[] encrypted = new byte[2048];
                        byte[] plaintext = new byte[2048];

                        /* encrypt in 128-byte chunks */
                        Arrays.fill(encrypted, (byte)0);
                        for (int j = 0; j < rand2kBuf.length; j+= 128) {
                            ret = enc.update(rand2kBuf, j, 128, encrypted, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Cipher.update(Aes,ENCRYPT_MODE) returned "
                                    + ret);
                            }
                        }

                        /* decrypt in 128-byte chunks */
                        Arrays.fill(plaintext, (byte)0);
                        for (int j = 0; j < encrypted.length; j+= 128) {
                            ret = dec.update(encrypted, j, 128, plaintext, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Cipher.update(Aes,DECRYPT_MODE) returned "
                                    + ret);
                            }
                        }

                        /* make sure decrypted is same as input */
                        if (Arrays.equals(rand2kBuf, plaintext)) {
                            results.add(0);
                        }
                        else {
                            /* not equal, error case */
                            results.add(1);
                        }

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
                fail("Threading error in AES Cipher thread test");
            }
        }
    }

    /* test vectors {key, iv, input, output, tag, aad } */
    CipherVector aesGcmVectors[] = new CipherVector[] {
        /* AES-GCM-128 */
        /* The following is an interesting test case from the example
         * FIPS test vectors for AES-GCM. IVlen = 1 byte */
        new CipherVector(
            new byte[] { /* key (k3 from test.c) */
                (byte)0xbb, (byte)0x01, (byte)0xd7, (byte)0x03,
                (byte)0x81, (byte)0x1c, (byte)0x10, (byte)0x1a,
                (byte)0x35, (byte)0xe0, (byte)0xff, (byte)0xd2,
                (byte)0x91, (byte)0xba, (byte)0xf2, (byte)0x4b
            },
            new byte[] { /* iv (iv3 from test.c) */
                (byte)0xca
            },
            new byte[] { /* input (p3 from test.c) */
                (byte)0x57, (byte)0xce, (byte)0x45, (byte)0x1f,
                (byte)0xa5, (byte)0xe2, (byte)0x35, (byte)0xa5,
                (byte)0x8e, (byte)0x1a, (byte)0xa2, (byte)0x3b,
                (byte)0x77, (byte)0xcb, (byte)0xaf, (byte)0xe2
            },
            new byte[] { /* output (c3 from test.c) */
                (byte)0x6b, (byte)0x5f, (byte)0xb3, (byte)0x9d,
                (byte)0xc1, (byte)0xc5, (byte)0x7a, (byte)0x4f,
                (byte)0xf3, (byte)0x51, (byte)0x4d, (byte)0xc2,
                (byte)0xd5, (byte)0xf0, (byte)0xd0, (byte)0x07
            },
            new byte[] { /* tag (t3 from test.c) */
                (byte)0x06, (byte)0x90, (byte)0xed, (byte)0x01,
                (byte)0x34, (byte)0xdd, (byte)0xc6, (byte)0x95,
                (byte)0x31, (byte)0x2e, (byte)0x2a, (byte)0xf9,
                (byte)0x57, (byte)0x7a, (byte)0x1e, (byte)0xa6
            },
            new byte[] { /* aad (a3 from test.c) */
                (byte)0x40, (byte)0xfc, (byte)0xdc, (byte)0xd7,
                (byte)0x4a, (byte)0xd7, (byte)0x8b, (byte)0xf1,
                (byte)0x3e, (byte)0x7c, (byte)0x60, (byte)0x55,
                (byte)0x50, (byte)0x51, (byte)0xdd, (byte)0x54
            }
        ),

        /* AES-GCM-192 */
        /* FIPS, QAT and PIC32MZ HW Crypto only support 12-byte IV */
        /* Test Case 12, uses same plaintext and AAD data. */
        new CipherVector(
            new byte[] { /* key (k2 from test.c) */
                (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
                (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c,
                (byte)0x6d, (byte)0x6a, (byte)0x8f, (byte)0x94,
                (byte)0x67, (byte)0x30, (byte)0x83, (byte)0x08,
                (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
                (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c
            },
            new byte[] { /* iv (iv2 from test.c) */
                (byte)0x93, (byte)0x13, (byte)0x22, (byte)0x5d,
                (byte)0xf8, (byte)0x84, (byte)0x06, (byte)0xe5,
                (byte)0x55, (byte)0x90, (byte)0x9c, (byte)0x5a,
                (byte)0xff, (byte)0x52, (byte)0x69, (byte)0xaa,
                (byte)0x6a, (byte)0x7a, (byte)0x95, (byte)0x38,
                (byte)0x53, (byte)0x4f, (byte)0x7d, (byte)0xa1,
                (byte)0xe4, (byte)0xc3, (byte)0x03, (byte)0xd2,
                (byte)0xa3, (byte)0x18, (byte)0xa7, (byte)0x28,
                (byte)0xc3, (byte)0xc0, (byte)0xc9, (byte)0x51,
                (byte)0x56, (byte)0x80, (byte)0x95, (byte)0x39,
                (byte)0xfc, (byte)0xf0, (byte)0xe2, (byte)0x42,
                (byte)0x9a, (byte)0x6b, (byte)0x52, (byte)0x54,
                (byte)0x16, (byte)0xae, (byte)0xdb, (byte)0xf5,
                (byte)0xa0, (byte)0xde, (byte)0x6a, (byte)0x57,
                (byte)0xa6, (byte)0x37, (byte)0xb3, (byte)0x9b
            },
            new byte[] { /* input (p from test.c) */
                (byte)0xd9, (byte)0x31, (byte)0x32, (byte)0x25,
                (byte)0xf8, (byte)0x84, (byte)0x06, (byte)0xe5,
                (byte)0xa5, (byte)0x59, (byte)0x09, (byte)0xc5,
                (byte)0xaf, (byte)0xf5, (byte)0x26, (byte)0x9a,
                (byte)0x86, (byte)0xa7, (byte)0xa9, (byte)0x53,
                (byte)0x15, (byte)0x34, (byte)0xf7, (byte)0xda,
                (byte)0x2e, (byte)0x4c, (byte)0x30, (byte)0x3d,
                (byte)0x8a, (byte)0x31, (byte)0x8a, (byte)0x72,
                (byte)0x1c, (byte)0x3c, (byte)0x0c, (byte)0x95,
                (byte)0x95, (byte)0x68, (byte)0x09, (byte)0x53,
                (byte)0x2f, (byte)0xcf, (byte)0x0e, (byte)0x24,
                (byte)0x49, (byte)0xa6, (byte)0xb5, (byte)0x25,
                (byte)0xb1, (byte)0x6a, (byte)0xed, (byte)0xf5,
                (byte)0xaa, (byte)0x0d, (byte)0xe6, (byte)0x57,
                (byte)0xba, (byte)0x63, (byte)0x7b, (byte)0x39
            },
            new byte[] { /* output (c2 from test.c) */
                (byte)0xd2, (byte)0x7e, (byte)0x88, (byte)0x68,
                (byte)0x1c, (byte)0xe3, (byte)0x24, (byte)0x3c,
                (byte)0x48, (byte)0x30, (byte)0x16, (byte)0x5a,
                (byte)0x8f, (byte)0xdc, (byte)0xf9, (byte)0xff,
                (byte)0x1d, (byte)0xe9, (byte)0xa1, (byte)0xd8,
                (byte)0xe6, (byte)0xb4, (byte)0x47, (byte)0xef,
                (byte)0x6e, (byte)0xf7, (byte)0xb7, (byte)0x98,
                (byte)0x28, (byte)0x66, (byte)0x6e, (byte)0x45,
                (byte)0x81, (byte)0xe7, (byte)0x90, (byte)0x12,
                (byte)0xaf, (byte)0x34, (byte)0xdd, (byte)0xd9,
                (byte)0xe2, (byte)0xf0, (byte)0x37, (byte)0x58,
                (byte)0x9b, (byte)0x29, (byte)0x2d, (byte)0xb3,
                (byte)0xe6, (byte)0x7c, (byte)0x03, (byte)0x67,
                (byte)0x45, (byte)0xfa, (byte)0x22, (byte)0xe7,
                (byte)0xe9, (byte)0xb7, (byte)0x37, (byte)0x3b
            },
            new byte[] { /* tag (t2 from test.c) */
                (byte)0xdc, (byte)0xf5, (byte)0x66, (byte)0xff,
                (byte)0x29, (byte)0x1c, (byte)0x25, (byte)0xbb,
                (byte)0xb8, (byte)0x56, (byte)0x8f, (byte)0xc3,
                (byte)0xd3, (byte)0x76, (byte)0xa6, (byte)0xd9
            },
            new byte[] { /* aad (a from test.c) */
                (byte)0xfe, (byte)0xed, (byte)0xfa, (byte)0xce,
                (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef,
                (byte)0xfe, (byte)0xed, (byte)0xfa, (byte)0xce,
                (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef,
                (byte)0xab, (byte)0xad, (byte)0xda, (byte)0xd2
            }
        ),

        /* AES-GCM-256 */
        /* This is Test Case 16 from the document Galois/Counter Mode of
         * Operation (GCM) by McGrew and Viega. */
        new CipherVector(
            new byte[] { /* key (k1 from test.c) */
                (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
                (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c,
                (byte)0x6d, (byte)0x6a, (byte)0x8f, (byte)0x94,
                (byte)0x67, (byte)0x30, (byte)0x83, (byte)0x08,
                (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
                (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c,
                (byte)0x6d, (byte)0x6a, (byte)0x8f, (byte)0x94,
                (byte)0x67, (byte)0x30, (byte)0x83, (byte)0x08
            },
            new byte[] { /* iv (iv1 from test.c) */
                (byte)0xca, (byte)0xfe, (byte)0xba, (byte)0xbe,
                (byte)0xfa, (byte)0xce, (byte)0xdb, (byte)0xad,
                (byte)0xde, (byte)0xca, (byte)0xf8, (byte)0x88
            },
            new byte[] { /* input (p from test.c) */
                (byte)0xd9, (byte)0x31, (byte)0x32, (byte)0x25,
                (byte)0xf8, (byte)0x84, (byte)0x06, (byte)0xe5,
                (byte)0xa5, (byte)0x59, (byte)0x09, (byte)0xc5,
                (byte)0xaf, (byte)0xf5, (byte)0x26, (byte)0x9a,
                (byte)0x86, (byte)0xa7, (byte)0xa9, (byte)0x53,
                (byte)0x15, (byte)0x34, (byte)0xf7, (byte)0xda,
                (byte)0x2e, (byte)0x4c, (byte)0x30, (byte)0x3d,
                (byte)0x8a, (byte)0x31, (byte)0x8a, (byte)0x72,
                (byte)0x1c, (byte)0x3c, (byte)0x0c, (byte)0x95,
                (byte)0x95, (byte)0x68, (byte)0x09, (byte)0x53,
                (byte)0x2f, (byte)0xcf, (byte)0x0e, (byte)0x24,
                (byte)0x49, (byte)0xa6, (byte)0xb5, (byte)0x25,
                (byte)0xb1, (byte)0x6a, (byte)0xed, (byte)0xf5,
                (byte)0xaa, (byte)0x0d, (byte)0xe6, (byte)0x57,
                (byte)0xba, (byte)0x63, (byte)0x7b, (byte)0x39
            },
            new byte[] { /* output (c1 from test.c) */
                (byte)0x52, (byte)0x2d, (byte)0xc1, (byte)0xf0,
                (byte)0x99, (byte)0x56, (byte)0x7d, (byte)0x07,
                (byte)0xf4, (byte)0x7f, (byte)0x37, (byte)0xa3,
                (byte)0x2a, (byte)0x84, (byte)0x42, (byte)0x7d,
                (byte)0x64, (byte)0x3a, (byte)0x8c, (byte)0xdc,
                (byte)0xbf, (byte)0xe5, (byte)0xc0, (byte)0xc9,
                (byte)0x75, (byte)0x98, (byte)0xa2, (byte)0xbd,
                (byte)0x25, (byte)0x55, (byte)0xd1, (byte)0xaa,
                (byte)0x8c, (byte)0xb0, (byte)0x8e, (byte)0x48,
                (byte)0x59, (byte)0x0d, (byte)0xbb, (byte)0x3d,
                (byte)0xa7, (byte)0xb0, (byte)0x8b, (byte)0x10,
                (byte)0x56, (byte)0x82, (byte)0x88, (byte)0x38,
                (byte)0xc5, (byte)0xf6, (byte)0x1e, (byte)0x63,
                (byte)0x93, (byte)0xba, (byte)0x7a, (byte)0x0a,
                (byte)0xbc, (byte)0xc9, (byte)0xf6, (byte)0x62
            },
            new byte[] { /* tag (t1 from test.c) */
                (byte)0x76, (byte)0xfc, (byte)0x6e, (byte)0xce,
                (byte)0x0f, (byte)0x4e, (byte)0x17, (byte)0x68,
                (byte)0xcd, (byte)0xdf, (byte)0x88, (byte)0x53,
                (byte)0xbb, (byte)0x2d, (byte)0x55, (byte)0x1b
            },
            new byte[] { /* aad (a from test.c) */
                (byte)0xfe, (byte)0xed, (byte)0xfa, (byte)0xce,
                (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef,
                (byte)0xfe, (byte)0xed, (byte)0xfa, (byte)0xce,
                (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef,
                (byte)0xab, (byte)0xad, (byte)0xda, (byte)0xd2
            }
        )
    };

    /*
     * Test Cipher("AES/GCM/NoPadding") processing with single call to
     * doFinal().
     */
    @Test
    public void testAesGcmNoPadding() throws NoSuchAlgorithmException,
        InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException,
        InvalidAlgorithmParameterException, BadPaddingException,
        NoSuchPaddingException {


        byte output[] = null;
        byte plain[] = null;

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);

        for (int i = 0; i < aesGcmVectors.length; i++) {

            /* skip AES-128 vector if not compiled in native library */
            if ((i == 0) && (!FeatureDetect.Aes128Enabled())) {
                continue;
            }

            /* skip AES-192 vector if not compiled in native library, or if
             * using wolfCrypt FIPS since it only supports 12-byte IVs */
            if ((i == 1) && (!FeatureDetect.Aes192Enabled() || Fips.enabled)) {
                continue;
            }

            /* skip AES-256 vector if not compiled in native library */
            if ((i == 2) && (!FeatureDetect.Aes256Enabled())) {
                continue;
            }

            byte[] vOut = aesGcmVectors[i].getOutput();
            byte[] vTag = aesGcmVectors[i].getTag();
            byte[] tmpOut = new byte[vOut.length + vTag.length];
            SecretKeySpec key = new SecretKeySpec(
                aesGcmVectors[i].getKey(), "AES");
            GCMParameterSpec spec = new GCMParameterSpec(
                (vTag.length * 8), aesGcmVectors[i].getIV());

            if (i == 0) {
                /* getOutputSize() before init() should throw exception */
                try {
                    enc.getOutputSize(aesGcmVectors[i].getInput().length);
                    fail("getOutputSize() before init() should fail");
                } catch (IllegalStateException e) {
                    /* expected, continue */
                }
            }

            /* Encrypt */
            enc.init(Cipher.ENCRYPT_MODE, key, spec);
            enc.updateAAD(aesGcmVectors[i].getAAD());
            assertEquals(tmpOut.length,
                enc.getOutputSize(aesGcmVectors[i].getInput().length));
            output = enc.doFinal(aesGcmVectors[i].getInput());

            /* Concatenate tag to ciphertext, JCE Cipher does this internally */
            System.arraycopy(vOut, 0, tmpOut, 0, vOut.length);
            System.arraycopy(vTag, 0, tmpOut, vOut.length, vTag.length);

            assertArrayEquals(tmpOut, output);

            /* Decrypt */
            dec.init(Cipher.DECRYPT_MODE, key, spec);
            dec.updateAAD(aesGcmVectors[i].getAAD());
            plain = dec.doFinal(output);

            /* plain is just ciphertext, no tag */
            assertArrayEquals(aesGcmVectors[i].getInput(), plain);

            /* ----- confirm wrong result if no AAD given but needed ----- */
            enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
            enc.init(Cipher.ENCRYPT_MODE, key, spec);
            output = enc.doFinal(aesGcmVectors[i].getInput());
            /* Concatenate tag to ciphertext, JCE Cipher does this internally */
            System.arraycopy(vOut, 0, tmpOut, 0, vOut.length);
            System.arraycopy(vTag, 0, tmpOut, vOut.length, vTag.length);
            if (Arrays.equals(tmpOut, output)) {
                fail("Encrypt without needed AAD should not match expected");
            }
        }
    }

    /*
     * Test Cipher("AES/GCM/NoPadding") with multiple calls to update()
     * on both encrypt and decrypt.
     */
    @Test
    public void testAesGcmNoPaddingWithUpdate()
        throws NoSuchAlgorithmException, InvalidKeyException,
               IllegalBlockSizeException, NoSuchProviderException,
               InvalidAlgorithmParameterException, BadPaddingException,
               NoSuchPaddingException {

        byte tmp[] = null;
        byte output[] = null;
        byte plain[] = null;

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);

        for (int i = 0; i < aesGcmVectors.length; i++) {

            int inIdx = 0;
            int outIdx = 0;
            int fourByteBlocks = 0;
            int remainingBytes = 0;
            byte[] vIn  = aesGcmVectors[i].getInput();
            byte[] vOut = aesGcmVectors[i].getOutput();
            byte[] vTag = aesGcmVectors[i].getTag();
            byte[] tmpOut = new byte[vOut.length + vTag.length];
            SecretKeySpec key = new SecretKeySpec(
                aesGcmVectors[i].getKey(), "AES");
            GCMParameterSpec spec = new GCMParameterSpec(
                (vTag.length * 8), aesGcmVectors[i].getIV());

            /* skip AES-128 vector if not compiled in native library */
            if ((i == 0) && (!FeatureDetect.Aes128Enabled())) {
                continue;
            }

            /* skip AES-192 vector if not compiled in native library, or if
             * using wolfCrypt FIPS since it only supports 12-byte IVs */
            if ((i == 1) && (!FeatureDetect.Aes192Enabled() || Fips.enabled)) {
                continue;
            }

            /* skip AES-256 vector if not compiled in native library */
            if ((i == 2) && (!FeatureDetect.Aes256Enabled())) {
                continue;
            }

            /* ----- ENCRYPT (vIn -> output) ----- */

            enc.init(Cipher.ENCRYPT_MODE, key, spec);
            enc.updateAAD(aesGcmVectors[i].getAAD());

            /* Expected output is size vOut + vTag.length */
            output = new byte[vOut.length + vTag.length];

            /* Process via update() by 4-byte blocks */
            fourByteBlocks = vIn.length / 4;
            remainingBytes = vIn.length % 4;

            for (int j = 0; j < fourByteBlocks; j++) {
                tmp = enc.update(Arrays.copyOfRange(vIn, inIdx, inIdx + 4));
                assertNotNull(tmp);
                /* AES-GCM stream API not supported in JCE yet */
                assertEquals(0, tmp.length);
                System.arraycopy(tmp, 0, output, outIdx, tmp.length);
                inIdx += 4;
                outIdx += tmp.length;
            }

            /* Process any remaining data (CipherVector.input length was not
             * a multiple of 4 bytes */
            if (remainingBytes > 0) {
                tmp = enc.update(Arrays.copyOfRange(vIn, inIdx,
                        inIdx + remainingBytes));
                assertNotNull(tmp);
                /* AES-GCM stream API not supported in JCE yet */
                assertEquals(0, tmp.length);
                System.arraycopy(tmp, 0, output, outIdx, tmp.length);
                inIdx += remainingBytes;
                outIdx += tmp.length;
            }

            /* doFinal() should get tag (or whole ciphertext if AES-GCM
             * streaming is not enabled at native wolfSSL level) */
            tmp = enc.doFinal();
            assertNotNull(tmp);
            /* AES-GCM stream API not supported in JCE yet */
            assertEquals(tmpOut.length, tmp.length);
            System.arraycopy(tmp, 0, output, outIdx, tmp.length);
            outIdx += tmp.length;

            /* Sanity check on total length written */
            assertEquals(output.length, outIdx);

            /* Concatenate tag to end of ciphertext from our test vector, JCE
             * Cipher class already does this internally and will be the format
             * returned from update/final */
            System.arraycopy(vOut, 0, tmpOut, 0, vOut.length);
            System.arraycopy(vTag, 0, tmpOut, vOut.length, vTag.length);

            /* Encrypted matches vector output? */
            assertArrayEquals(tmpOut, output);

            /* ----- DECRYPT (output -> plain) ----- */

            /* Sanity check, makes sure we built up output correctly */
            assertArrayEquals(tmpOut, output);

            /* Decrypt */
            dec.init(Cipher.DECRYPT_MODE, key, spec);
            dec.updateAAD(aesGcmVectors[i].getAAD());

            /* plain is just plaintext, no tag */
            plain = new byte[vIn.length];

            /* Process via update() by 4-byte blocks */
            fourByteBlocks = output.length / 4;
            remainingBytes = output.length % 4;

            inIdx = 0;
            outIdx = 0;

            for (int j = 0; j < fourByteBlocks; j++) {
                tmp = dec.update(Arrays.copyOfRange(output, inIdx, inIdx + 4));
                assertNotNull(tmp);
                /* AES-GCM stream API not supported in JCE yet */
                assertEquals(0, tmp.length);
                System.arraycopy(tmp, 0, plain, outIdx, tmp.length);
                inIdx += 4;
                outIdx += tmp.length;
            }

            /* Process any remaining data (output length was not
             * a multiple of 4 bytes */
            if (remainingBytes > 0) {
                tmp = dec.update(Arrays.copyOfRange(output, inIdx,
                        inIdx + remainingBytes));
                assertNotNull(tmp);
                /* AES-GCM stream API not supported in JCE yet */
                assertEquals(0, tmp.length);
                System.arraycopy(tmp, 0, plain, outIdx, tmp.length);
                inIdx += remainingBytes;
                outIdx += tmp.length;
            }

            /* doFinal() will return whole plaintext if AES-GCM
             * streaming is not enabled at native wolfSSL level */
            tmp = dec.doFinal();
            assertNotNull(tmp);
            /* AES-GCM stream API not supported in JCE yet */
            assertEquals(vIn.length, tmp.length);
            System.arraycopy(tmp, 0, plain, outIdx, tmp.length);
            outIdx += tmp.length;

            /* Sanity check on total length written */
            assertEquals(plain.length, outIdx);

            /* Decrypted matches vector input? */
            assertArrayEquals(vIn, plain);
        }
    }

    /*
     * Test Cipher("AES/GCM/NoPadding") to make sure updateAAD() correctly
     * throws an exception when called after a call to update or doFinal.
     */
    @Test
    public void testAesGcmNoPaddingUpdateAADByteArray()
        throws NoSuchAlgorithmException, InvalidKeyException,
               IllegalBlockSizeException, NoSuchProviderException,
               InvalidAlgorithmParameterException, BadPaddingException,
               NoSuchPaddingException {

        int i = 0;
        byte output[] = null;
        byte plain[] = null;
        CipherVector vect = null;
        byte[] vOut = null;
        byte[] vIn = null;
        byte[] vKey = null;
        byte[] vIV = null;
        byte[] vTag = null;
        byte[] vAAD = null;

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);

        /* Try to pick a vector based on what is compiled in natively,
         * doesn't matter too much which vector we get */
        if (FeatureDetect.Aes128Enabled()) {
            vect = aesGcmVectors[0];
        }
        else if (FeatureDetect.Aes192Enabled() && !Fips.enabled) {
            vect = aesGcmVectors[1];
        }
        else if (FeatureDetect.Aes256Enabled()) {
            vect = aesGcmVectors[2];
        }
        else {
            /* No test vector found, skipping test */
            return;
        }

        vOut = vect.getOutput();
        vIn = vect.getInput();
        vKey = vect.getKey();
        vIV = vect.getIV();
        vTag = vect.getTag();
        vAAD = vect.getAAD();

        byte[] tmpOut = new byte[vOut.length + vTag.length];
        SecretKeySpec key = new SecretKeySpec(vKey, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(
            (vTag.length * 8), vIV);

        /* Encrypt, test calling updateAAD() multiple times */
        enc.init(Cipher.ENCRYPT_MODE, key, spec);

        for (i = 0; i < vAAD.length; i++) {
            enc.updateAAD(new byte[] {vAAD[i]});
        }
        output = enc.doFinal(vIn);

        /* Concatenate tag to end of ciphertext, JCE Cipher class already
         * does this internally */
        System.arraycopy(vOut, 0, tmpOut, 0, vOut.length);
        System.arraycopy(vTag, 0, tmpOut, vOut.length, vTag.length);

        assertArrayEquals(tmpOut, output);

        /* Decrypt, test calling updateAAD() multiple times */
        dec.init(Cipher.DECRYPT_MODE, key, spec);
        for (i = 0; i < vAAD.length; i++) {
            dec.updateAAD(new byte[] {vAAD[i]});
        }
        plain = dec.doFinal(output);

        /* plain is just ciphertext, no tag */
        assertArrayEquals(vIn, plain);

        /* ----- updateAAD() after update() should fail ----- */
        enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);
        enc.update(vIn);
        try {
            enc.updateAAD(vAAD);
            fail("updateAAD() after update() should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* ----- updateAAD() throws exception if called before init ----- */
        enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        try {
            enc.updateAAD(vAAD);
            fail("updateAAD() before init() should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    /*
     * Test Cipher("AES/GCM/NoPadding") to make sure updateAAD() correctly
     * throws an exception when called after a call to update or doFinal,
     * using ByteBuffer method.
     */
    @Test
    public void testAesGcmNoPaddingUpdateAADByteBuffer()
        throws NoSuchAlgorithmException, InvalidKeyException,
               IllegalBlockSizeException, NoSuchProviderException,
               InvalidAlgorithmParameterException, BadPaddingException,
               NoSuchPaddingException {

        int i = 0;
        byte output[] = null;
        byte plain[] = null;
        CipherVector vect = null;
        byte[] vOut = null;
        byte[] vIn = null;
        byte[] vKey = null;
        byte[] vIV = null;
        byte[] vTag = null;
        byte[] vAAD = null;

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);

        /* Try to pick a vector based on what is compiled in natively,
         * doesn't matter too much which vector we get */
        if (FeatureDetect.Aes128Enabled()) {
            vect = aesGcmVectors[0];
        }
        else if (FeatureDetect.Aes192Enabled() && !Fips.enabled) {
            vect = aesGcmVectors[1];
        }
        else if (FeatureDetect.Aes256Enabled()) {
            vect = aesGcmVectors[2];
        }
        else {
            /* No test vector found, skipping test */
            return;
        }

        vOut = vect.getOutput();
        vIn = vect.getInput();
        vKey = vect.getKey();
        vIV = vect.getIV();
        vTag = vect.getTag();
        vAAD = vect.getAAD();

        byte[] tmpOut = new byte[vOut.length + vTag.length];
        SecretKeySpec key = new SecretKeySpec(vKey, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(
            (vTag.length * 8), vIV);

        /* Encrypt, test calling updateAAD() multiple times */
        enc.init(Cipher.ENCRYPT_MODE, key, spec);

        for (i = 0; i < vAAD.length; i++) {
            enc.updateAAD(ByteBuffer.wrap(new byte[] {vAAD[i]}));
        }
        output = enc.doFinal(vIn);

        /* Concatenate tag to end of ciphertext, JCE Cipher class already
         * does this internally */
        System.arraycopy(vOut, 0, tmpOut, 0, vOut.length);
        System.arraycopy(vTag, 0, tmpOut, vOut.length, vTag.length);

        assertArrayEquals(tmpOut, output);

        /* Decrypt, test calling updateAAD() multiple times */
        dec.init(Cipher.DECRYPT_MODE, key, spec);
        for (i = 0; i < vAAD.length; i++) {
            dec.updateAAD(ByteBuffer.wrap(new byte[] {vAAD[i]}));
        }
        plain = dec.doFinal(output);

        /* plain is just ciphertext, no tag */
        assertArrayEquals(vIn, plain);

        /* ----- updateAAD() after update() should fail ----- */
        enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);
        enc.update(vIn);
        try {
            enc.updateAAD(ByteBuffer.wrap(vAAD));
            fail("updateAAD() after update() should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* ----- updateAAD() throws exception if called before init ----- */
        enc = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        try {
            enc.updateAAD(ByteBuffer.wrap(vAAD));
            fail("updateAAD() before init() should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    /*
     * Test Cipher("AES/GCM/NoPadding") interop if other provider is available.
     */
    @Test
    public void testAesGcmNoPaddingInterop() throws NoSuchAlgorithmException,
        InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException,
        InvalidAlgorithmParameterException, BadPaddingException,
        NoSuchPaddingException {


        byte cipher[] = null;
        byte plain[] = null;

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        if (interopProvider == null) {
            /* no interop provider available, skip */
            return;
        }

        Cipher ciphA = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        Cipher ciphB = Cipher.getInstance("AES/GCM/NoPadding", interopProvider);

        for (int i = 0; i < aesGcmVectors.length; i++) {

            /* skip AES-128 vector if not compiled in native library */
            if ((i == 0) && (!FeatureDetect.Aes128Enabled())) {
                continue;
            }

            /* skip AES-192 vector if not compiled in native library, or if
             * using wolfCrypt FIPS since it only supports 12-byte IVs */
            if ((i == 1) && (!FeatureDetect.Aes192Enabled() || Fips.enabled)) {
                continue;
            }

            /* skip AES-256 vector if not compiled in native library */
            if ((i == 2) && (!FeatureDetect.Aes256Enabled())) {
                continue;
            }

            byte[] vOut = aesGcmVectors[i].getOutput();
            byte[] vIn  = aesGcmVectors[i].getInput();
            byte[] vKey = aesGcmVectors[i].getKey();
            byte[] vIV  = aesGcmVectors[i].getIV();
            byte[] vTag = aesGcmVectors[i].getTag();
            byte[] vAAD = aesGcmVectors[i].getAAD();

            /* Concatenate tag to ciphertext, JCE Cipher does this internally */
            byte[] tmpOut = new byte[vOut.length + vTag.length];
            System.arraycopy(vOut, 0, tmpOut, 0, vOut.length);
            System.arraycopy(vTag, 0, tmpOut, vOut.length, vTag.length);

            SecretKeySpec key = new SecretKeySpec(vKey, "AES");
            GCMParameterSpec spec = new GCMParameterSpec(
                (vTag.length * 8), vIV);

            /* Encrypt with wolfJCE */
            ciphA.init(Cipher.ENCRYPT_MODE, key, spec);
            ciphA.updateAAD(vAAD);
            cipher = ciphA.doFinal(vIn);
            assertArrayEquals(tmpOut, cipher);

            /* Decrypt with INTEROP provider */
            ciphB.init(Cipher.DECRYPT_MODE, key, spec);
            ciphB.updateAAD(vAAD);
            plain = ciphB.doFinal(cipher);
            assertArrayEquals(vIn, plain);

            /* Reset Cipher (same IV can't be used twice) */
            ciphA = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
            ciphB = Cipher.getInstance("AES/GCM/NoPadding", interopProvider);

            /* Encrypt with INTEROP provider */
            ciphB.init(Cipher.ENCRYPT_MODE, key, spec);
            ciphB.updateAAD(vAAD);
            cipher = ciphB.doFinal(vIn);
            assertArrayEquals(tmpOut, cipher);

            /* Decrypt with wolfJCE */
            ciphA.init(Cipher.DECRYPT_MODE, key, spec);
            ciphA.updateAAD(vAAD);
            plain = ciphA.doFinal(cipher);
            assertArrayEquals(vIn, plain);
        }
    }

    /**
     * Test Cipher("AES/GCM/NoPadding") getOutputSize() method for various
     * use cases.
     */
    @Test
    public void testAesGcmGetOutputSize() throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        final int TAG_LENGTH_BYTES = 16;  /* Default tag length */
        final int KEY_LENGTH_BYTES = 16;  /* 128-bit AES key */
        final int IV_LENGTH_BYTES  = 12;

        /* Fill key and IV with non-zero values */
        byte[] keyBytes = new byte[KEY_LENGTH_BYTES];
        java.util.Arrays.fill(keyBytes, (byte) 0x01);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[IV_LENGTH_BYTES];
        java.util.Arrays.fill(iv, (byte) 0x02);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BYTES * 8, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);

        /* Test ENCRYPT with zero-length input */
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        assertEquals("Output size for zero-length input should be tag length",
            TAG_LENGTH_BYTES, cipher.getOutputSize(0));

        /* Test ENCRYPT with small input, re-init to reset state */
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        assertEquals("Output size should be input length plus tag length",
            10 + TAG_LENGTH_BYTES, cipher.getOutputSize(10));

        /* Test ENCRYPT with block boundary input */
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        assertEquals("Output size should be input length plus tag length " +
            "at block boundary", 16 + TAG_LENGTH_BYTES,
            cipher.getOutputSize(16));

        /* Test DECRYPT with tag included */
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        assertEquals("Output size for decryption should be input length " +
            "minus tag length", 10,
            cipher.getOutputSize(10 + TAG_LENGTH_BYTES));

        /* Test ENCRYPT after partial update */
        byte[] partialInput = new byte[5];
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher.update(partialInput); /* Process some data */
        assertEquals("Output size after update should account for remaining " +
            "input plus tag", 16 + TAG_LENGTH_BYTES, cipher.getOutputSize(11));

        /* Test getOutputSize() before initialization, expect exception */
        Cipher uninitializedCipher = Cipher.getInstance("AES/GCM/NoPadding");
        try {
            uninitializedCipher.getOutputSize(10);
            fail("Expected IllegalStateException for uninitialized cipher");
        } catch (IllegalStateException e) {
            /* Expected exception */
        }
    }

    /**
     * Verify that getOutputSize() in DECRYPT mode does not add pad bytes.
     */
    @Test
    public void testAesEcbPkcs5GetOutputSizeRegression() throws Exception {

        if (!enabledJCEAlgos.contains("AES/ECB/PKCS5Padding")) {
            /* skip if AES-ECB-PKCS5 is not enabled */
            return;
        }

        /* 16-byte AES key */
        byte[] key = new byte[] {
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x61, (byte)0x62,
            (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66
        };

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", jceProvider);

        /* Test ENCRYPT mode - should add padding bytes to output size */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* For 16-byte input with PKCS5 padding, output should be 32 bytes
         * (16 bytes input + 16 bytes padding) */
        assertEquals("ENCRYPT mode output size should include padding bytes",
            32, cipher.getOutputSize(16));

        /* For 17-byte input with PKCS5 padding, output should be 32 bytes
         * (17 bytes input + 15 bytes padding) */
        assertEquals("ENCRYPT mode output size should include padding bytes",
            32, cipher.getOutputSize(17));

        /* Test DECRYPT mode - should NOT add padding bytes to output size */
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        /* For 16-byte input in DECRYPT mode, output should be 16 bytes
         * (padding will be stripped off) */
        assertEquals("DECRYPT mode output size shouldn't include padding bytes",
            16, cipher.getOutputSize(16));

        /* For 32-byte input in DECRYPT mode, output should be 32 bytes
         * (padding will be stripped off) */
        assertEquals("DECRYPT mode output size shouldn't include padding bytes",
            32, cipher.getOutputSize(32));
    }

    /**
     * AES-GCM decrypt failure should throw AEADBadTagException instead
     * of generic exception.
     */
    @Test
    public void testAesGcmBadTagExceptionRegression()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        byte[] key = new byte[] {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        byte[] iv = new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
            (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c
        };

        byte[] plaintext = new byte[] {
            (byte)0x48, (byte)0x65, (byte)0x6c, (byte)0x6c,
            (byte)0x6f, (byte)0x20, (byte)0x57, (byte)0x6f,
            (byte)0x72, (byte)0x6c, (byte)0x64, (byte)0x21
        };

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        /* First encrypt to get valid ciphertext */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        /* Corrupt the authentication tag (last 16 bytes) */
        byte[] corruptedCiphertext = ciphertext.clone();
        int tagStart = corruptedCiphertext.length - 16;
        for (int i = tagStart; i < corruptedCiphertext.length; i++) {
            corruptedCiphertext[i] = (byte)0xFF;
        }

        /* Attempt to decrypt with corrupted tag - should throw
         * AEADBadTagException */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        try {
            cipher.doFinal(corruptedCiphertext);
            fail("Expected AEADBadTagException for corrupted GCM tag");
        } catch (AEADBadTagException e) {
            /* Expected */
            assertTrue("Exception message should mention authentication",
                e.getMessage().contains("Authentication check fail"));
        } catch (Exception e) {
            fail("Expected AEADBadTagException but got: " +
                e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    @Test
    public void testAesEcbNoPadding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector vectors[] = new CipherVector[] {
            /* test vectors {key, input, output} - ECB doesn't use IV */
            /* NIST SP 800-38A test vector */
            new CipherVector(
                new byte[] {
                    (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                    (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                    (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
                    (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
                },
                null, /* ECB doesn't use IV */
                new byte[] {
                    (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
                    (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
                    (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
                    (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
                },
                new byte[] {
                    (byte)0x3a, (byte)0xd7, (byte)0x7b, (byte)0xb4,
                    (byte)0x0d, (byte)0x7a, (byte)0x36, (byte)0x60,
                    (byte)0xa8, (byte)0x9e, (byte)0xca, (byte)0xf3,
                    (byte)0x24, (byte)0x66, (byte)0xef, (byte)0x97
                },
                null, null
            )
        };

        byte output[];

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            /* bail out if AES-ECB is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);

        for (int i = 0; i < vectors.length; i++) {

            SecretKeySpec key = new SecretKeySpec(vectors[i].getKey(), "AES");

            /* getOutputSize() before init() should throw exception */
            try {
                cipher.getOutputSize(vectors[i].getInput().length);
                fail("getOutputSize() before init() should fail");
            } catch (IllegalStateException e) {
                /* expected, continue */
            }

            cipher.init(Cipher.ENCRYPT_MODE, key);
            output = cipher.doFinal(vectors[i].getInput());

            assertArrayEquals(output, vectors[i].getOutput());

            /* now decrypt */
            cipher.init(Cipher.DECRYPT_MODE, key);
            output = cipher.doFinal(vectors[i].getOutput());

            assertArrayEquals(output, vectors[i].getInput());
        }
    }

    @Test
    public void testAesEcbNoPaddingWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            /* bail out if AES-ECB is not enabled */
            return;
        }

        byte key[] = new byte[] {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        /* Multi-block test data (32 bytes = 2 AES blocks) */
        byte input[] = new byte[] {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a,
            (byte)0xae, (byte)0x2d, (byte)0x8a, (byte)0x57,
            (byte)0x1e, (byte)0x03, (byte)0xac, (byte)0x9c,
            (byte)0x9e, (byte)0xb7, (byte)0x6f, (byte)0xac,
            (byte)0x45, (byte)0xaf, (byte)0x8e, (byte)0x51
        };

        byte expected[] = new byte[] {
            (byte)0x3a, (byte)0xd7, (byte)0x7b, (byte)0xb4,
            (byte)0x0d, (byte)0x7a, (byte)0x36, (byte)0x60,
            (byte)0xa8, (byte)0x9e, (byte)0xca, (byte)0xf3,
            (byte)0x24, (byte)0x66, (byte)0xef, (byte)0x97,
            (byte)0xf5, (byte)0xd3, (byte)0xd5, (byte)0x85,
            (byte)0x03, (byte)0xb9, (byte)0x69, (byte)0x9d,
            (byte)0xe7, (byte)0x85, (byte)0x89, (byte)0x5a,
            (byte)0x96, (byte)0xfd, (byte)0xba, (byte)0xaf
        };

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        /* Test with update() calls */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] output1 = cipher.update(input, 0, 16); /* First block */
        byte[] output2 = cipher.doFinal(input, 16, 16); /* Second block */

        /* Combine outputs */
        byte[] fullOutput = new byte[output1.length + output2.length];
        System.arraycopy(output1, 0, fullOutput, 0, output1.length);
        System.arraycopy(output2, 0, fullOutput, output1.length,
            output2.length);

        assertArrayEquals(expected, fullOutput);

        /* Test decryption with update() */
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted1 = cipher.update(fullOutput, 0, 16);
        byte[] decrypted2 = cipher.doFinal(fullOutput, 16, 16);

        byte[] fullDecrypted = new byte[decrypted1.length + decrypted2.length];
        System.arraycopy(decrypted1, 0, fullDecrypted, 0, decrypted1.length);
        System.arraycopy(decrypted2, 0, fullDecrypted, decrypted1.length,
                         decrypted2.length);

        assertArrayEquals(input, fullDecrypted);
    }

    @Test
    public void testAesEcbPKCS5Padding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/ECB/PKCS5Padding")) {
            /* bail out if AES-ECB with padding is not enabled */
            return;
        }

        byte key[] = new byte[] {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        /* Test with data that needs padding.
         * 12 bytes, needs 4 bytes padding */
        byte input[] = "Hello World!".getBytes();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        /* Test encryption */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ciphertext = cipher.doFinal(input);

        /* Ciphertext should be block-aligned (16 bytes) */
        assertEquals(16, ciphertext.length);

        /* Test decryption */
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals(input, decrypted);

        /* Test with exact block size data */
        byte blockSizeInput[] = new byte[16];
        Arrays.fill(blockSizeInput, (byte)0x41); /* Fill with 'A' */

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] blockCiphertext = cipher.doFinal(blockSizeInput);

        /* Should be 32 bytes (original 16 + 16 bytes padding) */
        assertEquals(32, blockCiphertext.length);

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] blockDecrypted = cipher.doFinal(blockCiphertext);

        assertArrayEquals(blockSizeInput, blockDecrypted);
    }

    @Test
    public void testAesEcbThreaded() throws InterruptedException {
        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            /* AES-ECB not compiled in */
            return;
        }

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    int ret = 0;

                    try {
                        /* NIST test vector */
                        byte key[] = new byte[] {
                            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
                            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
                        };

                        byte input[] = new byte[] {
                            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
                            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
                            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
                            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
                        };

                        byte expected[] = new byte[] {
                            (byte)0x3a, (byte)0xd7, (byte)0x7b, (byte)0xb4,
                            (byte)0x0d, (byte)0x7a, (byte)0x36, (byte)0x60,
                            (byte)0xa8, (byte)0x9e, (byte)0xca, (byte)0xf3,
                            (byte)0x24, (byte)0x66, (byte)0xef, (byte)0x97
                        };

                        Cipher cipher = Cipher.getInstance(
                            "AES/ECB/NoPadding", jceProvider);
                        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

                        /* Test encrypt */
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                        byte[] ciphertext = cipher.doFinal(input);

                        if (!Arrays.equals(expected, ciphertext)) {
                            ret = 1;
                        }

                        /* Test decrypt */
                        cipher.init(Cipher.DECRYPT_MODE, keySpec);
                        byte[] decrypted = cipher.doFinal(ciphertext);

                        if (!Arrays.equals(input, decrypted)) {
                            ret = 1;
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        ret = 1;
                    }

                    results.add(ret);
                    latch.countDown();
                }
            });
        }

        latch.await();

        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in AES-ECB Cipher thread test");
            }
        }
    }

    @Test
    public void testAesCtrNoPadding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CTR/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* NIST SP 800-38A test vector for AES-128-CTR */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        byte[] iv = {
            (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3,
            (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
            (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb,
            (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
        };

        byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        byte[] expected = {
            (byte)0x87, (byte)0x4d, (byte)0x61, (byte)0x91,
            (byte)0xb6, (byte)0x20, (byte)0xe3, (byte)0x26,
            (byte)0x1b, (byte)0xef, (byte)0x68, (byte)0x64,
            (byte)0x99, (byte)0x0d, (byte)0xb6, (byte)0xce
        };

        /* Test encrypt */
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        assertArrayEquals(expected, ciphertext);

        /* Test decrypt */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testAesCtrNoPaddingWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CTR/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* NIST SP 800-38A test vector for AES-128-CTR */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        byte[] iv = {
            (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3,
            (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
            (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb,
            (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
        };

        byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        byte[] expected = {
            (byte)0x87, (byte)0x4d, (byte)0x61, (byte)0x91,
            (byte)0xb6, (byte)0x20, (byte)0xe3, (byte)0x26,
            (byte)0x1b, (byte)0xef, (byte)0x68, (byte)0x64,
            (byte)0x99, (byte)0x0d, (byte)0xb6, (byte)0xce
        };

        /* Test encrypt with update() calls */
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        /* Process plaintext in chunks */
        byte[] part1 = cipher.update(plaintext, 0, 8);
        byte[] part2 = cipher.doFinal(plaintext, 8, 8);

        /* Combine parts */
        byte[] ciphertext = new byte[part1.length + part2.length];
        System.arraycopy(part1, 0, ciphertext, 0, part1.length);
        System.arraycopy(part2, 0, ciphertext, part1.length, part2.length);

        assertArrayEquals(expected, ciphertext);

        /* Test decrypt with update() calls */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decPart1 = cipher.update(ciphertext, 0, 8);
        byte[] decPart2 = cipher.doFinal(ciphertext, 8, 8);

        /* Combine parts */
        byte[] decrypted = new byte[decPart1.length + decPart2.length];
        System.arraycopy(decPart1, 0, decrypted, 0, decPart1.length);
        System.arraycopy(decPart2, 0, decrypted, decPart1.length,
            decPart2.length);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testAesCtrStreaming()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CTR/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* Test CTR streaming with arbitrary data sizes */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        byte[] iv = {
            (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3,
            (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
            (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb,
            (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
        };

        /* Test with various data sizes (not block aligned) */
        int[] dataSizes = {1, 7, 15, 17, 31, 33, 63, 65};

        for (int size : dataSizes) {
            byte[] plaintext = new byte[size];
            secureRandom.nextBytes(plaintext);

            Cipher cipher =
                Cipher.getInstance("AES/CTR/NoPadding", jceProvider);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            /* Encrypt */
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            /* Decrypt */
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);

            assertArrayEquals("Failed for size " + size, plaintext, decrypted);
        }
    }

    @Test
    public void testAesCtrThreaded() throws InterruptedException {
        if (!enabledJCEAlgos.contains("AES/CTR/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        /* NIST SP 800-38A test vector for AES-128-CTR */
        final byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        final byte[] iv = {
            (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3,
            (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
            (byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb,
            (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
        };

        final byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        final byte[] expected = {
            (byte)0x87, (byte)0x4d, (byte)0x61, (byte)0x91,
            (byte)0xb6, (byte)0x20, (byte)0xe3, (byte)0x26,
            (byte)0x1b, (byte)0xef, (byte)0x68, (byte)0x64,
            (byte)0x99, (byte)0x0d, (byte)0xb6, (byte)0xce
        };

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    int ret = 0;

                    try {
                        Cipher cipher = Cipher.getInstance(
                            "AES/CTR/NoPadding", jceProvider);
                        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                        IvParameterSpec ivSpec = new IvParameterSpec(iv);

                        /* Test encrypt */
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                        byte[] ciphertext = cipher.doFinal(plaintext);

                        if (!Arrays.equals(expected, ciphertext)) {
                            ret = 1;
                        }

                        /* Test decrypt */
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                        byte[] decrypted = cipher.doFinal(ciphertext);

                        if (!Arrays.equals(plaintext, decrypted)) {
                            ret = 1;
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        ret = 1;
                    }

                    results.add(ret);
                    latch.countDown();
                }
            });
        }

        latch.await();

        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in AES-CTR Cipher thread test");
            }
        }
    }

    @Test
    public void testAesOfbNoPadding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/OFB/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* NIST SP 800-38A test vector for AES-128-OFB */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        byte[] iv = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
        };

        byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        byte[] expected = {
            (byte)0x3b, (byte)0x3f, (byte)0xd9, (byte)0x2e,
            (byte)0xb7, (byte)0x2d, (byte)0xad, (byte)0x20,
            (byte)0x33, (byte)0x34, (byte)0x49, (byte)0xf8,
            (byte)0xe8, (byte)0x3c, (byte)0xfb, (byte)0x4a
        };

        /* Test encrypt */
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        assertArrayEquals(expected, ciphertext);

        /* Test decrypt */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testAesOfbNoPaddingWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/OFB/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* NIST SP 800-38A test vector for AES-128-OFB */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        byte[] iv = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
        };

        byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        byte[] expected = {
            (byte)0x3b, (byte)0x3f, (byte)0xd9, (byte)0x2e,
            (byte)0xb7, (byte)0x2d, (byte)0xad, (byte)0x20,
            (byte)0x33, (byte)0x34, (byte)0x49, (byte)0xf8,
            (byte)0xe8, (byte)0x3c, (byte)0xfb, (byte)0x4a
        };

        /* Test encrypt with update() calls */
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        /* Process plaintext in chunks */
        byte[] part1 = cipher.update(plaintext, 0, 8);
        byte[] part2 = cipher.doFinal(plaintext, 8, 8);

        /* Combine parts */
        byte[] ciphertext = new byte[part1.length + part2.length];
        System.arraycopy(part1, 0, ciphertext, 0, part1.length);
        System.arraycopy(part2, 0, ciphertext, part1.length, part2.length);

        assertArrayEquals(expected, ciphertext);

        /* Test decrypt with update() calls */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decPart1 = cipher.update(ciphertext, 0, 8);
        byte[] decPart2 = cipher.doFinal(ciphertext, 8, 8);

        /* Combine parts */
        byte[] decrypted = new byte[decPart1.length + decPart2.length];
        System.arraycopy(decPart1, 0, decrypted, 0, decPart1.length);
        System.arraycopy(decPart2, 0, decrypted, decPart1.length,
            decPart2.length);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testAesOfbStreaming()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/OFB/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* Test OFB streaming with arbitrary data sizes */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        byte[] iv = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
        };

        /* Test with various data sizes (not block aligned) */
        int[] dataSizes = {1, 7, 15, 17, 31, 33, 63, 65};

        for (int size : dataSizes) {
            byte[] plaintext = new byte[size];
            secureRandom.nextBytes(plaintext);

            Cipher cipher = Cipher.getInstance(
                "AES/OFB/NoPadding", jceProvider);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            /* Encrypt */
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            /* Decrypt */
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);

            assertArrayEquals("Failed for size " + size, plaintext, decrypted);
        }
    }

    @Test
    public void testAesOfbThreaded() throws InterruptedException {
        if (!enabledJCEAlgos.contains("AES/OFB/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        /* NIST SP 800-38A test vector for AES-128-OFB */
        final byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        final byte[] iv = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
        };

        final byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        final byte[] expected = {
            (byte)0x3b, (byte)0x3f, (byte)0xd9, (byte)0x2e,
            (byte)0xb7, (byte)0x2d, (byte)0xad, (byte)0x20,
            (byte)0x33, (byte)0x34, (byte)0x49, (byte)0xf8,
            (byte)0xe8, (byte)0x3c, (byte)0xfb, (byte)0x4a
        };

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    int ret = 0;

                    try {
                        Cipher cipher = Cipher.getInstance(
                            "AES/OFB/NoPadding", jceProvider);
                        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                        IvParameterSpec ivSpec = new IvParameterSpec(iv);

                        /* Test encrypt */
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                        byte[] ciphertext = cipher.doFinal(plaintext);

                        if (!Arrays.equals(expected, ciphertext)) {
                            ret = 1;
                        }

                        /* Test decrypt */
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                        byte[] decrypted = cipher.doFinal(ciphertext);

                        if (!Arrays.equals(plaintext, decrypted)) {
                            ret = 1;
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        ret = 1;
                    }

                    results.add(ret);
                    latch.countDown();
                }
            });
        }

        latch.await();

        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in AES-OFB Cipher thread test");
            }
        }
    }

    @Test
    public void testDESedeCbcNoPadding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector vectors[] = new CipherVector[] {
            /* test vectors {key, iv, input, output } */
            new CipherVector(
                new byte[] {
                    (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
                    (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
                    (byte)0xfe, (byte)0xde, (byte)0xba, (byte)0x98,
                    (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                    (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
                    (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67
                },
                new byte[] {
                    (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
                    (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef,
                },
                new byte[] {
                    (byte)0x4e, (byte)0x6f, (byte)0x77, (byte)0x20,
                    (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
                    (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
                    (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20,
                    (byte)0x66, (byte)0x6f, (byte)0x72, (byte)0x20,
                    (byte)0x61, (byte)0x6c, (byte)0x6c, (byte)0x20
                },
                new byte[] {
                    (byte)0x43, (byte)0xa0, (byte)0x29, (byte)0x7e,
                    (byte)0xd1, (byte)0x84, (byte)0xf8, (byte)0x0e,
                    (byte)0x89, (byte)0x64, (byte)0x84, (byte)0x32,
                    (byte)0x12, (byte)0xd5, (byte)0x08, (byte)0x98,
                    (byte)0x18, (byte)0x94, (byte)0x15, (byte)0x74,
                    (byte)0x87, (byte)0x12, (byte)0x7d, (byte)0xb0
                },
                null, null
            )
        };

        byte output[];

        if (!enabledJCEAlgos.contains("DESede/CBC/NoPadding") ||
            !FeatureDetect.Des3Enabled()) {
            /* bail out if 3DES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", jceProvider);

        for (int i = 0; i < vectors.length; i++) {

            SecretKeySpec key =
                new SecretKeySpec(vectors[i].getKey(), "DESede");
            IvParameterSpec spec =
                new IvParameterSpec(vectors[i].getIV());

            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            output = cipher.doFinal(vectors[i].input);

            assertArrayEquals(output, vectors[i].output);
        }
    }

    @Test
    public void testDESedeCbcNoPaddingWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte key[] = new byte[] {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xde, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67
        };

        byte iv[] = new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef,
        };

        byte input[] = new byte[] {
            (byte)0x4e, (byte)0x6f, (byte)0x77, (byte)0x20,
            (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74,
            (byte)0x68, (byte)0x65, (byte)0x20, (byte)0x74,
            (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x20,
            (byte)0x66, (byte)0x6f, (byte)0x72, (byte)0x20,
            (byte)0x61, (byte)0x6c, (byte)0x6c, (byte)0x20
        };

        byte output[] = new byte[] {
            (byte)0x43, (byte)0xa0, (byte)0x29, (byte)0x7e,
            (byte)0xd1, (byte)0x84, (byte)0xf8, (byte)0x0e,
            (byte)0x89, (byte)0x64, (byte)0x84, (byte)0x32,
            (byte)0x12, (byte)0xd5, (byte)0x08, (byte)0x98,
            (byte)0x18, (byte)0x94, (byte)0x15, (byte)0x74,
            (byte)0x87, (byte)0x12, (byte)0x7d, (byte)0xb0
        };

        byte tmp[];

        if (!enabledJCEAlgos.contains("DESede/CBC/NoPadding") ||
            !FeatureDetect.Des3Enabled()) {
            /* bail out if 3DES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", jceProvider);

        SecretKeySpec keyspec = new SecretKeySpec(key, "DESede");
        IvParameterSpec spec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keyspec, spec);

        tmp = cipher.update(Arrays.copyOfRange(input, 0, 4));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        tmp = cipher.update(Arrays.copyOfRange(input, 4, 8));
        assertArrayEquals(tmp, Arrays.copyOfRange(output, 0, 8));

        tmp = cipher.update(Arrays.copyOfRange(input, 8, 16));
        assertArrayEquals(tmp, Arrays.copyOfRange(output, 8, 16));

        tmp = cipher.doFinal(Arrays.copyOfRange(input, 16, 24));
        assertArrayEquals(tmp, Arrays.copyOfRange(output, 16, 24));

        try {
            tmp = cipher.doFinal(Arrays.copyOfRange(input, 0, 2));
            fail("cipher.doFinal on odd size block cipher input should " +
                 "throw exception");
        } catch (IllegalBlockSizeException e) {
            assertTrue(e.getMessage().contains("not multiple of 8 bytes"));
        }
    }

    @Test
    public void testDESedeCbcNoPaddingThreaded() throws InterruptedException {

        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();
        final byte[] rand2kBuf = new byte[2048];

        final byte key[] = new byte[] {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xde, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67
        };

        final byte iv[] = new byte[] {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
            (byte)0x90, (byte)0xab, (byte)0xcd, (byte)0xef,
        };

        if (!enabledJCEAlgos.contains("DESede/CBC/NoPadding") ||
            !FeatureDetect.Des3Enabled()) {
            /* skip if DESede/CBC/NoPadding is not enabled */
            return;
        }

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand2kBuf);

        /* encrypt / decrypt input data, make sure decrypted matches original */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int ret = 0;

                    try {
                        Cipher enc = Cipher.getInstance(
                            "DESede/CBC/NoPadding", jceProvider);
                        enc.init(Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(key, "DESede"),
                            new IvParameterSpec(iv));

                        Cipher dec = Cipher.getInstance(
                            "DESede/CBC/NoPadding", jceProvider);
                        dec.init(Cipher.DECRYPT_MODE,
                            new SecretKeySpec(key, "DESede"),
                            new IvParameterSpec(iv));

                        byte[] encrypted = new byte[2048];
                        byte[] plaintext = new byte[2048];

                        /* encrypt in 128-byte chunks */
                        Arrays.fill(encrypted, (byte)0);
                        for (int j = 0; j < rand2kBuf.length; j+= 128) {
                            ret = enc.update(rand2kBuf, j, 128, encrypted, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Cipher.update(DES,ENCRYPT_MODE) returned "
                                    + ret);
                            }
                        }

                        /* decrypt in 128-byte chunks */
                        Arrays.fill(plaintext, (byte)0);
                        for (int j = 0; j < encrypted.length; j+= 128) {
                            ret = dec.update(encrypted, j, 128, plaintext, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Cipher.update(DES,DECRYPT_MODE) returned "
                                    + ret);
                            }
                        }

                        /* make sure decrypted is same as input */
                        if (Arrays.equals(rand2kBuf, plaintext)) {
                            results.add(0);
                        }
                        else {
                            /* not equal, error case */
                            results.add(1);
                        }

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
                fail("Threading error in DESede Cipher thread test");
            }
        }
    }

    private void testRSAPublicPrivateEncryptDecrypt(String algo)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector[] vectors = new CipherVector[] {
            /* test vectors {key, iv, input, output } */
            new CipherVector(
                null,
                null,
                new byte[] {
                    (byte)0x45, (byte)0x76, (byte)0x65, (byte)0x72,
                    (byte)0x79, (byte)0x6f, (byte)0x6e, (byte)0x65,
                    (byte)0x20, (byte)0x67, (byte)0x65, (byte)0x74,
                    (byte)0x73, (byte)0x20, (byte)0x46, (byte)0x72,
                    (byte)0x69, (byte)0x64, (byte)0x61, (byte)0x79,
                    (byte)0x20, (byte)0x6f, (byte)0x66, (byte)0x66,
                    (byte)0x2e
                },
                null, null, null
            )
        };

        byte[] ciphertext = null;
        byte[] plaintext = null;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        if (!enabledJCEAlgos.contains(algo)) {
            /* mode not supported, return without testing */
            return;
        }

        Cipher ciph = Cipher.getInstance(algo, jceProvider);

        for (int i = 0; i < vectors.length; i++) {

            /* PRIVATE ENCRYPT */
            ciph.init(Cipher.ENCRYPT_MODE, priv);
            ciphertext = ciph.doFinal(vectors[i].input);

            /* PUBLIC DECRYPT */
            ciph.init(Cipher.DECRYPT_MODE, pub);
            plaintext = ciph.doFinal(ciphertext);

            assertArrayEquals(plaintext, vectors[i].input);

            /* PUBLIC ENCRYPT */
            ciph.init(Cipher.ENCRYPT_MODE, pub);
            ciphertext = ciph.doFinal(vectors[i].input);

            /* PRIVATE DECRYPT */
            ciph.init(Cipher.DECRYPT_MODE, priv);
            plaintext = ciph.doFinal(ciphertext);

            assertArrayEquals(plaintext, vectors[i].input);
        }
    }

    private void testRSAWithUpdateSizes(String algo)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte[] input = new byte[] {
            (byte)0x45, (byte)0x76, (byte)0x65, (byte)0x72,
            (byte)0x79, (byte)0x6f, (byte)0x6e, (byte)0x65,
            (byte)0x20, (byte)0x67, (byte)0x65, (byte)0x74,
            (byte)0x73, (byte)0x20, (byte)0x46, (byte)0x72,
            (byte)0x69, (byte)0x64, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6f, (byte)0x66, (byte)0x66,
            (byte)0x2e
        };

        byte[] tmp = null;
        byte[] ciphertext = null;
        byte[] plaintext = null;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        if (!enabledJCEAlgos.contains(algo)) {
            /* mode not supported, return without testing */
            return;
        }

        Cipher ciph = Cipher.getInstance(algo, jceProvider);

        /* PRIVATE ENCRYPT, 4 byte chunks + 1 remaining for final */
        ciph.init(Cipher.ENCRYPT_MODE, priv);
        tmp = ciph.update(Arrays.copyOfRange(input, 0, 4));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(input, 4, 8));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(input, 8, 16));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(input, 16, 24));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        ciphertext = ciph.doFinal(Arrays.copyOfRange(input, 24, 25));

        /* PUBLIC DECRYPT, 50-byte chunks + 56 remaining for final */
        ciph.init(Cipher.DECRYPT_MODE, pub);
        tmp = ciph.update(Arrays.copyOfRange(ciphertext, 0, 50));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertext, 50, 100));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertext, 100, 150));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertext, 150, 200));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        plaintext = ciph.doFinal(Arrays.copyOfRange(ciphertext, 200, 256));

        assertArrayEquals(plaintext, input);

        /* PUBLIC ENCRYPT, 1 byte chunks, none remaining for final */
        ciph.init(Cipher.ENCRYPT_MODE, pub);
        for (int i = 1; i < input.length + 1; i++) {
            tmp = ciph.update(Arrays.copyOfRange(input, i-1, i));
            assertNotNull(tmp);
            assertEquals(tmp.length, 0);
        }
        ciphertext = ciph.doFinal();

        /* PRIVATE DECRYPT, 100-byte chunks + 56 remaining for final */
        ciph.init(Cipher.DECRYPT_MODE, priv);
        tmp = ciph.update(Arrays.copyOfRange(ciphertext, 0, 100));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertext, 100, 200));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        plaintext = ciph.doFinal(Arrays.copyOfRange(ciphertext, 200, 256));
        assertArrayEquals(plaintext, input);
    }

    private void testRSAWithUpdateVerifyFinalResetsState(String algo)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte[] input = new byte[] {
            (byte)0x45, (byte)0x76, (byte)0x65, (byte)0x72,
            (byte)0x79, (byte)0x6f, (byte)0x6e, (byte)0x65,
            (byte)0x20, (byte)0x67, (byte)0x65, (byte)0x74,
            (byte)0x73, (byte)0x20, (byte)0x46, (byte)0x72,
            (byte)0x69, (byte)0x64, (byte)0x61, (byte)0x79,
            (byte)0x20, (byte)0x6f, (byte)0x66, (byte)0x66,
            (byte)0x2e
        };

        byte[] tmp = null;
        byte[] ciphertextA = null;
        byte[] ciphertextB = null;
        byte[] plaintextA  = null;
        byte[] plaintextB  = null;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        if (!enabledJCEAlgos.contains(algo)) {
            /* mode not supported, return without testing */
            return;
        }

        Cipher ciph = Cipher.getInstance(algo, jceProvider);

        /* PRIVATE ENCRYPT */
        /* storing to ciphertextA */
        ciph.init(Cipher.ENCRYPT_MODE, priv);
        tmp = ciph.update(Arrays.copyOfRange(input, 0, 16));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(input, 16, 24));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        ciphertextA = ciph.doFinal(Arrays.copyOfRange(input, 24, 25));

        /* PRIVATE ENCRYPT */
        /* doFinal should reset state, encrypt again without init */
        tmp = ciph.update(Arrays.copyOfRange(input, 0, 16));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(input, 16, 24));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        ciphertextB = ciph.doFinal(Arrays.copyOfRange(input, 24, 25));

        /* PUBLIC DECRYPT */
        /* public decrypt, verifying ciphertextA */
        ciph.init(Cipher.DECRYPT_MODE, pub);
        tmp = ciph.update(Arrays.copyOfRange(ciphertextA, 0, 150));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertextA, 150, 200));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        plaintextA = ciph.doFinal(Arrays.copyOfRange(ciphertextA, 200, 256));
        assertArrayEquals(plaintextA, input);

        /* PUBLIC DECRYPT */
        /* doFinal should reset state, decrypt ciphertext B without init */
        tmp = ciph.update(Arrays.copyOfRange(ciphertextB, 0, 150));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertextB, 150, 200));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        plaintextB = ciph.doFinal(Arrays.copyOfRange(ciphertextB, 200, 256));
        assertArrayEquals(plaintextB, input);

        /* PUBLIC ENCRYPT */
        /* storing to ciphertextA */
        ciph.init(Cipher.ENCRYPT_MODE, pub);
        tmp = ciph.update(Arrays.copyOfRange(input, 0, 16));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(input, 16, 24));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        ciphertextA = ciph.doFinal(Arrays.copyOfRange(input, 24, 25));

        /* PUBLIC ENCRYPT */
        /* doFinal should reset state, encrypt again without init */
        tmp = ciph.update(Arrays.copyOfRange(input, 0, 16));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(input, 16, 24));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        ciphertextB = ciph.doFinal(Arrays.copyOfRange(input, 24, 25));

        /* PRIVATE DECRYPT */
        /* public decrypt, verifying ciphertextA */
        ciph.init(Cipher.DECRYPT_MODE, priv);
        tmp = ciph.update(Arrays.copyOfRange(ciphertextA, 0, 150));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertextA, 150, 200));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        plaintextA = ciph.doFinal(Arrays.copyOfRange(ciphertextA, 200, 256));
        assertArrayEquals(plaintextA, input);

        /* PRIVATE DECRYPT */
        /* doFinal should reset state, decrypt ciphertext B without init */
        tmp = ciph.update(Arrays.copyOfRange(ciphertextB, 0, 150));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        tmp = ciph.update(Arrays.copyOfRange(ciphertextB, 150, 200));
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);
        plaintextB = ciph.doFinal(Arrays.copyOfRange(ciphertextB, 200, 256));
        assertArrayEquals(plaintextB, input);
    }

    private void testRSAWithTooBigData(String algo)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        byte[] tmp = null;

        byte[] inputA = new byte[2048];
        byte[] inputB = new byte[100];

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        if (!enabledJCEAlgos.contains(algo)) {
            /* mode not supported, return without testing */
            return;
        }

        Cipher ciph = Cipher.getInstance(algo, jceProvider);

        /* PRIVATE ENCRYPT */
        ciph.init(Cipher.ENCRYPT_MODE, priv);

        tmp = ciph.update(inputA);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        tmp = ciph.update(inputB);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        try {
            ciph.doFinal();
            fail("Cipher.doFinal should throw exception when data " +
                 "is larger than RSA key size");
        } catch (WolfCryptException | IllegalBlockSizeException e) {
            /* expected */
        }

        /* PUBLIC DECRYPT */
        ciph.init(Cipher.DECRYPT_MODE, pub);

        tmp = ciph.update(inputA);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        tmp = ciph.update(inputB);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        try {
            ciph.doFinal();
            fail("Cipher.doFinal should throw exception when data " +
                 "is larger than RSA key size");
        } catch (WolfCryptException | IllegalBlockSizeException e) {
            /* expected */
        }

        /* PUBLIC ENCRYPT */
        ciph.init(Cipher.ENCRYPT_MODE, pub);

        tmp = ciph.update(inputA);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        tmp = ciph.update(inputB);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        try {
            ciph.doFinal();
            fail("Cipher.doFinal should throw exception when data " +
                 "is larger than RSA key size");
        } catch (WolfCryptException | IllegalBlockSizeException e) {
            /* expected */
        }

        /* PRIVATE DECRYPT */
        ciph.init(Cipher.DECRYPT_MODE, priv);

        tmp = ciph.update(inputA);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        tmp = ciph.update(inputB);
        assertNotNull(tmp);
        assertEquals(tmp.length, 0);

        try {
            ciph.doFinal();
            fail("Cipher.doFinal should throw exception when data " +
                 "is larger than RSA key size");
        } catch (WolfCryptException | IllegalBlockSizeException e) {
            /* expected */
        }
    }

    private void testRSAInterop(String algo)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector[] vectors = new CipherVector[] {
            /* test vectors {key, iv, input, output } */
            new CipherVector(
                null,
                null,
                new byte[] {
                    (byte)0x45, (byte)0x76, (byte)0x65, (byte)0x72,
                    (byte)0x79, (byte)0x6f, (byte)0x6e, (byte)0x65,
                    (byte)0x20, (byte)0x67, (byte)0x65, (byte)0x74,
                    (byte)0x73, (byte)0x20, (byte)0x46, (byte)0x72,
                    (byte)0x69, (byte)0x64, (byte)0x61, (byte)0x79,
                    (byte)0x20, (byte)0x6f, (byte)0x66, (byte)0x66,
                    (byte)0x2e
                },
                null, null, null
            )
        };

        byte[] ciphertext = null;
        byte[] plaintext = null;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        if (!enabledJCEAlgos.contains(algo)) {
            /* mode not supported, return without testing */
            return;
        }

        Cipher ciphA = Cipher.getInstance(algo, jceProvider);
        Cipher ciphB = Cipher.getInstance(algo, interopProvider);

        Provider prov = ciphB.getProvider();
        if (prov.equals("wolfJCE")) {
            /* return, no other provider installed to interop against */
            return;
        }

        for (int i = 0; i < vectors.length; i++) {

            {
                /* wolfJCE PRIVATE ENCRYPT */
                ciphA.init(Cipher.ENCRYPT_MODE, priv);
                ciphertext = ciphA.doFinal(vectors[i].input);

                /* Interop PUBLIC DECRYPT */
                ciphB.init(Cipher.DECRYPT_MODE, pub);
                plaintext = ciphB.doFinal(ciphertext);

                assertArrayEquals(plaintext, vectors[i].input);
            }

            {
                /* Interop PRIVATE ENCRYPT */
                ciphB.init(Cipher.ENCRYPT_MODE, priv);
                ciphertext = ciphB.doFinal(vectors[i].input);

                /* wolfJCE PUBLIC DECRYPT */
                ciphA.init(Cipher.DECRYPT_MODE, pub);
                plaintext = ciphA.doFinal(ciphertext);

                assertArrayEquals(plaintext, vectors[i].input);
            }

            {
                /* wolfJCE PUBLIC ENCRYPT */
                ciphA.init(Cipher.ENCRYPT_MODE, pub);
                ciphertext = ciphA.doFinal(vectors[i].input);

                /* Interop PRIVATE DECRYPT */
                ciphB.init(Cipher.DECRYPT_MODE, priv);
                plaintext = ciphB.doFinal(ciphertext);

                assertArrayEquals(plaintext, vectors[i].input);
            }

            {
                /* Interop PUBLIC ENCRYPT */
                ciphB.init(Cipher.ENCRYPT_MODE, pub);
                ciphertext = ciphB.doFinal(vectors[i].input);

                /* wolfJCE PRIVATE DECRYPT */
                ciphA.init(Cipher.DECRYPT_MODE, priv);
                plaintext = ciphA.doFinal(ciphertext);

                assertArrayEquals(plaintext, vectors[i].input);
            }
        }
    }

    @Test
    public void testRSA()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        testRSAPublicPrivateEncryptDecrypt("RSA");
        testRSAPublicPrivateEncryptDecrypt("RSA/ECB/PKCS1Padding");

        /* test RSA encrypt/decrypt using various update/final sizes */
        testRSAWithUpdateSizes("RSA");
        testRSAWithUpdateSizes("RSA/ECB/PKCS1Padding");

        testRSAWithUpdateVerifyFinalResetsState("RSA");
        testRSAWithUpdateVerifyFinalResetsState("RSA/ECB/PKCS1Padding");

        /* test RSA with update, and too large of data */
        testRSAWithTooBigData("RSA");
        testRSAWithTooBigData("RSA/ECB/PKCS1Padding");

        testRSAInterop("RSA");
        testRSAInterop("RSA/ECB/PKCS1Padding");
    }

    @Test
    public void testAesCcmNoPadding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* Simple CCM test vector */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        byte[] nonce = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b
        }; /* 12-byte nonce */
        byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        /* Test encrypt */
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        /* 128-bit tag */
        GCMParameterSpec ccmSpec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        /* Verify ciphertext is longer than plaintext due to auth tag */
        assertTrue("CCM ciphertext should be longer than plaintext",
                   ciphertext.length > plaintext.length);
        assertEquals("CCM ciphertext should include 16-byte auth tag",
                     plaintext.length + 16, ciphertext.length);

        /* Test decrypt */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);

        /* Verify roundtrip */
        assertArrayEquals("CCM decrypt should match original plaintext",
                          plaintext, decrypted);
    }

    @Test
    public void testAesCcmNoPaddingWithAAD()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* CCM test vector with AAD */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        byte[] nonce = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b
        }; /* 12-byte nonce */
        byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96
        };
        byte[] aad = {
            (byte)0xfe, (byte)0xed, (byte)0xfa, (byte)0xce,
            (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef
        };

        /* Test encrypt with AAD */
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec ccmSpec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext);

        /* Test decrypt with AAD */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals("CCM with AAD decrypt should match plaintext",
                          plaintext, decrypted);
    }

    @Test
    public void testAesCcmNoPaddingWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        /* CCM test with multiple update() calls */
        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        byte[] nonce = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b
        };
        byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        /* Test encrypt with update() calls */
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec ccmSpec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);

        /* CCM buffers data until doFinal, so update() should return empty */
        byte[] tmp1 = cipher.update(plaintext, 0, 8);
        byte[] tmp2 = cipher.update(plaintext, 8, 8);
        byte[] ciphertext = cipher.doFinal();

        /* For CCM, update() calls should return empty arrays */
        assertEquals("CCM update() should return empty", 0, tmp1.length);
        assertEquals("CCM update() should return empty", 0, tmp2.length);
        assertTrue("CCM ciphertext should be non-empty", ciphertext.length > 0);

        /* Test decrypt */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals("CCM multi-update decrypt should match plaintext",
                          plaintext, decrypted);
    }

    @Test
    public void testAesCcmStreaming()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        byte[] nonce = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b
        };

        /* Test various data sizes */
        int[] testSizes = {1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65};

        for (int size : testSizes) {
            byte[] plaintext = new byte[size];
            for (int i = 0; i < size; i++) {
                plaintext[i] = (byte)(i & 0xFF);
            }

            Cipher cipher =
                Cipher.getInstance("AES/CCM/NoPadding", jceProvider);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec ccmSpec = new GCMParameterSpec(128, nonce);

            /* Encrypt */
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            /* Decrypt */
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);

            assertArrayEquals("Failed for size " + size, plaintext, decrypted);
        }
    }

    @Test
    public void testAesCcmThreaded() throws InterruptedException {
        if (!enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        int numThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        final byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        final byte[] nonce = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b
        };
        final byte[] plaintext = {
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96
        };

        for (int i = 0; i < numThreads; i++) {
            final int threadNum = i;
            service.submit(new Runnable() {
                @Override
                public void run() {
                    int result = 0;
                    try {
                        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding",
                                                         jceProvider);
                        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                        GCMParameterSpec ccmSpec =
                            new GCMParameterSpec(128, nonce);

                        /* Multiple encrypt/decrypt cycles */
                        for (int j = 0; j < 100; j++) {
                            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
                            byte[] ciphertext = cipher.doFinal(plaintext);

                            cipher.init(Cipher.DECRYPT_MODE, keySpec, ccmSpec);
                            byte[] decrypted = cipher.doFinal(ciphertext);

                            if (!Arrays.equals(plaintext, decrypted)) {
                                result = 1;
                                break;
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        result = 1;
                    }
                    results.add(result);
                    latch.countDown();
                }
            });
        }

        latch.await();
        service.shutdown();

        Integer[] resultsArray = results.toArray(new Integer[results.size()]);
        for (int i = 0; i < resultsArray.length; i++) {
            if (resultsArray[i] != 0) {
                fail("Threading error in AES-CCM Cipher thread test");
            }
        }
    }

    @Test
    public void testAesCcmNonceLengthValidation() {
        if (!enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            /* algorithm not enabled */
            return;
        }

        byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        try {
            Cipher cipher = Cipher.getInstance(
                "AES/CCM/NoPadding", jceProvider);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            /* Test nonce too short (6 bytes) */
            byte[] shortNonce = new byte[6];
            GCMParameterSpec shortSpec = new GCMParameterSpec(128, shortNonce);

            try {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, shortSpec);
                fail("Should reject nonce shorter than 7 bytes");
            } catch (InvalidAlgorithmParameterException e) {
                assertTrue("Error message should mention nonce length",
                           e.getMessage().contains("nonce length"));
            }

            /* Test nonce too long (16 bytes) */
            byte[] longNonce = new byte[16];
            GCMParameterSpec longSpec = new GCMParameterSpec(128, longNonce);

            try {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, longSpec);
                fail("Should reject nonce longer than 15 bytes");
            } catch (InvalidAlgorithmParameterException e) {
                assertTrue("Error message should mention nonce length",
                           e.getMessage().contains("nonce length"));
            }

            /* Test valid nonce lengths (7-15 bytes) */
            for (int len = 7; len <= 15; len++) {
                byte[] validNonce = new byte[len];
                GCMParameterSpec validSpec =
                    new GCMParameterSpec(128, validNonce);

                /* Should not throw exception */
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, validSpec);
            }

        } catch (Exception e) {
            fail("Unexpected exception in nonce length validation: " +
                e.getMessage());
        }
    }

    /**
     * Test IV consistency across encryption/decryption cycles.
     * This test prevents regression of the issue where getIV() would return
     * different values before and after doFinal() operations, which would
     * cause CTR mode (and potentially other modes) to fail when using the
     * standard JCE pattern of retrieving the IV after encryption and using
     * it for decryption initialization.
     */
    @Test
    public void testIVConsistencyAcrossOperations() throws Exception {

        /* Test all enabled cipher modes that use IVs (exclude RSA and ECB) */
        for (String mode : enabledJCEAlgos) {
            /* Skip modes that don't use IVs */
            if (mode.startsWith("RSA") || mode.contains("/ECB/") ||
                mode.equals("AES")) {
                continue;
            }


            /* Skip 3DES if not compiled in */
            if (mode.startsWith("DESede") && !FeatureDetect.Des3Enabled()) {
                continue;
            }

            testIVConsistencyForMode(mode);
        }
    }

    /**
     * Test IV consistency for a specific cipher mode with the pattern:
     * Init with no IV, encrypt data, retrieve IV after encryption,
     * init for decryption with retrieved IV, decrypt and verify data matches,
     * and verify IV remains consistent throughout.
     */
    private void testIVConsistencyForMode(String algorithm) throws Exception {

        byte[] key;
        SecretKeySpec keySpec;
        int[] testSizes = {16, 32, 100, 1601, 1602, 1603};

        /* Generate test key */
        if (algorithm.startsWith("AES")) {
            key = new byte[16]; /* AES-128 */
            keySpec = new SecretKeySpec(key, "AES");
        } else if (algorithm.startsWith("DESede")) {
            key = new byte[24]; /* 3DES */
            keySpec = new SecretKeySpec(key, "DESede");
        } else {
            return; /* Unsupported algorithm */
        }

        secureRandom.nextBytes(key);

        /* Generate test data of various sizes to ensure robustness */
        for (int dataSize : testSizes) {
            testIVConsistencyForModeAndSize(algorithm, keySpec, dataSize);
        }
    }

    /**
     * Test IV consistency for specific algorithm and data size
     */
    private void testIVConsistencyForModeAndSize(String algorithm,
            SecretKeySpec keySpec, int dataSize) throws Exception {

        Cipher cipher;
        byte[] plaintext;
        byte[] ivAfterInit;
        byte[] ciphertext;
        byte[] ivAfterEncryption;
        byte[] ivAfterDecryptInit;
        byte[] recoveredPlaintext;
        byte[] ivAfterDecryption;

        /* Skip sizes that would cause issues with block ciphers */
        if ((algorithm.equals("AES") ||
            ((algorithm.contains("CBC") || algorithm.contains("ECB")) &&
            algorithm.contains("NoPadding"))) && (dataSize % 16 != 0)) {
            return; /* Block size must be multiple of 16 for NoPadding */
        }
        if (algorithm.startsWith("DESede") &&
            algorithm.contains("NoPadding") &&
            (dataSize % 8 != 0)) {
            return; /* 3DES block size must be multiple of 8 for NoPadding */
        }

        /* Generate random test data */
        plaintext = new byte[dataSize];
        secureRandom.nextBytes(plaintext);

        /* Get cipher instance */
        cipher = Cipher.getInstance(algorithm, jceProvider);

        /* Initialize for encryption. For authenticated modes (GCM/CCM), we
         * need to provide a GCMParameterSpec with tag length, but we let the
         * IV be auto-generated by not providing one in the spec. */
        if (algorithm.contains("GCM") || algorithm.contains("CCM")) {
            /* For GCM/CCM, provide tag length and proper IV */
            byte[] randomIv = new byte[12];
            secureRandom.nextBytes(randomIv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, randomIv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        } else {
            /* Standard modes can auto-generate IV without any spec */
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }

        /* Get IV after initialization - should be the original IV */
        ivAfterInit = cipher.getIV();
        assertNotNull("IV should not be null after encryption init for " +
            algorithm, ivAfterInit);

        /* Encrypt */
        ciphertext = cipher.doFinal(plaintext);
        assertNotNull("Ciphertext should not be null for " +
            algorithm, ciphertext);

        /* Get IV after encryption - should be same as after init */
        ivAfterEncryption = cipher.getIV();
        assertNotNull("IV should not be null after encryption for " +
            algorithm, ivAfterEncryption);
        assertArrayEquals("IV should remain consistent after encryption for " +
            algorithm + " with data size " + dataSize, ivAfterInit,
            ivAfterEncryption);

        /* Initialize for decryption with the retrieved IV */
        if (algorithm.contains("GCM") || algorithm.contains("CCM")) {
            /* For GCM/CCM, use GCMParameterSpec */
            int tagLen = 16; /* 128-bit tag */
            GCMParameterSpec authSpec =
                new GCMParameterSpec(tagLen * 8, ivAfterEncryption);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, authSpec);
        } else {
            /* Standard modes use IvParameterSpec */
            IvParameterSpec ivSpec = new IvParameterSpec(ivAfterEncryption);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }

        /* Get IV after decryption init - should be same as encryption IV */
        ivAfterDecryptInit = cipher.getIV();
        assertNotNull("IV should not be null after decryption init for " +
            algorithm, ivAfterDecryptInit);
        assertArrayEquals("IV should be consistent after decryption init for " +
            algorithm + " with data size " + dataSize, ivAfterEncryption,
            ivAfterDecryptInit);

        /* Decrypt */
        recoveredPlaintext = cipher.doFinal(ciphertext);
        assertNotNull("Recovered plaintext should not be null for " +
            algorithm, recoveredPlaintext);

        /* Verify decryption worked correctly */
        assertArrayEquals("Decrypted data should match original " +
            "plaintext for " + algorithm + " with data size " + dataSize,
            plaintext, recoveredPlaintext);

        /* Get IV after decryption - should still be consistent */
        ivAfterDecryption = cipher.getIV();
        assertNotNull("IV should not be null after decryption for " +
            algorithm, ivAfterDecryption);
        assertArrayEquals("IV should remain consistent after decryption for " +
            algorithm + " with data size " + dataSize, ivAfterEncryption,
            ivAfterDecryption);
    }

    @Test
    public void testByteBufferUpdateBasic()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               javax.crypto.ShortBufferException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            return;
        }

        /* Test basic ByteBuffer update operation */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] plaintext = new byte[64]; /* 4 AES blocks */
        secureRandom.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* Test with ByteBuffers */
        ByteBuffer inputBuf = ByteBuffer.wrap(plaintext);
        ByteBuffer outputBuf = ByteBuffer.allocate(plaintext.length + 16);

        int bytesWritten = cipher.update(inputBuf, outputBuf);
        assertTrue("Update should process some data", bytesWritten > 0);

        /* Compare with byte array result */
        byte[] expectedUpdate = cipher.update(plaintext);
        outputBuf.flip();
        byte[] actualUpdate = new byte[bytesWritten];
        outputBuf.get(actualUpdate);

        assertArrayEquals("ByteBuffer update should match byte array update",
                         expectedUpdate, actualUpdate);
    }

    @Test
    public void testByteBufferDoFinalBasic()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               javax.crypto.ShortBufferException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            return;
        }

        /* Test basic ByteBuffer doFinal operation */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] plaintext = new byte[32]; /* 2 AES blocks */
        secureRandom.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* Test with ByteBuffers */
        ByteBuffer inputBuf = ByteBuffer.wrap(plaintext);
        ByteBuffer outputBuf = ByteBuffer.allocate(plaintext.length + 16);

        int bytesWritten = cipher.doFinal(inputBuf, outputBuf);
        assertEquals("DoFinal should write expected bytes",
                    plaintext.length, bytesWritten);

        /* Compare with byte array result */
        byte[] expectedOutput = cipher.doFinal(plaintext);
        outputBuf.flip();
        byte[] actualOutput = new byte[bytesWritten];
        outputBuf.get(actualOutput);

        assertArrayEquals("ByteBuffer doFinal should match byte array result",
                         expectedOutput, actualOutput);
    }

    @Test
    public void testByteBufferWithOffsets()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               javax.crypto.ShortBufferException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            return;
        }

        /* Test ByteBuffer operations with position/limit offsets */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] plaintext = new byte[48]; /* 3 AES blocks */
        secureRandom.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* Create input buffer with offset */
        ByteBuffer inputBuf = ByteBuffer.allocate(plaintext.length + 20);
        inputBuf.position(10);
        inputBuf.put(plaintext);
        inputBuf.flip();
        inputBuf.position(10); /* Position at start of data */

        /* Create output buffer with offset */
        ByteBuffer outputBuf = ByteBuffer.allocate(plaintext.length + 30);
        outputBuf.position(15);

        int bytesWritten = cipher.doFinal(inputBuf, outputBuf);
        assertEquals("Should write expected number of bytes",
                    plaintext.length, bytesWritten);

        /* Verify position was updated correctly */
        assertEquals("Input buffer should be consumed",
                    inputBuf.limit(), inputBuf.position());
        assertEquals("Output buffer position should advance",
                    15 + bytesWritten, outputBuf.position());

        /* Extract and verify result */
        outputBuf.flip();
        outputBuf.position(15);
        byte[] result = new byte[bytesWritten];
        outputBuf.get(result);

        byte[] expected = cipher.doFinal(plaintext);
        assertArrayEquals("Result should match byte array encryption",
                         expected, result);
    }

    @Test
    public void testByteBufferMultipartOperation()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               javax.crypto.ShortBufferException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            return;
        }

        /* Test ByteBuffer multi-part encryption (update + doFinal) */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] plaintext = new byte[80]; /* 5 AES blocks */
        secureRandom.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* Split data for multi-part operation */
        ByteBuffer inputBuf1 = ByteBuffer.wrap(plaintext, 0, 32);
        ByteBuffer inputBuf2 = ByteBuffer.wrap(plaintext, 32, 48);
        ByteBuffer outputBuf = ByteBuffer.allocate(plaintext.length + 16);

        /* First update */
        int bytes1 = cipher.update(inputBuf1, outputBuf);
        assertTrue("First update should process data", bytes1 > 0);

        /* Final operation */
        int bytes2 = cipher.doFinal(inputBuf2, outputBuf);
        assertTrue("Final operation should process remaining data", bytes2 > 0);

        /* Verify total result */
        outputBuf.flip();
        byte[] result = new byte[bytes1 + bytes2];
        outputBuf.get(result);

        byte[] expected = cipher.doFinal(plaintext);
        assertArrayEquals("Multi-part result should match single operation",
                         expected, result);
    }

    @Test
    public void testByteBufferShortBufferException()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            return;
        }

        /* Test ShortBufferException is thrown correctly */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] plaintext = new byte[32];
        secureRandom.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        ByteBuffer inputBuf = ByteBuffer.wrap(plaintext);
        ByteBuffer outputBuf = ByteBuffer.allocate(16); /* Too small */

        try {
            cipher.doFinal(inputBuf, outputBuf);
            fail("Should throw ShortBufferException for insufficient space");
        } catch (javax.crypto.ShortBufferException e) {
            /* Expected */
        } catch (Exception e) {
            fail("Should throw ShortBufferException, got: " + e.getClass());
        }

        /* Verify buffers are in original state after exception */
        assertEquals("Input buffer position should be restored", 0,
                    inputBuf.position());
        assertEquals("Output buffer position should be restored", 0,
                    outputBuf.position());
    }

    @Test
    public void testByteBufferNullInputHandling()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               javax.crypto.ShortBufferException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            return;
        }

        /* Test empty ByteBuffer input processing */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* Test doFinal with empty input ByteBuffer */
        ByteBuffer emptyInput = ByteBuffer.allocate(0);
        ByteBuffer outputBuf = ByteBuffer.allocate(32);
        int bytesWritten = cipher.doFinal(emptyInput, outputBuf);

        /* Empty input should produce no output when no buffered data */
        assertEquals("Empty input with no buffered data should produce " +
            "no output", 0, bytesWritten);

        /* Test with actual data in ByteBuffers */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);  /* Reset cipher state */
        byte[] data = new byte[16];
        secureRandom.nextBytes(data);

        ByteBuffer inputBuf = ByteBuffer.wrap(data);
        outputBuf.clear();
        bytesWritten = cipher.doFinal(inputBuf, outputBuf);

        assertEquals("Should process full input data", 16, bytesWritten);
        outputBuf.flip();
        byte[] result = new byte[bytesWritten];
        outputBuf.get(result);

        /* Compare with expected result */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);  /* Reset cipher state */
        byte[] expected = cipher.doFinal(data);
        assertArrayEquals("ByteBuffer doFinal should match byte array doFinal",
                         expected, result);
    }

    @Test
    public void testByteBufferDirectBuffers()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               javax.crypto.ShortBufferException {

        if (!enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            return;
        }

        /* Test with direct ByteBuffers */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] plaintext = new byte[32];
        secureRandom.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* Create direct ByteBuffers */
        ByteBuffer inputBuf = ByteBuffer.allocateDirect(plaintext.length);
        inputBuf.put(plaintext);
        inputBuf.flip();

        ByteBuffer outputBuf = ByteBuffer.allocateDirect(plaintext.length + 16);

        int bytesWritten = cipher.doFinal(inputBuf, outputBuf);
        assertEquals("Should write expected bytes", plaintext.length,
                    bytesWritten);

        /* Extract result from direct buffer */
        outputBuf.flip();
        byte[] result = new byte[bytesWritten];
        outputBuf.get(result);

        /* Compare with regular encryption */
        byte[] expected = cipher.doFinal(plaintext);
        assertArrayEquals("Direct buffer result should match",
                         expected, result);
    }

    @Test
    public void testByteBufferWithGCM()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               InvalidAlgorithmParameterException,
               javax.crypto.ShortBufferException {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            return;
        }

        /* Test ByteBuffer operations with AES-GCM */
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        byte[] plaintext = new byte[48];
        secureRandom.nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        /* Test with ByteBuffers - GCM includes auth tag */
        ByteBuffer inputBuf = ByteBuffer.wrap(plaintext);
        ByteBuffer outputBuf = ByteBuffer.allocate(plaintext.length + 32);

        int bytesWritten = cipher.doFinal(inputBuf, outputBuf);
        assertEquals("GCM should include auth tag",
                    plaintext.length + 16, bytesWritten);

        /* Compare with byte array result */
        byte[] expected = cipher.doFinal(plaintext);
        outputBuf.flip();
        byte[] result = new byte[bytesWritten];
        outputBuf.get(result);

        assertArrayEquals("GCM ByteBuffer should match byte array",
                         expected, result);
    }

    /*
     * Test Cipher.getParameters() method for all supported algorithms
     * and modes. This method calls engineGetParameters() internally.
     */
    @Test
    public void testGetParameters()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException {

        if (!FeatureDetect.AesEnabled()) {
            /* skip if AES is not enabled */
            return;
        }

        /* Test AES-CBC mode */
        if (enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            testGetParametersAesCbc();
        }

        /* Test AES-GCM mode */
        if (enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            testGetParametersAesGcm();
        }

        /* Test AES-CCM mode */
        if (enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            testGetParametersAesCcm();
        }

        /* Test AES-ECB modes */
        if (enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            testGetParametersAesEcb();
        }

        /* Test AES-CTR mode */
        if (enabledJCEAlgos.contains("AES/CTR/NoPadding")) {
            testGetParametersAesCtr();
        }

        /* Test AES-OFB mode */
        if (enabledJCEAlgos.contains("AES/OFB/NoPadding")) {
            testGetParametersAesOfb();
        }

        /* Test 3DES-CBC mode */
        if (enabledJCEAlgos.contains("DESede/CBC/NoPadding")) {
            testGetParametersDesEdeCbc();
        }

        /* Test RSA mode */
        if (enabledJCEAlgos.contains("RSA/ECB/PKCS1Padding")) {
            testGetParametersRsa();
        }
    }

    private void testGetParametersAesCbc()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException {

        byte[] keyBytes = new byte[16];
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(keyBytes);
        secureRandom.nextBytes(ivBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        /* Test AES/CBC/NoPadding */
        if (enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            Cipher cipher =
                Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            AlgorithmParameters params = cipher.getParameters();
            assertNotNull("AES/CBC/NoPadding should return AlgorithmParameters",
                params);
            assertEquals("Algorithm should be AES", "AES",
                params.getAlgorithm());

            /* Verify we can extract the IV from parameters */
            try {
                IvParameterSpec extractedSpec = params.getParameterSpec(
                    IvParameterSpec.class);
                assertNotNull("Should be able to extract IvParameterSpec",
                    extractedSpec);
                assertArrayEquals("IV should match", ivBytes,
                    extractedSpec.getIV());

            } catch (java.security.spec.InvalidParameterSpecException e) {
                fail("Should be able to extract IvParameterSpec: " +
                     e.getMessage());
            }
        }

        /* Test AES/CBC/PKCS5Padding */
        if (enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding",
                                              jceProvider);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            AlgorithmParameters params = cipher.getParameters();
            assertNotNull("AES/CBC/PKCS5Padding should return " +
                "AlgorithmParameters", params);
            assertEquals("Algorithm should be AES", "AES",
                params.getAlgorithm());
        }
    }

    private void testGetParametersAesGcm()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException {

        byte[] keyBytes = new byte[16];
        byte[] ivBytes = new byte[12]; /* 96-bit IV for GCM */
        secureRandom.nextBytes(keyBytes);
        secureRandom.nextBytes(ivBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("AES/GCM/NoPadding should return AlgorithmParameters",
            params);
        assertEquals("Algorithm should be GCM", "GCM", params.getAlgorithm());

        /* Verify we can extract the GCMParameterSpec from parameters */
        try {
            GCMParameterSpec extractedSpec = params.getParameterSpec(
                GCMParameterSpec.class);
            assertNotNull("Should be able to extract GCMParameterSpec",
                extractedSpec);
            assertArrayEquals("IV should match", ivBytes,
                extractedSpec.getIV());
            assertEquals("Tag length should match", 128,
                extractedSpec.getTLen());

        } catch (java.security.spec.InvalidParameterSpecException e) {
            fail("Should be able to extract GCMParameterSpec: " +
                 e.getMessage());
        }
    }

    private void testGetParametersAesCcm()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException {

        byte[] keyBytes = new byte[16];
        byte[] nonceBytes = new byte[11]; /* 88-bit nonce for CCM */
        secureRandom.nextBytes(keyBytes);
        secureRandom.nextBytes(nonceBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        /* Use GCMParameterSpec for CCM compatibility */
        GCMParameterSpec ccmSpec = new GCMParameterSpec(128, nonceBytes);

        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, ccmSpec);

        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("AES/CCM/NoPadding should return AlgorithmParameters",
            params);
        assertEquals("Algorithm should be GCM (CCM compatibility)", "GCM",
                    params.getAlgorithm());

        /* Verify we can extract the GCMParameterSpec from parameters */
        try {
            GCMParameterSpec extractedSpec = params.getParameterSpec(
                GCMParameterSpec.class);
            assertNotNull("Should be able to extract GCMParameterSpec",
                extractedSpec);
            assertArrayEquals("Nonce should match", nonceBytes,
                extractedSpec.getIV());
            assertEquals("Tag length should match", 128,
                extractedSpec.getTLen());

        } catch (java.security.spec.InvalidParameterSpecException e) {
            fail("Should be able to extract GCMParameterSpec: " +
                 e.getMessage());
        }
    }

    private void testGetParametersAesEcb()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, NoSuchPaddingException {

        byte[] keyBytes = new byte[16];
        secureRandom.nextBytes(keyBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        /* Test AES/ECB/NoPadding */
        if (enabledJCEAlgos.contains("AES/ECB/NoPadding")) {
            Cipher cipher =
                Cipher.getInstance("AES/ECB/NoPadding", jceProvider);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            AlgorithmParameters params = cipher.getParameters();
            assertNull("AES/ECB/NoPadding should return null " +
                "(no parameters)", params);
        }

        /* Test AES/ECB/PKCS5Padding */
        if (enabledJCEAlgos.contains("AES/ECB/PKCS5Padding")) {
            Cipher cipher =
                Cipher.getInstance("AES/ECB/PKCS5Padding", jceProvider);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            AlgorithmParameters params = cipher.getParameters();
            assertNull("AES/ECB/PKCS5Padding should return null " +
                "(no parameters)", params);
        }
    }

    private void testGetParametersAesCtr()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException {

        byte[] keyBytes = new byte[16];
        byte[] ivBytes = new byte[16]; /* 128-bit IV for CTR */
        secureRandom.nextBytes(keyBytes);
        secureRandom.nextBytes(ivBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("AES/CTR/NoPadding should return AlgorithmParameters",
            params);
        assertEquals("Algorithm should be AES", "AES", params.getAlgorithm());

        /* Verify we can extract the IV from parameters */
        try {
            IvParameterSpec extractedSpec = params.getParameterSpec(
                IvParameterSpec.class);
            assertNotNull("Should be able to extract IvParameterSpec",
                extractedSpec);
            assertArrayEquals("IV should match", ivBytes,
                extractedSpec.getIV());

        } catch (java.security.spec.InvalidParameterSpecException e) {
            fail("Should be able to extract IvParameterSpec: " +
                 e.getMessage());
        }
    }

    private void testGetParametersAesOfb()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException {

        byte[] keyBytes = new byte[16];
        byte[] ivBytes = new byte[16]; /* 128-bit IV for OFB */
        secureRandom.nextBytes(keyBytes);
        secureRandom.nextBytes(ivBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("AES/OFB/NoPadding should return AlgorithmParameters",
            params);
        assertEquals("Algorithm should be AES", "AES", params.getAlgorithm());

        /* Verify we can extract the IV from parameters */
        try {
            IvParameterSpec extractedSpec = params.getParameterSpec(
                IvParameterSpec.class);
            assertNotNull("Should be able to extract IvParameterSpec",
                extractedSpec);
            assertArrayEquals("IV should match", ivBytes,
                extractedSpec.getIV());

        } catch (java.security.spec.InvalidParameterSpecException e) {
            fail("Should be able to extract IvParameterSpec: " +
                 e.getMessage());
        }
    }

    private void testGetParametersDesEdeCbc()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException {

        byte[] keyBytes = new byte[24]; /* 3DES key is 192 bits (24 bytes) */
        byte[] ivBytes = new byte[8];   /* 3DES IV is 64 bits (8 bytes) */
        secureRandom.nextBytes(keyBytes);
        secureRandom.nextBytes(ivBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DESede");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("DESede/CBC/NoPadding should return " +
            "AlgorithmParameters", params);
        assertEquals("Algorithm should be DESede", "DESede",
            params.getAlgorithm());

        /* Verify we can extract the IV from parameters */
        try {
            IvParameterSpec extractedSpec = params.getParameterSpec(
                IvParameterSpec.class);
            assertNotNull("Should be able to extract IvParameterSpec",
                extractedSpec);
            assertArrayEquals("IV should match", ivBytes,
                extractedSpec.getIV());

        } catch (java.security.spec.InvalidParameterSpecException e) {
            fail("Should be able to extract IvParameterSpec: " +
                 e.getMessage());
        }
    }

    private void testGetParametersRsa()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, NoSuchPaddingException {

        /* Generate RSA key pair for testing */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        /* Test RSA/ECB/PKCS1Padding with public key */
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        java.security.AlgorithmParameters params = cipher.getParameters();
        assertNull("RSA/ECB/PKCS1Padding should return null (no parameters)",
            params);

        /* Test RSA/ECB/PKCS1Padding with private key */
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", jceProvider);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        params = cipher.getParameters();
        assertNull("RSA/ECB/PKCS1Padding should return null (no parameters)",
            params);

        /* Test RSA (default) with public key */
        if (enabledJCEAlgos.contains("RSA")) {
            cipher = Cipher.getInstance("RSA", jceProvider);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            params = cipher.getParameters();
            assertNull("RSA should return null (no parameters)", params);
        }
    }

    /*
     * Test that getParameters() returns null when cipher is not initialized
     */
    @Test
    public void testGetParametersUninitializedCipher()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* skip if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", jceProvider);
        /* Don't initialize the cipher */

        java.security.AlgorithmParameters params = cipher.getParameters();
        assertNull("Uninitialized cipher should return null parameters",
            params);
    }

    /*
     * Test getParameters() after cipher operations (encrypt/decrypt)
     */
    @Test
    public void testGetParametersAfterCipherOperations()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidKeyException, InvalidAlgorithmParameterException,
               NoSuchPaddingException, IllegalBlockSizeException,
               BadPaddingException {

        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* skip if AES/CBC/PKCS5Padding is not enabled */
            return;
        }

        byte[] keyBytes = new byte[16];
        byte[] ivBytes = new byte[16];
        byte[] plaintext = "Test message for cipher operations".getBytes();
        secureRandom.nextBytes(keyBytes);
        secureRandom.nextBytes(ivBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        /* Test after encryption */
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        /* Encrypt data */
        byte[] ciphertext = cipher.doFinal(plaintext);

        /* getParameters() should still work after encryption */
        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("Should return parameters after encryption", params);
        assertEquals("Algorithm should be AES", "AES", params.getAlgorithm());

        /* Test after decryption */
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(ciphertext);

        /* getParameters() should still work after decryption */
        params = cipher.getParameters();
        assertNotNull("Should return parameters after decryption", params);
        assertEquals("Algorithm should be AES", "AES", params.getAlgorithm());

        /* Verify decryption worked correctly */
        assertArrayEquals("Decrypted text should match original", plaintext,
            decrypted);
    }

    private class CipherVector {

        private byte key[];
        private byte iv[];
        private byte input[];
        private byte output[];
        private byte tag[]; /* AES-GCM auth tag */
        private byte aad[]; /* AES-GCM additional auth data */

        public CipherVector(byte[] key, byte[] iv, byte[] input,
                            byte[] output, byte[] tag, byte[] aad) {
            this.key = key;
            this.iv = iv;
            this.input = input;
            this.output = output;
            this.tag = tag;
            this.aad = aad;
        }

        public byte[] getKey() {
            return this.key;
        }

        public byte[] getIV() {
            return this.iv;
        }

        public byte[] getInput() {
            return this.input;
        }

        public byte[] getOutput() {
            return this.output;
        }

        public byte[] getTag() {
            return this.tag;
        }

        public byte[] getAAD() {
            return this.aad;
        }
    }

    /**
     * Test for regression of NPE when AlgorithmParameters is null.
     */
    @Test
    public void testNullAlgorithmParametersNPERegression()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException, IllegalBlockSizeException,
               BadPaddingException {

        Cipher c;
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");

        /* Test AES/ECB/PKCS5Padding - mode that doesn't require IV */
        if (enabledJCEAlgos.contains("AES/ECB/PKCS5Padding")) {
            c = Cipher.getInstance("AES/ECB/PKCS5Padding", jceProvider);
            c.init(Cipher.ENCRYPT_MODE, key);

            /* Get parameters (may be null for ECB mode) */
            AlgorithmParameters params = c.getParameters();

            /* This should not throw NPE even if params is null */
            c.init(Cipher.DECRYPT_MODE, key, params);

            /* Should be able to call doFinal with empty buffer */
            byte[] result = c.doFinal(new byte[0]);
            assertNotNull("doFinal should not return null", result);
        }

        /* Test AES/CBC/PKCS5Padding - mode that has parameters */
        if (enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            c = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
            c.init(Cipher.ENCRYPT_MODE, key);

            /* Get parameters (should contain IV for CBC mode) */
            AlgorithmParameters params = c.getParameters();

            /* This should not throw NPE */
            c.init(Cipher.DECRYPT_MODE, key, params);

            /* Should be able to call doFinal with empty buffer */
            byte[] result = c.doFinal(new byte[0]);
            assertNotNull("doFinal should not return null", result);
        }
    }

    /*
     * Test AES-GCM cipher reinitalization with getParameters().
     * This tests where cipher reinitialization after using getParameters()
     * should properly handle GCM mode with correct tag length.
     */
    @Test
    public void testAESGCMReinitializationWithGetParameters()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               InvalidAlgorithmParameterException {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            return;
        }

        /* Test multiple key sizes */
        int[] keySizes = {128, 192, 256};
        for (int keySize : keySizes) {
            testAESGCMReinitWithKeySize(keySize);
        }
    }

    private void testAESGCMReinitWithKeySize(int keySize)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               InvalidAlgorithmParameterException {

        byte[] key = new byte[keySize / 8];
        secureRandom.nextBytes(key);
        byte[] plaintext = "Hello, World! This is a test message.".getBytes();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        /* First encryption - let cipher generate IV automatically */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ciphertext1 = cipher.doFinal(plaintext);

        /* Get parameters after first encryption */
        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("GCM should return AlgorithmParameters", params);

        /* Decrypt using getParameters() */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
        byte[] decrypted1 = cipher.doFinal(ciphertext1);
        assertArrayEquals("First decryption should match plaintext",
            plaintext, decrypted1);

        /* Second encryption after reinit */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ciphertext2 = cipher.doFinal(plaintext);

        /* Get parameters again */
        AlgorithmParameters params2 = cipher.getParameters();
        assertNotNull("GCM should return AlgorithmParameters on reuse",
            params2);

        /* Decrypt second ciphertext using getParameters() */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, params2);
        byte[] decrypted2 = cipher.doFinal(ciphertext2);
        assertArrayEquals("Second decryption should match plaintext",
            plaintext, decrypted2);

        /* Test multiple reinitializations in sequence */
        for (int i = 0; i < 5; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] ctext = cipher.doFinal(plaintext);
            AlgorithmParameters p = cipher.getParameters();
            cipher.init(Cipher.DECRYPT_MODE, keySpec, p);
            byte[] ptext = cipher.doFinal(ctext);
            assertArrayEquals("Reinit iteration " + i + " should work",
                plaintext, ptext);
        }
    }

    /*
     * Test AES-GCM with explicit GCMParameterSpec and getParameters() reuse.
     * This ensures we handle explicit parameter specs correctly.
     */
    @Test
    public void testAESGCMExplicitParamsWithGetParameters()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               InvalidAlgorithmParameterException {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            return;
        }

        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        byte[] plaintext = "Test message for explicit GCM params.".getBytes();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        /* Test different tag lengths */
        int[] tagLengths = {96, 104, 112, 120, 128};

        for (int tagLen : tagLengths) {
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLen, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            /* Get parameters and verify they contain correct tag length */
            AlgorithmParameters params = cipher.getParameters();
            assertNotNull("Should return parameters for tag length " + tagLen,
                params);

            /* Decrypt using getParameters() */
            cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
            byte[] decrypted = cipher.doFinal(ciphertext);
            assertArrayEquals("Decryption with tag length " + tagLen +
                " should work", plaintext, decrypted);
        }
    }

    /*
     * Test AES-CCM cipher reinitalization with getParameters().
     */
    @Test
    public void testAESCCMReinitializationWithGetParameters()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               InvalidAlgorithmParameterException {

        if (!enabledJCEAlgos.contains("AES/CCM/NoPadding")) {
            return;
        }

        /* Test multiple key sizes */
        int[] keySizes = {128, 192, 256};
        for (int keySize : keySizes) {
            testAESCCMReinitWithKeySize(keySize);
        }
    }

    private void testAESCCMReinitWithKeySize(int keySize)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               InvalidAlgorithmParameterException {

        byte[] key = new byte[keySize / 8];
        secureRandom.nextBytes(key);
        byte[] plaintext = "Hello CCM mode test!".getBytes();

        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        /* CCM uses GCMParameterSpec for Java 8+ compatibility */
        byte[] iv = new byte[12]; /* CCM IV length */
        secureRandom.nextBytes(iv);

        /* Use GCMParameterSpec for CCM mode, 128-bit tag */
        GCMParameterSpec ccmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
        byte[] ciphertext1 = cipher.doFinal(plaintext);

        /* Get parameters after first encryption */
        AlgorithmParameters params = cipher.getParameters();
        assertNotNull("CCM should return AlgorithmParameters", params);

        /* Decrypt using getParameters() */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
        byte[] decrypted1 = cipher.doFinal(ciphertext1);
        assertArrayEquals("CCM decryption should match plaintext",
                         plaintext, decrypted1);

        /* Test reinitializtion sequence */
        for (int i = 0; i < 3; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmSpec);
            byte[] ctext = cipher.doFinal(plaintext);
            AlgorithmParameters p = cipher.getParameters();
            cipher.init(Cipher.DECRYPT_MODE, keySpec, p);
            byte[] ptext = cipher.doFinal(ctext);
            assertArrayEquals("CCM reinit iteration " + i + " should work",
                plaintext, ptext);
        }
    }

    /**
     * Test AlgorithmParameters.getInstance("GCM") basic functionality
     */
    @Test
    public void testGCMAlgorithmParametersGetInstance()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        /* Test getting instance with "GCM" algorithm */
        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);
        assertNotNull("GCM AlgorithmParameters should not be null", params);
        assertEquals("Provider should be wolfJCE", jceProvider,
            params.getProvider().getName());

        /* Test alias "AES-GCM" */
        AlgorithmParameters paramsAlias =
            AlgorithmParameters.getInstance("AES-GCM", jceProvider);
        assertNotNull("AES-GCM AlgorithmParameters should not be null",
            paramsAlias);
        assertEquals("Provider should be wolfJCE", jceProvider,
            paramsAlias.getProvider().getName());
    }

    /**
     * Test GCM AlgorithmParameters initialization with GCMParameterSpec
     */
    @Test
    public void testGCMAlgorithmParametersInit()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);

        /* Test with valid GCMParameterSpec */
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        params.init(gcmSpec);

        /* Get the spec back and verify */
        GCMParameterSpec retrievedSpec =
            params.getParameterSpec(GCMParameterSpec.class);
        assertNotNull("Retrieved GCMParameterSpec should not be null",
            retrievedSpec);
        assertEquals("Tag length should match", 128, retrievedSpec.getTLen());
        assertArrayEquals("IV should match", iv, retrievedSpec.getIV());

        /* Test with different tag lengths */
        int[] tagLengths = {96, 104, 112, 120, 128};
        for (int tagLen : tagLengths) {
            params = AlgorithmParameters.getInstance("GCM", jceProvider);
            gcmSpec = new GCMParameterSpec(tagLen, iv);
            params.init(gcmSpec);

            retrievedSpec = params.getParameterSpec(GCMParameterSpec.class);
            assertEquals("Tag length should match for " + tagLen,
                tagLen, retrievedSpec.getTLen());
        }
    }

    /**
     * Test GCM AlgorithmParameters parameter validation
     */
    @Test
    public void testGCMAlgorithmParametersValidation()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);

        /* Test with null IV - GCMParameterSpec constructor throws
         * IllegalArgumentException for null IV */
        try {
            GCMParameterSpec invalidSpec = new GCMParameterSpec(128, null);
            params.init(invalidSpec);
            fail("Should throw IllegalArgumentException for null IV");
        } catch (Exception e) {
            assertTrue("Should be IllegalArgumentException",
                e instanceof IllegalArgumentException);
        }

        /* Test with empty IV */
        try {
            params = AlgorithmParameters.getInstance("GCM", jceProvider);
            GCMParameterSpec invalidSpec = new GCMParameterSpec(128,
                new byte[0]);
            params.init(invalidSpec);
            fail("Should throw InvalidParameterSpecException for empty IV");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof java.security.spec.InvalidParameterSpecException);
        }

        /* Test with invalid tag length */
        try {
            params = AlgorithmParameters.getInstance("GCM", jceProvider);
            byte[] iv = new byte[12];
            GCMParameterSpec invalidSpec = new GCMParameterSpec(0, iv);
            params.init(invalidSpec);
            fail("Should throw InvalidParameterSpecException for " +
                "zero tag length");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof java.security.spec.InvalidParameterSpecException);
        }

        /* Test with negative tag length */
        try {
            params = AlgorithmParameters.getInstance("GCM", jceProvider);
            byte[] iv = new byte[12];
            GCMParameterSpec invalidSpec = new GCMParameterSpec(-1, iv);
            params.init(invalidSpec);
            fail("Should throw Exception for negative tag length");
        } catch (Exception e) {
            if (e instanceof InvalidParameterSpecException) {
                /* Expected */
            } else if (e instanceof IllegalArgumentException) {
                /* Some JDK versions may throw IllegalArgumentException */
            } else {
                fail("Unexpected exception type: " + e.getClass().getName());
            }
        }

        /* Test with non-GCMParameterSpec */
        try {
            params = AlgorithmParameters.getInstance("GCM", jceProvider);
            IvParameterSpec invalidSpec = new IvParameterSpec(new byte[12]);
            params.init(invalidSpec);
            fail("Should throw InvalidParameterSpecException for " +
                "non-GCMParameterSpec");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof java.security.spec.InvalidParameterSpecException);
        }
    }

    /**
     * Test GCM AlgorithmParameters getParameterSpec with different classes
     */
    @Test
    public void testGCMAlgorithmParametersGetParameterSpec()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        params.init(gcmSpec);

        /* Test getting GCMParameterSpec */
        GCMParameterSpec retrievedSpec =
            params.getParameterSpec(GCMParameterSpec.class);
        assertNotNull("Should return GCMParameterSpec", retrievedSpec);
        assertEquals("Tag length should match", 128, retrievedSpec.getTLen());
        assertArrayEquals("IV should match", iv, retrievedSpec.getIV());

        /* Test getting AlgorithmParameterSpec (superclass) */
        AlgorithmParameterSpec genericSpec =
            params.getParameterSpec(AlgorithmParameterSpec.class);
        assertNotNull("Should return AlgorithmParameterSpec", genericSpec);
        assertTrue("Should be instance of GCMParameterSpec",
            genericSpec instanceof GCMParameterSpec);

        /* Test with unsupported class */
        try {
            params.getParameterSpec(IvParameterSpec.class);
            fail("Should throw InvalidParameterSpecException for " +
                "unsupported class");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof java.security.spec.InvalidParameterSpecException);
        }

        /* Test with null class */
        try {
            params.getParameterSpec(null);
            fail("Should throw InvalidParameterSpecException for null class");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof java.security.spec.InvalidParameterSpecException);
        }

        /* Test getting spec from uninitialized parameters */
        try {
            AlgorithmParameters uninitParams =
                AlgorithmParameters.getInstance("GCM", jceProvider);
            uninitParams.getParameterSpec(GCMParameterSpec.class);
            fail("Should throw InvalidParameterSpecException for " +
                "uninitialized parameters");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof java.security.spec.InvalidParameterSpecException);
        }
    }

    /**
     * Test GCM AlgorithmParameters unsupported operations
     */
    @Test
    public void testGCMAlgorithmParametersUnsupportedOperations()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);

        /* Test encoded parameter operations (should be unsupported) */
        try {
            params.init(new byte[16]);
            fail("Should throw IOException for encoded init");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }

        try {
            params.init(new byte[16], "DER");
            fail("Should throw IOException for encoded init with format");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }

        /* Initialize with valid spec for encoding tests */
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        params.init(gcmSpec);

        try {
            params.getEncoded();
            fail("Should throw IOException for getEncoded");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }

        try {
            params.getEncoded("DER");
            fail("Should throw IOException for getEncoded with format");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }
    }

    /**
     * Test GCM AlgorithmParameters toString method
     */
    @Test
    public void testGCMAlgorithmParametersToString()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);

        /* Test toString for uninitialized parameters - Java
         * AlgorithmParameters.toString() returns null when uninitialized */
        String uninitString = params.toString();
        /* Standard Java behavior is to return null for uninitialized params */
        assertNull("Uninitialized toString should return null", uninitString);

        /* Test toString for initialized parameters */
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        params.init(gcmSpec);

        String initString = params.toString();
        assertNotNull("toString should not return null", initString);
        assertTrue("Should contain tag length",
            initString.contains("tagLen=128"));
        assertTrue("Should contain IV length",
            initString.contains("ivLen=12"));
    }

    /**
     * Test GCM AlgorithmParameters IV isolation (no external modification)
     */
    @Test
    public void testGCMAlgorithmParametersIVIsolation()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);

        /* Create IV and modify original after init */
        byte[] originalIV = new byte[12];
        new SecureRandom().nextBytes(originalIV);
        byte[] originalIVCopy = originalIV.clone();

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, originalIV);
        params.init(gcmSpec);

        /* Modify the original IV array */
        Arrays.fill(originalIV, (byte) 0xFF);

        /* Get the spec back and verify IV wasn't modified */
        GCMParameterSpec retrievedSpec =
            params.getParameterSpec(GCMParameterSpec.class);
        assertArrayEquals("IV should not be affected by external modification",
            originalIVCopy, retrievedSpec.getIV());

        /* Modify the retrieved IV and get spec again */
        byte[] retrievedIV = retrievedSpec.getIV();
        Arrays.fill(retrievedIV, (byte) 0x00);

        GCMParameterSpec retrievedSpec2 =
            params.getParameterSpec(GCMParameterSpec.class);
        assertArrayEquals("Internal IV should not be affected by " +
            "modification of returned array", originalIVCopy,
            retrievedSpec2.getIV());
    }

    /**
     * Test GCM AlgorithmParameters integration with Cipher operations
     */
    @Test
    public void testGCMAlgorithmParametersWithCipher()
            throws Exception {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* GCM not compiled in */
            return;
        }

        /* Create AlgorithmParameters with GCM spec */
        AlgorithmParameters params =
            AlgorithmParameters.getInstance("GCM", jceProvider);

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        params.init(gcmSpec);

        /* Use with cipher for encryption */
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);

        byte[] plaintext = "Test message for GCM cipher integration".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        /* Decrypt using the same parameters */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals("Decrypted text should match original",
            plaintext, decrypted);

        /* Verify cipher returns compatible parameters */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        AlgorithmParameters cipherParams = cipher.getParameters();
        assertNotNull("Cipher should return parameters", cipherParams);

        /* Should be able to use cipher-returned params for decryption */
        byte[] ciphertext2 = cipher.doFinal(plaintext);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, cipherParams);
        byte[] decrypted2 = cipher.doFinal(ciphertext2);

        assertArrayEquals("Should decrypt correctly with cipher parameters",
            plaintext, decrypted2);
    }

    /**
     * Test AlgorithmParameters.getInstance("AES") basic functionality
     */
    @Test
    public void testAESAlgorithmParametersGetInstance()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES")) {
            /* AES not compiled in */
            return;
        }

        /* Test getting instance with "AES" algorithm */
        AlgorithmParameters params =
            AlgorithmParameters.getInstance("AES", jceProvider);
        assertNotNull("AES AlgorithmParameters should not be null", params);
        assertEquals("Provider should be wolfJCE", jceProvider,
            params.getProvider().getName());
    }

    /**
     * Test AES AlgorithmParameters initialization with IvParameterSpec
     */
    @Test
    public void testAESAlgorithmParametersInit()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES")) {
            /* AES not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("AES", jceProvider);

        /* Test with valid IvParameterSpec */
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        params.init(ivSpec);

        /* Get the spec back and verify */
        IvParameterSpec retrievedSpec =
            params.getParameterSpec(IvParameterSpec.class);
        assertNotNull("Retrieved spec should not be null", retrievedSpec);
        assertArrayEquals("IV should match", iv, retrievedSpec.getIV());
    }

    /**
     * Test AES AlgorithmParameters invalid initialization scenarios
     */
    @Test
    public void testAESAlgorithmParametersInvalidInit()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES")) {
            /* AES not compiled in */
            return;
        }

        /* Test with null IV - expect NullPointerException */
        try {
            AlgorithmParameters params =
                AlgorithmParameters.getInstance("AES", jceProvider);
            IvParameterSpec invalidSpec = new IvParameterSpec(null);
            params.init(invalidSpec);
            fail("Should throw NullPointerException for null IV");
        } catch (Exception e) {
            assertTrue("Should be NullPointerException",
                e instanceof NullPointerException);
        }

        /* Test with empty IV */
        try {
            AlgorithmParameters params =
                AlgorithmParameters.getInstance("AES", jceProvider);
            IvParameterSpec invalidSpec = new IvParameterSpec(new byte[0]);
            params.init(invalidSpec);
            fail("Should throw InvalidParameterSpecException for empty IV");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof InvalidParameterSpecException);
        }

        /* Test with wrong IV length (not 16 bytes for AES) */
        try {
            AlgorithmParameters params =
                AlgorithmParameters.getInstance("AES", jceProvider);
            IvParameterSpec invalidSpec = new IvParameterSpec(new byte[12]);
            params.init(invalidSpec);
            fail("Should throw InvalidParameterSpecException for " +
                 "wrong IV length");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof InvalidParameterSpecException);
        }

        /* Test with non-IvParameterSpec */
        try {
            AlgorithmParameters params =
                AlgorithmParameters.getInstance("AES", jceProvider);
            GCMParameterSpec invalidSpec = new GCMParameterSpec(128,
                new byte[16]);
            params.init(invalidSpec);
            fail("Should throw InvalidParameterSpecException for " +
                 "non-IvParameterSpec");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof InvalidParameterSpecException);
        }
    }

    /**
     * Test AES AlgorithmParameters getParameterSpec functionality
     */
    @Test
    public void testAESAlgorithmParametersGetParameterSpec()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES")) {
            /* AES not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("AES", jceProvider);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        params.init(ivSpec);

        /* Test getting IvParameterSpec */
        IvParameterSpec retrievedSpec =
            params.getParameterSpec(IvParameterSpec.class);
        assertNotNull("Should return IvParameterSpec", retrievedSpec);
        assertArrayEquals("IV should match original", iv,
            retrievedSpec.getIV());

        /* Test getting AlgorithmParameterSpec (parent class) */
        AlgorithmParameterSpec genericSpec =
            params.getParameterSpec(AlgorithmParameterSpec.class);
        assertNotNull("Should return AlgorithmParameterSpec", genericSpec);
        assertTrue("Should be instance of IvParameterSpec",
            genericSpec instanceof IvParameterSpec);

        /* Test getting unsupported parameter spec */
        try {
            params.getParameterSpec(GCMParameterSpec.class);
            fail("Should throw InvalidParameterSpecException for " +
                 "unsupported spec");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof InvalidParameterSpecException);
        }

        /* Test getting spec from uninitialized parameters */
        try {
            AlgorithmParameters uninitParams =
                AlgorithmParameters.getInstance("AES", jceProvider);
            uninitParams.getParameterSpec(IvParameterSpec.class);
            fail("Should throw InvalidParameterSpecException for " +
                 "uninitialized parameters");
        } catch (Exception e) {
            assertTrue("Should be InvalidParameterSpecException",
                e instanceof InvalidParameterSpecException);
        }
    }

    /**
     * Test AES AlgorithmParameters encoded operations (should be unsupported)
     */
    @Test
    public void testAESAlgorithmParametersEncodedOperations()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES")) {
            /* AES not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("AES", jceProvider);

        /* Test encoded parameter operations (should be unsupported) */
        try {
            params.init(new byte[16]);
            fail("Should throw IOException for encoded init");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }

        try {
            params.init(new byte[16], "ASN.1");
            fail("Should throw IOException for encoded init with format");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }

        /* Initialize properly first */
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        params.init(ivSpec);

        /* Test encoded getters */
        try {
            params.getEncoded();
            fail("Should throw IOException for getEncoded");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }

        try {
            params.getEncoded("ASN.1");
            fail("Should throw IOException for getEncoded with format");
        } catch (Exception e) {
            assertTrue("Should be IOException",
                e instanceof java.io.IOException);
        }
    }

    /**
     * Test AES AlgorithmParameters toString functionality
     */
    @Test
    public void testAESAlgorithmParametersToString()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES")) {
            /* AES not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("AES", jceProvider);

        /* Test toString for uninitialized parameters */
        String uninitString = params.toString();
        assertNull("toString should return null for uninitialized parameters ",
                   uninitString);

        /* Test toString for initialized parameters */
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        params.init(ivSpec);

        String initString = params.toString();
        assertNotNull("toString should not return null", initString);
        assertTrue("Should contain IV length",
            initString.contains("ivLen=16"));
    }

    /**
     * Test AES AlgorithmParameters IV isolation (no external modification)
     */
    @Test
    public void testAESAlgorithmParametersIVIsolation()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES")) {
            /* AES not compiled in */
            return;
        }

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("AES", jceProvider);

        /* Create IV and modify original after init */
        byte[] originalIV = new byte[16];
        new SecureRandom().nextBytes(originalIV);
        byte[] originalIVCopy = originalIV.clone();
        IvParameterSpec ivSpec = new IvParameterSpec(originalIV);
        params.init(ivSpec);

        /* Modify the original IV array */
        Arrays.fill(originalIV, (byte)0xFF);

        /* Get IV back and verify it wasn't affected */
        IvParameterSpec retrievedSpec =
            params.getParameterSpec(IvParameterSpec.class);
        assertArrayEquals("IV should not be affected by external " +
                         "modification", originalIVCopy, retrievedSpec.getIV());

        /* Modify the retrieved IV and verify original stays intact */
        byte[] retrievedIV = retrievedSpec.getIV();
        Arrays.fill(retrievedIV, (byte)0x00);

        /* Get IV again and verify it's still correct */
        IvParameterSpec retrievedSpec2 =
            params.getParameterSpec(IvParameterSpec.class);
        assertArrayEquals("IV should not be affected by modification of " +
                         "retrieved array", originalIVCopy,
                         retrievedSpec2.getIV());
    }

    /**
     * Test AES AlgorithmParameters with AES/CBC cipher integration
     */
    @Test
    public void testAESAlgorithmParametersWithCipher()
            throws Exception {
        if (!enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            /* AES/CBC not compiled in */
            return;
        }

        /* Create AlgorithmParameters with IV spec */
        AlgorithmParameters params =
            AlgorithmParameters.getInstance("AES", jceProvider);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        params.init(ivSpec);

        /* Use with cipher for encryption */
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding",
            jceProvider);
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);

        byte[] plaintext = "Test message for AES cipher integration".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        /* Decrypt using the same parameters */
        cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertArrayEquals("Decrypted text should match original",
            plaintext, decrypted);

        /* Verify cipher returns compatible parameters */
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        AlgorithmParameters cipherParams = cipher.getParameters();
        assertNotNull("Cipher should return parameters", cipherParams);

        /* Should be able to use cipher-returned params for decryption */
        byte[] ciphertext2 = cipher.doFinal(plaintext);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, cipherParams);
        byte[] decrypted2 = cipher.doFinal(ciphertext2);
        assertArrayEquals("Should decrypt correctly with cipher parameters",
            plaintext, decrypted2);
    }

    /**
     * Test that calling getOutputSize(0) doesn't throw an exception
     * when using PKCS5 padding modes.
     */
    @Test
    public void testGetOutputSizeZeroInputPKCS5Padding() throws Exception {

        if (!enabledJCEAlgos.contains("AES/ECB/PKCS5Padding")) {
            /* skip test if AES/ECB/PKCS5Padding not supported */
            return;
        }

        byte[] key = new byte[] {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB,
            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF
        };

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        /* This should not throw an exception and should return block size */
        int outputSize = cipher.getOutputSize(0);
        assertEquals("Output size for zero input should be one block " +
            "(16 bytes)", 16, outputSize);

        /* Test AES/CBC/PKCS5Padding if available */
        if (enabledJCEAlgos.contains("AES/CBC/PKCS5Padding")) {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", jceProvider);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            outputSize = cipher.getOutputSize(0);
            assertEquals("CBC: Output size for zero input should be one " +
                "block (16 bytes)", 16, outputSize);
        }

        /* Test DESede if available */
        if (enabledJCEAlgos.contains("DESede/CBC/PKCS5Padding")) {
            byte[] desKey = new byte[24]; /* 3DES requires 24-byte key */
            Arrays.fill(desKey, (byte)0x42);
            SecretKeySpec desKeySpec = new SecretKeySpec(desKey, "DESede");

            cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", jceProvider);
            cipher.init(Cipher.ENCRYPT_MODE, desKeySpec);

            outputSize = cipher.getOutputSize(0);
            assertEquals("DESede: Output size for zero input should be one " +
                "block (8 bytes)", 8, outputSize);
        }
    }

    /**
     * Test AES-GCM with null plaintext input. This tests scenarios where
     * users may only provide AAD to generate an authentication tag.
     * Uses test vectors from OpenJDK SunJCE tests that have null plaintext.
     */
    @Test
    public void testAesGcmWithNullPlaintext()
        throws NoSuchAlgorithmException, InvalidKeyException,
               IllegalBlockSizeException, NoSuchProviderException,
               InvalidAlgorithmParameterException, BadPaddingException,
               NoSuchPaddingException {

        if (!enabledJCEAlgos.contains("AES/GCM/NoPadding")) {
            /* skip if AES-GCM is not enabled */
            return;
        }

        /*
         * Test vector from OpenJDK TestKATForGCM.java - Test case 1
         * 96-bit iv with 128-bit tag, no plaintext, no AAD
         */
        byte[] key = new byte[] {
            (byte)0x11, (byte)0x75, (byte)0x4c, (byte)0xd7,
            (byte)0x2a, (byte)0xec, (byte)0x30, (byte)0x9b,
            (byte)0xf5, (byte)0x2f, (byte)0x76, (byte)0x87,
            (byte)0x21, (byte)0x2e, (byte)0x89, (byte)0x57
        };
        byte[] iv = new byte[] {
            (byte)0x3c, (byte)0x81, (byte)0x9d, (byte)0x9a,
            (byte)0x9b, (byte)0xed, (byte)0x08, (byte)0x76,
            (byte)0x15, (byte)0x03, (byte)0x0b, (byte)0x65
        };
        byte[] expectedTag = new byte[] {
            (byte)0x25, (byte)0x03, (byte)0x27, (byte)0xc6,
            (byte)0x74, (byte)0xaa, (byte)0xf4, (byte)0x77,
            (byte)0xae, (byte)0xf2, (byte)0x67, (byte)0x57,
            (byte)0x48, (byte)0xcf, (byte)0x69, (byte)0x71
        };

        /*
         * Test vector from OpenJDK TestKATForGCM.java - Test case 6
         * 96-bit iv with 128-bit tag, no plaintext, 16-byte AAD
         */
        byte[] key2 = new byte[] {
            (byte)0x77, (byte)0xbe, (byte)0x63, (byte)0x70,
            (byte)0x89, (byte)0x71, (byte)0xc4, (byte)0xe2,
            (byte)0x40, (byte)0xd1, (byte)0xcb, (byte)0x79,
            (byte)0xe8, (byte)0xd7, (byte)0x7f, (byte)0xeb
        };
        byte[] iv2 = new byte[] {
            (byte)0xe0, (byte)0xe0, (byte)0x0f, (byte)0x19,
            (byte)0xfe, (byte)0xd7, (byte)0xba, (byte)0x01,
            (byte)0x36, (byte)0xa7, (byte)0x97, (byte)0xf3
        };
        byte[] aad2 = new byte[] {
            (byte)0x7a, (byte)0x43, (byte)0xec, (byte)0x1d,
            (byte)0x9c, (byte)0x0a, (byte)0x5a, (byte)0x78,
            (byte)0xa0, (byte)0xb1, (byte)0x65, (byte)0x33,
            (byte)0xa6, (byte)0x21, (byte)0x3c, (byte)0xab
        };
        byte[] expectedTag2 = new byte[] {
            (byte)0x20, (byte)0x9f, (byte)0xcc, (byte)0x8d,
            (byte)0x36, (byte)0x75, (byte)0xed, (byte)0x93,
            (byte)0x8e, (byte)0x9c, (byte)0x71, (byte)0x66,
            (byte)0x70, (byte)0x9d, (byte)0xd9, (byte)0x46
        };

        /* Using byte[0] instead of null because OpenJDK Cipher.java
         * throws IllegalArgumentException when in is null. */
        byte[] nullInput = new byte[0];

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", jceProvider);

        /* Test case 1: No plaintext, no AAD */
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(
            expectedTag.length * 8, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] output = cipher.doFinal(nullInput);

        /* Output should just be the tag since no ciphertext */
        assertArrayEquals("Tag should match expected for null plaintext",
            expectedTag, output);

        /* Test case 2: No plaintext, with AAD */
        SecretKeySpec keySpec2 = new SecretKeySpec(key2, "AES");
        GCMParameterSpec gcmSpec2 = new GCMParameterSpec(
            expectedTag2.length * 8, iv2);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec2, gcmSpec2);
        cipher.updateAAD(aad2);
        byte[] output2 = cipher.doFinal(nullInput);

        /* Output should just be the tag since no ciphertext */
        assertArrayEquals("Tag should match expected for null plaintext " +
            "with AAD", expectedTag2, output2);

        /* Verify decryption works too */
        cipher.init(Cipher.DECRYPT_MODE, keySpec2, gcmSpec2);
        cipher.updateAAD(aad2);
        byte[] decrypted = cipher.doFinal(output2);

        /* Decrypted should be empty/null since original plaintext was null */
        assertTrue("Decrypted plaintext should be empty when original " +
            "plaintext was null", decrypted == null || decrypted.length == 0);
    }
}

