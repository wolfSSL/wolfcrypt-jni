/* wolfCryptCipherTest.java
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

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class WolfCryptCipherTest {

    /* all supported algos from wolfJCE provider, if enabled */
    private static String supportedJCEAlgos[] = {
        "AES/CBC/NoPadding",
        "AES/CBC/PKCS5Padding",
        "AES/GCM/NoPadding",
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
                Cipher c = Cipher.getInstance(
                    supportedJCEAlgos[i], jceProvider);
                enabledJCEAlgos.add(supportedJCEAlgos[i]);

            } catch (NoSuchAlgorithmException e) {
                /* algorithm not enabled */
            }
        }

        /* fill expected block size HashMap */
        expectedBlockSizes.put("AES/CBC/NoPadding", 16);
        expectedBlockSizes.put("AES/CBC/PKCS5Padding", 16);
        expectedBlockSizes.put("AES/GCM/NoPadding", 16);
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

        Cipher cipher;

        /* try to get all available options we expect to have */
        for (int i = 0; i < enabledJCEAlgos.size(); i++) {
            cipher = Cipher.getInstance(enabledJCEAlgos.get(i), jceProvider);
        }

        /* getting a garbage algorithm should throw
         * a NoSuchAlgorithmException */
        try {
            cipher = Cipher.getInstance("NotValid", jceProvider);

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
            assertEquals(e.getMessage(),
                         "Input length not multiple of 16 bytes");
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
                System.arraycopy(tmp, 0, output, finalOutput.length, tmp.length);
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
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
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
            assertEquals(e.getMessage(),
                         "Input length not multiple of 8 bytes");
        }
    }

    @Test
    public void testDESedeCbcNoPaddingThreaded() throws InterruptedException {

        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
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
        byte[] ciphertext = null;
        byte[] plaintext = null;

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
            ciphertext = ciph.doFinal();
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
            plaintext = ciph.doFinal();
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
            ciphertext = ciph.doFinal();
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
            plaintext = ciph.doFinal();
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

        public void setKey(byte[] key) {
            this.key = key;
        }

        public void setIV(byte[] iv) {
            this.iv = iv;
        }

        public void setInput(byte[] input) {
            this.input = input;
        }

        public void setOutput(byte[] output) {
            this.output = output;
        }

        public void setTag(byte[] tag) {
            this.tag = tag;
        }

        public void setAad(byte[] aad) {
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
}

