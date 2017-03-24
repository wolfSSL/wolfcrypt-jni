/* wolfCryptCipherTest.java
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.provider.jce;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.BeforeClass;

import java.util.ArrayList;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
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

import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptCipherTest {

    /* all supported algos from wolfJCE provider, if enabled */
    private static String supportedJCEAlgos[] = {
        "AES/CBC/NoPadding",
        "DESede/CBC/NoPadding",
        "RSA/ECB/PKCS1Padding"
    };

    /* populated with all enabled algos (some could have been compiled out) */
    private static ArrayList<String> enabledJCEAlgos =
        new ArrayList<String>();

    private static HashMap<String, Integer> expectedBlockSizes =
        new HashMap<String, Integer>();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException, NoSuchPaddingException {

        /* install wolfJCE provider at runtime */
        Security.addProvider(new WolfCryptProvider());

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* populate enabledJCEAlgos to test */
        for (int i = 0; i < supportedJCEAlgos.length; i++) {
            try {
                Cipher c = Cipher.getInstance(supportedJCEAlgos[i], "wolfJCE");
                enabledJCEAlgos.add(supportedJCEAlgos[i]);

            } catch (NoSuchAlgorithmException e) {
                /* algorithm not enabled */
            }
        }

        /* fill expected block size HashMap */
        expectedBlockSizes.put("AES/CBC/NoPadding", 16);
        expectedBlockSizes.put("DESede/CBC/NoPadding", 8);
        expectedBlockSizes.put("RSA/ECB/PKCS1Padding", 0);
    }

    @Test
    public void testGetCipherFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException {

        Cipher cipher;

        /* try to get all available options we expect to have */
        for (int i = 0; i < enabledJCEAlgos.size(); i++) {
            cipher = Cipher.getInstance(enabledJCEAlgos.get(i), "wolfJCE");
        }

        /* getting a garbage algorithm should throw
         * a NoSuchAlgorithmException */
        try {
            cipher = Cipher.getInstance("NotValid", "wolfJCE");

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
            cipher = Cipher.getInstance(enabledJCEAlgos.get(i), "wolfJCE");

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
                    (byte)0x77, (byte)0xa2, (byte)0x33, (byte)0xcb
                }
            )
        };

        byte output[];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {

            SecretKeySpec key = new SecretKeySpec(vectors[i].getKey(), "AES");
            IvParameterSpec spec = new IvParameterSpec(vectors[i].getIV());

            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            output = cipher.doFinal(vectors[i].input);

            assertArrayEquals(output, vectors[i].output);
        }
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
        final byte iv[]  = "1234567890abcdef   ".getBytes();

        byte cipher[] = new byte[input.length];
        byte plain[]  = new byte[input.length];

        if (!enabledJCEAlgos.contains("AES/CBC/NoPadding")) {
            /* bail out if AES is not enabled */
            return;
        }

        Cipher ciph = Cipher.getInstance("AES/CBC/NoPadding", "wolfJCE");
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
                    (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01,
                    (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01,
                    (byte)0x11, (byte)0x21, (byte)0x31, (byte)0x41,
                    (byte)0x51, (byte)0x61, (byte)0x71, (byte)0x81
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
                }
            )
        };

        byte output[];

        if (!enabledJCEAlgos.contains("DESede/CBC/NoPadding")) {
            /* bail out if 3DES is not enabled */
            return;
        }

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", "wolfJCE");

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
    public void testRSAECBPKCS1Padding() 
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector vectors[] = new CipherVector[] {
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
                null
            )
        };

        byte ciphertext[];
        byte plaintext[];

        if (!enabledJCEAlgos.contains("RSA/ECB/PKCS1Padding")) {
            /* bail out if RSA is not enabled */
            return;
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        Cipher ciph = Cipher.getInstance("RSA/ECB/PKCS1Padding", "wolfJCE");

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

    @Test
    public void testRSAECBPKCS1PaddingInterop() 
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, InvalidAlgorithmParameterException,
               BadPaddingException {

        CipherVector vectors[] = new CipherVector[] {
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
                null
            )
        };

        byte ciphertext[];
        byte plaintext[];

        if (!enabledJCEAlgos.contains("RSA/ECB/PKCS1Padding")) {
            /* bail out if RSA is not enabled */
            return;
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        Cipher ciphA = Cipher.getInstance("RSA/ECB/PKCS1Padding", "wolfJCE");
        Cipher ciphB = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
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

    private class CipherVector {

        private byte key[];
        private byte iv[];
        private byte input[];
        private byte output[];

        public CipherVector(byte[] key, byte[] iv, byte[] input,
                            byte[] output) {
            this.key = key;
            this.iv = iv;
            this.input = input;
            this.output = output;
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
    }
}

