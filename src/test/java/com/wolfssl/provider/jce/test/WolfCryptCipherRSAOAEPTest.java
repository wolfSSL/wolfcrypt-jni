/* WolfCryptCipherRSAOAEPTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Test RSA OAEP encryption with SHA-256 hash and default MGF1-SHA1
 * (per JCE OAEPWithSHA-256AndMGF1Padding behavior)
 */
public class WolfCryptCipherRSAOAEPTest {

    private static final String OAEP_ALGO =
        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String OAEP_SHA1_ALGO =
        "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String jceProvider = "wolfJCE";

    /* Interop provider for cross-provider testing */
    private static String interopProvider = null;

    /* One static SecureRandom to share */
    private static SecureRandom secureRandom = new SecureRandom();

    /* Pre-generated RSA key pair */
    private static KeyPair rsaPair = null;

    /* Flag indicating if OAEP SHA-256 is available */
    private static boolean oaepAvailable = false;

    /* Flag indicating if OAEP SHA-1 is available */
    private static boolean oaepSha1Available = false;

    /* Generated RSA-OAEP Test Vectors:
     * Algorithm: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
     * Key size: 2048 bits */

    /* PKCS#8 encoded private key (Base64) */
    private static final String TEST_PRIVATE_KEY =
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCY6FPxP6/oR8TZ" +
        "FOIP29OXY46NgfYeDkeb3GF2NUQqfcVh0Q+j3CcoKXUSZMKyRNJejTFhkg8Ozsme" +
        "SI+Ke/KKtP7jdEbcEz2WKkput1M2ezJtaj7dgyMHp069K9AJj4cxhEzUaQzxMHpT" +
        "CIkgKrYveFol5hieW9SpuaoAJ042ra5hBCen0kqZ9i6raLRvig6t5HVZyPU61M57" +
        "ElvJfW+ygPahtdqQ9+omLBKZ0JwiqcvK76eCssAcJfnKydEPcYXw1xtek1yjnoRu" +
        "tqUo4r8emhyeZTjSdX56vZXaxsxuBuKDbt4SN5RpZTnZ69NoN82IVMRwQs00CZ7P" +
        "eaGltsGTAgMBAAECggEBAJeJH6+l0zoa7i3I8WSQEfkldCAvXO9abYM8e+Y/Ucfe" +
        "jx+qpZpZ0wCNXXWWIBG1/NoxiW/N5VhifRN9i6vNvIfUagqWsKbn9o/8Z3mj+zay" +
        "Dz66HYU/shaiq3j0k571/CCJoe6cEXRx+7iQa/1R9u3Ck2ydxWYjUfXGh4DRc0Th" +
        "fXbB03ZWni5EX8EQnpONZtxX8MyMASYiEzXfXspmzIn1mMwNutAJOQ2n7FXGH7hi" +
        "wlW8M5PkiJqz6Mn34bKF+5P9arsW2ao8yf+pzU+zA2lHp+mc/6+LoHbrv3URGxGn" +
        "E64bQ5nPy6+3aFEDnV3f92LMHToQ18QZ/o6fFCcYn9ECgYEA4q6NyIPYmJBi3TT5" +
        "CTa9bSlLpIlzYhlk61EoHxlwtQIAAbXHsARz/9J4QyoPHbMOzNlQpd7vvEOytKhV" +
        "xzz/n7Fm0+zwUCdNSXGOKoh5ICdoi/mJYaiYJV2gM5io46eA1usLAzEDZjdacq0y" +
        "noHQg5BI3p06XpucZw+CXR6HpJsCgYEArK8aYPwKCwCvYMgfmf0cyunE//wB6ZmS" +
        "IFQ3p4pJjTZ3/5/SH2EjavjNZyDiLuW3VzeIx1wIboTP+jfLTT+lnbswCWroCOoK" +
        "XkSZfcknt721sGhsWjnXrBbTwQynwrqGYwu6YJCqHBsM9yhTMJkMlbn+HC+AY9LI" +
        "Q9weLvydmmkCgYAFJZFyjAvO6vhTrXA6FVQXtmhRRA2qnIj+Dsmqaxl0AqedYlM2" +
        "W+OGW3D/lWTid75OSGDcY0NuMttL3saTz36+UXjUNvz91OacVEe2D4Mwh7SH+RJ1" +
        "dS5/KrEIet7azGLQfmWxnNtG5trW37fWgXwKgKwm4csBeucCMAf1tUu/IQKBgHko" +
        "iluNuwYpPuOqxfFnE/KSvnPUvwrFgy9Hp5zXe++mTd9+pRD7OLxvQL6g5dF9v3tk" +
        "LYWi3w+cA8hNqUjT5UGb+oJBDfhjLU8i1obYwhM6+eWB/rP3bYkCoyQJ2xLXiD6q" +
        "FeR228PIfvpSwruQRrIuw0nHUk+3rmdeY5cYCwQxAoGAJO9qRitby7AdJOz8u9r7" +
        "t4AXRB5qZ07AX1lKD7EUZVXXkCBGuwZ424fQZshG1EMlgsc+nGJIPF0JG55RVA+N" +
        "CNvQazmSLrVOu9t958wkHeas1mhhAsPs4CcBiOLTHtZR3ta95Mv3DLGJQIxkNf7y" +
        "Cs4unsW/HHCqu0aaccHDdUs=";

    /* Test vector 1: message = "Test" */
    private static final String TEST_MSG_1 = "54657374";
    private static final String TEST_CT_1 =
        "67390e3954d5f49a93a3765fcab102a7285bbdeebe6eab280a93e2b63343acec" +
        "1caa3cc6d4042af0f6e5cba5e5e8fab271fb729e1c0471f8fd29ec95f0494da3" +
        "5be6c3e24a4a94ad4d0b23e59161e6fbc3f5b4033005038f8fd8606b8d925e9a" +
        "f2f3bd33ee3382c95f62a4c59b43a4045b9a86e80277e5fb28c852341e904e9a" +
        "48b8d6c425a7871b3c64a943b1e90f29a9cf9094551084c526101932e0809228" +
        "d1339c9563174f19fe5f3649ccbefb23aee2a2acb3aed47ecc178eb20b1057c5" +
        "d973e9cf9609248bfa8f967c9df1a6519b81f9fe55a30ee4c5bd7d3a4297a82b" +
        "d3c20efcd25c7205782fb4f802e41122b6c69fa35b1c91a138162effe7b226fa";

    /* Test vector 2: message = "Hello" */
    private static final String TEST_MSG_2 = "48656c6c6f";
    private static final String TEST_CT_2 =
        "5706145b1be8af0cc117a1edce2460a0fbd1c1e67dc89e905042095a5f9d27c7" +
        "dc61646c1ec65e8a145f07b8a84faaa1f8d9345354688eb777bbd6c73ac2feed" +
        "b3df3bce76f1cce9752d7b8d85481fe8e05fa8ee8617197d35a717b2c3272659" +
        "aa01df4ea6eb6bad9a635a4fe55b2731bdf8a059728a313d7fd5cd03e60497d0" +
        "6f3a2dba22d06876d22988baa4f4fe5927426565ae11b85c7908c542840a80db" +
        "d372b676314bcdd24fd05c7ebec70132cb842980091c6b0d4865583174c3c634" +
        "431e96f6bb6a14b5f99ab60f18ecc9170db6673c8896ad56f748f5b0e27ae1fa" +
        "b1013e9a7574f12573a9ea69ccb52a6ebd19e492ad2893b22fbcf9a464cd2a48";

    /* Test vector 3: message = "wolfSSL JNI" */
    private static final String TEST_MSG_3 = "776f6c6653534c204a4e49";
    private static final String TEST_CT_3 =
        "33d9e373bf2a5bbf4bd51626ac1a5432ffa2bb8b5d7bcc7f8993ea1ab3025717" +
        "1d8eae8595f17080f01e05a1179e70fb84464586e136cd9c30e3905d2bc17da1" +
        "c851c3d431ae4783ff75813e76c085ed9cd9c92857fe50051b0d7dd11703f770" +
        "1db02429515b9faa13f1918622835c691c9b7a56649725e6744c536f94fd0bc7" +
        "e3b6ca9d4ac47fb8c8ffedfb3bed8872c4fbcf4df5d86358b9e0fdcfceac95f9" +
        "b005d19c8f415da9b8c9b99ff1370613a71e5ed63e5ad055b504f99ade765b19" +
        "b2bea4f81f1c36c36403d98ff3825aa4f73a8b29e57557cf99b40ccc2670ed80" +
        "c95a499ef5382f1d8bc6139209637236a8d1239f86f8d48f8417ceecdaaa85bd";

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptCipherRSAOAEP Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider(jceProvider);
        assertNotNull(p);

        /* Check if RSA OAEP SHA-256 is available */
        try {
            Cipher.getInstance(OAEP_ALGO, jceProvider);
            oaepAvailable = true;
        } catch (NoSuchAlgorithmException e) {
            /* OAEP not compiled in */
            oaepAvailable = false;
        } catch (NoSuchPaddingException e) {
            oaepAvailable = false;
        }

        /* Check if RSA OAEP SHA-1 is available */
        try {
            Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
            oaepSha1Available = true;
        } catch (NoSuchAlgorithmException e) {
            /* OAEP SHA-1 not compiled in */
            oaepSha1Available = false;
        } catch (NoSuchPaddingException e) {
            oaepSha1Available = false;
        }

        /* Try to set up interop provider. Only use SunJCE for OAEP interop
         * testing since Bouncy Castle interprets OAEPWithSHA-256AndMGF1Padding
         * differently (uses SHA-256 for both OAEP and MGF1 hashes) while
         * SunJCE and wolfJCE use SHA-256 for OAEP and SHA-1 for MGF1 per
         * JCE specification defaults. */
        p = Security.getProvider("SunJCE");
        if (p != null) {
            interopProvider = "SunJCE";
        }

        /* Generate RSA key pair once for tests */
        if (oaepAvailable) {
            try {
                KeyPairGenerator keyGen =
                    KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048, secureRandom);
                rsaPair = keyGen.generateKeyPair();
            } catch (Exception e) {
                System.err.println("Failed to generate RSA key pair: " +
                    e.getMessage());
            }
        }
    }

    @Test
    public void testOAEPBasicEncryptDecrypt()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Hello wolfSSL OAEP!".getBytes();

        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > 0);
        /* Ciphertext should be RSA modulus size (256 bytes for 2048-bit) */
        assertEquals(256, ciphertext.length);

        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testOAEPNonDeterministic()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test OAEP randomness".getBytes();

        Cipher cipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext1 = cipher.doFinal(plaintext);

        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext2 = cipher.doFinal(plaintext);

        /* OAEP is randomized, same plaintext should produce different
         * ciphertext each time */
        assertFalse("OAEP ciphertext should be non-deterministic",
            Arrays.equals(ciphertext1, ciphertext2));
    }

    @Test
    public void testOAEPMaxPlaintextSize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        /* Max plaintext for 2048-bit RSA with SHA-256 OAEP:
         * 256 - 2*32 - 2 = 190 bytes */
        byte[] maxPlaintext = new byte[190];
        secureRandom.nextBytes(maxPlaintext);

        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(maxPlaintext);

        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(maxPlaintext, decrypted);
    }

    @Test
    public void testOAEPTooBigData()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        /* Too big for 2048-bit RSA with SHA-256 OAEP (max is 190 bytes) */
        byte[] tooBigPlaintext = new byte[191];
        secureRandom.nextBytes(tooBigPlaintext);

        Cipher cipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());

        try {
            cipher.doFinal(tooBigPlaintext);
            fail("Should throw exception for data too big for OAEP");
        } catch (IllegalBlockSizeException e) {
            /* Expected */
        } catch (BadPaddingException e) {
            /* Also acceptable from native layer */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped in RuntimeException is also valid */
        }
    }

    @Test
    public void testOAEPWithUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] part1 = "Hello ".getBytes();
        byte[] part2 = "World!".getBytes();
        byte[] fullPlaintext = "Hello World!".getBytes();

        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        encCipher.update(part1);
        byte[] ciphertext = encCipher.doFinal(part2);

        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(fullPlaintext, decrypted);
    }

    @Test
    public void testOAEPFinalResetsState()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext1 = "First message".getBytes();
        byte[] plaintext2 = "Second message".getBytes();

        Cipher cipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());

        /* First encryption */
        byte[] ciphertext1 = cipher.doFinal(plaintext1);

        /* After doFinal, cipher should be reset and usable without re-init */
        byte[] ciphertext2 = cipher.doFinal(plaintext2);

        /* Both should decrypt correctly */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());

        byte[] decrypted1 = decCipher.doFinal(ciphertext1);
        byte[] decrypted2 = decCipher.doFinal(ciphertext2);

        assertArrayEquals(plaintext1, decrypted1);
        assertArrayEquals(plaintext2, decrypted2);
    }

    @Test
    public void testOAEPInteropWithSunJCE()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);
        Assume.assumeNotNull(interopProvider);

        byte[] plaintext = "Interop test message".getBytes();

        /* Encrypt with wolfJCE */
        Cipher wolfEncrypt = Cipher.getInstance(OAEP_ALGO, jceProvider);
        wolfEncrypt.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] wolfCiphertext = wolfEncrypt.doFinal(plaintext);

        /* Decrypt with interop provider */
        Cipher interopDecrypt = Cipher.getInstance(OAEP_ALGO, interopProvider);
        interopDecrypt.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] interopDecrypted = interopDecrypt.doFinal(wolfCiphertext);

        assertArrayEquals(plaintext, interopDecrypted);

        /* Encrypt with interop provider */
        Cipher interopEncrypt = Cipher.getInstance(OAEP_ALGO, interopProvider);
        interopEncrypt.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] interopCiphertext = interopEncrypt.doFinal(plaintext);

        /* Decrypt with wolfJCE */
        Cipher wolfDecrypt = Cipher.getInstance(OAEP_ALGO, jceProvider);
        wolfDecrypt.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] wolfDecrypted = wolfDecrypt.doFinal(interopCiphertext);

        assertArrayEquals(plaintext, wolfDecrypted);
    }

    /**
     * Test empty plaintext handling. Note: While RFC 8017 allows empty
     * plaintext for OAEP, native wolfSSL rejects it with BAD_FUNC_ARG.
     * This test verifies the expected behavior.
     */
    @Test(expected = WolfCryptException.class)
    public void testOAEPEmptyPlaintext()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] emptyPlaintext = new byte[0];

        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());

        /* wolfSSL rejects empty plaintext with BAD_FUNC_ARG */
        encCipher.doFinal(emptyPlaintext);
    }

    @Test
    public void testOAEPPrivateKeyEncryptFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test data".getBytes();

        Cipher cipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPrivate());

        try {
            cipher.doFinal(plaintext);
            fail("OAEP encryption with private key should fail");
        } catch (IllegalStateException e) {
            /* Expected - OAEP requires public key for encryption */
        }
    }

    @Test
    public void testOAEPPublicKeyDecryptFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        /* First encrypt normally */
        byte[] plaintext = "Test data".getBytes();
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Try to decrypt with public key */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPublic());

        try {
            decCipher.doFinal(ciphertext);
            fail("OAEP decryption with public key should fail");
        } catch (IllegalStateException e) {
            /* Expected - OAEP requires private key for decryption */
        }
    }

    @Test
    public void testOAEPWrongKeyDecryptFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        /* Generate a different key pair */
        KeyPair otherPair = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, secureRandom);
            otherPair = keyGen.generateKeyPair();
        } catch (Exception e) {
            Assume.assumeNoException("Failed to generate second key pair", e);
        }
        Assume.assumeNotNull(otherPair);

        byte[] plaintext = "Test data".getBytes();

        /* Encrypt with first key */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Try to decrypt with wrong key */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, otherPair.getPrivate());

        try {
            decCipher.doFinal(ciphertext);
            fail("Decryption with wrong key should fail");
        } catch (BadPaddingException e) {
            /* Expected */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped is also valid */
        }
    }

    @Test
    public void testOAEPMultipleKeySizes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);

        int[] keySizes = {2048, 3072, 4096};
        byte[] plaintext = "Testing various key sizes".getBytes();

        for (int keySize : keySizes) {
            KeyPair keyPair = null;
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(keySize, secureRandom);
                keyPair = keyGen.generateKeyPair();
            } catch (Exception e) {
                /* Skip this key size if generation fails */
                continue;
            }

            Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
            encCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] ciphertext = encCipher.doFinal(plaintext);

            /* Ciphertext should be key size / 8 bytes */
            assertEquals("Ciphertext size for " + keySize + "-bit key",
                keySize / 8, ciphertext.length);

            Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
            decCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Round trip for " + keySize + "-bit key",
                plaintext, decrypted);
        }
    }

    @Test
    public void testOAEPAliasName()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        /* Test with alternate alias (without hyphen in SHA256) */
        String aliasAlgo = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";

        byte[] plaintext = "Alias test".getBytes();

        Cipher encCipher = Cipher.getInstance(aliasAlgo, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test decryption using test vectors.
     */
    @Test
    public void testOAEPKnownAnswerVectors()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException,
               InvalidKeySpecException {

        Assume.assumeTrue(oaepAvailable);

        /* Decode private key from Base64 */
        byte[] keyBytes = Base64.getDecoder().decode(TEST_PRIVATE_KEY);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        /* Test vector 1: message = "Test" */
        byte[] ct1 = WolfCrypt.hexStringToByteArray(TEST_CT_1);
        byte[] pt1 = cipher.doFinal(ct1);
        byte[] expected1 = WolfCrypt.hexStringToByteArray(TEST_MSG_1);
        assertArrayEquals("KAT vector 'Test' failed", expected1, pt1);

        /* Test vector 2: message = "Hello" */
        byte[] ct2 = WolfCrypt.hexStringToByteArray(TEST_CT_2);
        byte[] pt2 = cipher.doFinal(ct2);
        byte[] expected2 = WolfCrypt.hexStringToByteArray(TEST_MSG_2);
        assertArrayEquals("KAT vector 'Hello' failed", expected2, pt2);

        /* Test vector 3: message = "wolfSSL JNI" */
        byte[] ct3 = WolfCrypt.hexStringToByteArray(TEST_CT_3);
        byte[] pt3 = cipher.doFinal(ct3);
        byte[] expected3 = WolfCrypt.hexStringToByteArray(TEST_MSG_3);
        assertArrayEquals("KAT vector 'wolfSSL JNI' failed", expected3, pt3);
    }

    @Test
    public void testOAEPInvalidCiphertext()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test data".getBytes();

        /* Get ciphertext */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] validCiphertext = encCipher.doFinal(plaintext);

        /* Corrupt ciphertext by modifying a byte */
        byte[] corruptedCiphertext = validCiphertext.clone();
        corruptedCiphertext[0] ^= (byte)0xFF;

        /* Decrypt corrupted ciphertext, should fail */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());

        try {
            decCipher.doFinal(corruptedCiphertext);
            fail("Decryption of corrupted ciphertext should fail");
        } catch (BadPaddingException e) {
            /* Expected - OAEP padding check failed */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped in RuntimeException is also valid */
        }
    }

    @Test
    public void testOAEPTruncatedCiphertext()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test data".getBytes();

        /* Get ciphertext */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] validCiphertext = encCipher.doFinal(plaintext);

        /* Create truncated ciphertext (wrong size) */
        byte[] truncatedCiphertext =
            Arrays.copyOf(validCiphertext, validCiphertext.length - 1);

        /* Decrypt truncated ciphertext, should fail with
         * IllegalBlockSizeException due to wrong size */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());

        try {
            decCipher.doFinal(truncatedCiphertext);
            fail("Decryption of truncated ciphertext should fail");
        } catch (IllegalBlockSizeException e) {
            /* Expected - ciphertext size does not match RSA modulus */
        } catch (BadPaddingException e) {
            /* Also acceptable from native layer */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped in RuntimeException is also valid */
        }
    }

    /**
     * Test OAEP with explicit OAEPParameterSpec using default JCE parameters
     * (SHA-256 for OAEP hash, SHA-1 for MGF1).
     */
    @Test
    public void testOAEPWithExplicitDefaultParams()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test with explicit default OAEP params".getBytes();

        /* Create OAEPParameterSpec with default JCE parameters:
         * SHA-256 for OAEP hash, SHA-1 for MGF1 */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        );

        /* Encrypt with explicit params */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt with explicit params */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test OAEP with SHA-256 for both OAEP hash and MGF1.
     */
    @Test
    public void testOAEPWithSHA256ForBothHashes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test with SHA-256 for both hashes".getBytes();

        /* Create OAEPParameterSpec with SHA-256 for both OAEP and MGF1 */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );

        /* Encrypt */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test OAEP with SHA-384 for both OAEP hash and MGF1.
     */
    @Test
    public void testOAEPWithSHA384()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test with SHA-384".getBytes();

        /* Create OAEPParameterSpec with SHA-384 for both OAEP and MGF1 */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-384",
            "MGF1",
            MGF1ParameterSpec.SHA384,
            PSource.PSpecified.DEFAULT
        );

        /* Encrypt */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test OAEP with SHA-512 for both OAEP hash and MGF1.
     */
    @Test
    public void testOAEPWithSHA512()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test with SHA-512".getBytes();

        /* Create OAEPParameterSpec with SHA-512 for both OAEP and MGF1 */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-512",
            "MGF1",
            MGF1ParameterSpec.SHA512,
            PSource.PSpecified.DEFAULT
        );

        /* Encrypt */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test OAEP with SHA-1 for OAEP hash and SHA-256 for MGF1.
     * This tests mixed hash configuration.
     */
    @Test
    public void testOAEPWithMixedHashes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test with mixed hashes".getBytes();

        /* Create OAEPParameterSpec with SHA-1 for OAEP, SHA-256 for MGF1 */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );

        /* Encrypt */
        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test that encryption with one OAEPParameterSpec and decryption with
     * different parameters fails.
     */
    @Test
    public void testOAEPParamMismatchFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test param mismatch".getBytes();

        /* Encrypt with SHA-256/SHA-256 */
        OAEPParameterSpec encSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );

        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), encSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Try to decrypt with SHA-256/SHA-1 (should fail) */
        OAEPParameterSpec decSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        );

        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), decSpec);

        try {
            decCipher.doFinal(ciphertext);
            fail("Decryption with mismatched OAEP parameters should fail");
        } catch (BadPaddingException e) {
            /* Expected - OAEP padding check failed */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped in RuntimeException is also valid */
        }
    }

    /**
     * Test that interop between explicit params and default cipher works
     * when parameters match.
     */
    @Test
    public void testOAEPExplicitParamsInteropWithDefault()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test explicit params interop".getBytes();

        /* Encrypt with explicit params matching defaults (SHA-256/SHA-1) */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        );

        Cipher encCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt without explicit params (uses defaults) */
        Cipher decCipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);

        /* Also test reverse: encrypt with defaults, decrypt with explicit */
        Cipher encCipher2 = Cipher.getInstance(OAEP_ALGO, jceProvider);
        encCipher2.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext2 = encCipher2.doFinal(plaintext);

        Cipher decCipher2 = Cipher.getInstance(OAEP_ALGO, jceProvider);
        decCipher2.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted2 = decCipher2.doFinal(ciphertext2);

        assertArrayEquals(plaintext, decrypted2);
    }

    /**
     * Test that using OAEPParameterSpec with unsupported hash algorithm fails.
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testOAEPUnsupportedHashAlgorithm()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        /* Create OAEPParameterSpec with unsupported hash algorithm */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "MD5",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        );

        Cipher cipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
    }

    /**
     * Test that using OAEPParameterSpec with non-empty label fails.
     * wolfSSL does not support custom OAEP labels.
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testOAEPCustomLabelFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        Assume.assumeTrue(oaepAvailable);
        Assume.assumeNotNull(rsaPair);

        /* Create OAEPParameterSpec with custom label */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            new PSource.PSpecified("custom label".getBytes())
        );

        Cipher cipher = Cipher.getInstance(OAEP_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
    }

    @Test
    public void testOAEPSHA1BasicEncryptDecrypt()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Hello wolfSSL OAEP SHA-1!".getBytes();

        Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > 0);
        /* Ciphertext should be RSA modulus size (256 bytes for 2048-bit) */
        assertEquals(256, ciphertext.length);

        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testOAEPSHA1NonDeterministic()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test OAEP SHA-1 randomness".getBytes();

        Cipher cipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext1 = cipher.doFinal(plaintext);

        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext2 = cipher.doFinal(plaintext);

        /* OAEP is randomized, same plaintext should produce different
         * ciphertext each time */
        assertFalse("OAEP SHA-1 ciphertext should be non-deterministic",
            Arrays.equals(ciphertext1, ciphertext2));
    }

    @Test
    public void testOAEPSHA1MaxPlaintextSize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        /* Max plaintext for 2048-bit RSA with SHA-1 OAEP:
         * 256 - 2*20 - 2 = 214 bytes */
        byte[] maxPlaintext = new byte[214];
        secureRandom.nextBytes(maxPlaintext);

        Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(maxPlaintext);

        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(maxPlaintext, decrypted);
    }

    @Test
    public void testOAEPSHA1TooBigData()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        /* Too big for 2048-bit RSA with SHA-1 OAEP (max is 214 bytes) */
        byte[] tooBigPlaintext = new byte[215];
        secureRandom.nextBytes(tooBigPlaintext);

        Cipher cipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());

        try {
            cipher.doFinal(tooBigPlaintext);
            fail("Should throw exception for data too big for OAEP SHA-1");
        } catch (IllegalBlockSizeException e) {
            /* Expected */
        } catch (BadPaddingException e) {
            /* Also acceptable from native layer */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped in RuntimeException is also valid */
        }
    }

    @Test
    public void testOAEPSHA1FinalResetsState()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext1 = "First message SHA-1".getBytes();
        byte[] plaintext2 = "Second message SHA-1".getBytes();

        Cipher cipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());

        /* First encryption */
        byte[] ciphertext1 = cipher.doFinal(plaintext1);

        /* After doFinal, cipher should be reset and usable without re-init */
        byte[] ciphertext2 = cipher.doFinal(plaintext2);

        /* Both should decrypt correctly */
        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());

        byte[] decrypted1 = decCipher.doFinal(ciphertext1);
        byte[] decrypted2 = decCipher.doFinal(ciphertext2);

        assertArrayEquals(plaintext1, decrypted1);
        assertArrayEquals(plaintext2, decrypted2);
    }

    @Test
    public void testOAEPSHA1InteropWithSunJCE()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);
        Assume.assumeNotNull(interopProvider);

        byte[] plaintext = "Interop test message SHA-1".getBytes();

        /* Encrypt with wolfJCE */
        Cipher wolfEncrypt = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        wolfEncrypt.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] wolfCiphertext = wolfEncrypt.doFinal(plaintext);

        /* Decrypt with interop provider */
        Cipher interopDecrypt =
            Cipher.getInstance(OAEP_SHA1_ALGO, interopProvider);
        interopDecrypt.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] interopDecrypted = interopDecrypt.doFinal(wolfCiphertext);

        assertArrayEquals(plaintext, interopDecrypted);

        /* Encrypt with interop provider */
        Cipher interopEncrypt =
            Cipher.getInstance(OAEP_SHA1_ALGO, interopProvider);
        interopEncrypt.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] interopCiphertext = interopEncrypt.doFinal(plaintext);

        /* Decrypt with wolfJCE */
        Cipher wolfDecrypt = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        wolfDecrypt.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] wolfDecrypted = wolfDecrypt.doFinal(interopCiphertext);

        assertArrayEquals(plaintext, wolfDecrypted);
    }

    @Test
    public void testOAEPSHA1PrivateKeyEncryptFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test data".getBytes();

        Cipher cipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPrivate());

        try {
            cipher.doFinal(plaintext);
            fail("OAEP SHA-1 encryption with private key should fail");
        } catch (IllegalStateException e) {
            /* Expected - OAEP requires public key for encryption */
        }
    }

    @Test
    public void testOAEPSHA1PublicKeyDecryptFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        /* First encrypt normally */
        byte[] plaintext = "Test data".getBytes();
        Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Try to decrypt with public key */
        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPublic());

        try {
            decCipher.doFinal(ciphertext);
            fail("OAEP SHA-1 decryption with public key should fail");
        } catch (IllegalStateException e) {
            /* Expected - OAEP requires private key for decryption */
        }
    }

    @Test
    public void testOAEPSHA1WrongKeyDecryptFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        /* Generate a different key pair */
        KeyPair otherPair = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, secureRandom);
            otherPair = keyGen.generateKeyPair();
        } catch (Exception e) {
            Assume.assumeNoException("Failed to generate second key pair", e);
        }
        Assume.assumeNotNull(otherPair);

        byte[] plaintext = "Test data".getBytes();

        /* Encrypt with first key */
        Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Try to decrypt with wrong key */
        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, otherPair.getPrivate());

        try {
            decCipher.doFinal(ciphertext);
            fail("OAEP SHA-1 decryption with wrong key should fail");
        } catch (BadPaddingException e) {
            /* Expected */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped is also valid */
        }
    }

    @Test
    public void testOAEPSHA1MultipleKeySizes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);

        int[] keySizes = {2048, 3072, 4096};
        byte[] plaintext = "Testing various key sizes with SHA-1".getBytes();

        for (int keySize : keySizes) {
            KeyPair keyPair = null;
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(keySize, secureRandom);
                keyPair = keyGen.generateKeyPair();
            } catch (Exception e) {
                /* Skip this key size if generation fails */
                continue;
            }

            Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
            encCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] ciphertext = encCipher.doFinal(plaintext);

            /* Ciphertext should be key size / 8 bytes */
            assertEquals("Ciphertext size for " + keySize + "-bit key",
                keySize / 8, ciphertext.length);

            Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
            decCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Round trip for " + keySize + "-bit key",
                plaintext, decrypted);
        }
    }

    @Test
    public void testOAEPSHA1AliasName()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        /* Test with alternate alias (without hyphen in SHA1) */
        String aliasAlgo = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";

        byte[] plaintext = "Alias test SHA-1".getBytes();

        Cipher encCipher = Cipher.getInstance(aliasAlgo, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test OAEP SHA-1 with explicit OAEPParameterSpec using default JCE
     * parameters (SHA-1 for OAEP hash, SHA-1 for MGF1).
     */
    @Test
    public void testOAEPSHA1WithExplicitDefaultParams()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test with explicit SHA-1 OAEP params".getBytes();

        /* Create OAEPParameterSpec with default JCE parameters for SHA-1:
         * SHA-1 for OAEP hash, SHA-1 for MGF1 */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        );

        /* Encrypt with explicit params */
        Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt with explicit params */
        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Test that interop between explicit params and default cipher works
     * when parameters match for SHA-1 OAEP.
     */
    @Test
    public void testOAEPSHA1ExplicitParamsInteropWithDefault()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test explicit params interop SHA-1".getBytes();

        /* Encrypt with explicit params matching defaults (SHA-1/SHA-1) */
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        );

        Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), oaepSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Decrypt without explicit params (uses defaults) */
        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted);

        /* Also test reverse: encrypt with defaults, decrypt with explicit */
        Cipher encCipher2 = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher2.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] ciphertext2 = encCipher2.doFinal(plaintext);

        Cipher decCipher2 = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher2.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), oaepSpec);
        byte[] decrypted2 = decCipher2.doFinal(ciphertext2);

        assertArrayEquals(plaintext, decrypted2);
    }

    /**
     * Test that encryption with SHA-1 OAEP and decryption with
     * mismatched MGF1 parameters fails.
     */
    @Test
    public void testOAEPSHA1ParamMismatchFails()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               IllegalBlockSizeException, BadPaddingException {

        Assume.assumeTrue(oaepSha1Available);
        Assume.assumeNotNull(rsaPair);

        byte[] plaintext = "Test param mismatch SHA-1".getBytes();

        /* Encrypt with SHA-1/SHA-1 */
        OAEPParameterSpec encSpec = new OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        );

        Cipher encCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        encCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic(), encSpec);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        /* Try to decrypt with SHA-1/SHA-256 (should fail) */
        OAEPParameterSpec decSpec = new OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );

        Cipher decCipher = Cipher.getInstance(OAEP_SHA1_ALGO, jceProvider);
        decCipher.init(Cipher.DECRYPT_MODE, rsaPair.getPrivate(), decSpec);

        try {
            decCipher.doFinal(ciphertext);
            fail("Decryption with mismatched OAEP parameters should fail");
        } catch (BadPaddingException e) {
            /* Expected - OAEP padding check failed */
        } catch (RuntimeException e) {
            /* WolfCryptException wrapped in RuntimeException is also valid */
        }
    }
}

