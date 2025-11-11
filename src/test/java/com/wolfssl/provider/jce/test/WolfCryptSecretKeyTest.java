/* WolfCryptSecretKeyTest.java
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

import java.util.Arrays;
import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Des3;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptSecretKey;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class WolfCryptSecretKeyTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptSecretKey Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);
    }

    @Test
    public void testAES128KeyCreation() throws InvalidKeyException {
        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes, (byte)0x42);

        WolfCryptSecretKey key = new WolfCryptSecretKey("AES", keyBytes);

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertArrayEquals(keyBytes, key.getEncoded());
        assertFalse(key.isDestroyed());
    }

    @Test
    public void testAES192KeyCreation() throws InvalidKeyException {
        byte[] keyBytes = new byte[Aes.KEY_SIZE_192];
        Arrays.fill(keyBytes, (byte)0x42);

        WolfCryptSecretKey key = new WolfCryptSecretKey("AES", keyBytes);

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertArrayEquals(keyBytes, key.getEncoded());
    }

    @Test
    public void testAES256KeyCreation() throws InvalidKeyException {
        byte[] keyBytes = new byte[Aes.KEY_SIZE_256];
        Arrays.fill(keyBytes, (byte)0x42);

        WolfCryptSecretKey key = new WolfCryptSecretKey("AES", keyBytes);

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertArrayEquals(keyBytes, key.getEncoded());
    }

    @Test
    public void testAESInvalidKeySize() {
        byte[] invalidSizes[] = {
            new byte[8],   /* too small */
            new byte[Aes.KEY_SIZE_128 - 1],  /* one less than 128-bit */
            new byte[Aes.KEY_SIZE_128 + 1],  /* one more than 128-bit */
            new byte[Aes.KEY_SIZE_192 - 1],  /* one less than 192-bit */
            new byte[Aes.KEY_SIZE_192 + 1],  /* one more than 192-bit */
            new byte[Aes.KEY_SIZE_256 - 1],  /* one less than 256-bit */
            new byte[Aes.KEY_SIZE_256 + 1],  /* one more than 256-bit */
            new byte[64]   /* too large */
        };

        for (byte[] keyBytes : invalidSizes) {
            try {
                new WolfCryptSecretKey("AES", keyBytes);
                fail("WolfCryptSecretKey should have thrown " +
                     "InvalidKeyException for invalid key size: " +
                     keyBytes.length);
            } catch (InvalidKeyException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testDESedeKeyCreation() throws InvalidKeyException {
        byte[] keyBytes = new byte[Des3.KEY_SIZE];
        Arrays.fill(keyBytes, (byte)0x42);

        WolfCryptSecretKey key = new WolfCryptSecretKey("DESede", keyBytes);

        assertNotNull(key);
        assertEquals("DESede", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertArrayEquals(keyBytes, key.getEncoded());
    }

    @Test
    public void testDESedeInvalidKeySize() {
        byte[] invalidSizes[] = {
            new byte[8],   /* too small */
            new byte[16],  /* wrong size */
            new byte[Des3.KEY_SIZE - 1],  /* one less than 192-bit */
            new byte[Des3.KEY_SIZE + 1],  /* one more than 192-bit */
            new byte[32]   /* wrong size */
        };

        for (byte[] keyBytes : invalidSizes) {
            try {
                new WolfCryptSecretKey("DESede", keyBytes);
                fail("WolfCryptSecretKey should have thrown " +
                     "InvalidKeyException for invalid key size: " +
                     keyBytes.length);
            } catch (InvalidKeyException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testNullAlgorithm() {
        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];

        try {
            new WolfCryptSecretKey(null, keyBytes);
            fail("WolfCryptSecretKey should have thrown " +
                 "InvalidKeyException for null algorithm");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void testEmptyAlgorithm() {
        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];

        try {
            new WolfCryptSecretKey("", keyBytes);
            fail("WolfCryptSecretKey should have thrown " +
                 "InvalidKeyException for empty algorithm");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void testNullKeyBytes() {
        try {
            new WolfCryptSecretKey("AES", null);
            fail("WolfCryptSecretKey should have thrown " +
                 "InvalidKeyException for null key bytes");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void testZeroLengthKeyBytes() {
        try {
            new WolfCryptSecretKey("AES", new byte[0]);
            fail("WolfCryptSecretKey should have thrown " +
                 "InvalidKeyException for zero length key bytes");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void testUnsupportedAlgorithm() {
        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];

        try {
            new WolfCryptSecretKey("InvalidAlgo", keyBytes);
            fail("WolfCryptSecretKey should have thrown " +
                 "InvalidKeyException for unsupported algorithm");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void testEquals() throws InvalidKeyException {
        byte[] keyBytes1 = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes1, (byte)0x42);
        byte[] keyBytes2 = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes2, (byte)0x42);
        byte[] keyBytes3 = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes3, (byte)0x43);

        WolfCryptSecretKey key1 = new WolfCryptSecretKey("AES", keyBytes1);
        WolfCryptSecretKey key2 = new WolfCryptSecretKey("AES", keyBytes2);
        WolfCryptSecretKey key3 = new WolfCryptSecretKey("AES", keyBytes3);

        /* Same key */
        assertTrue(key1.equals(key1));

        /* Equal keys */
        assertTrue(key1.equals(key2));
        assertTrue(key2.equals(key1));

        /* Different keys */
        assertFalse(key1.equals(key3));
        assertFalse(key3.equals(key1));

        /* Null */
        assertFalse(key1.equals(null));

        /* Different type */
        assertFalse(key1.equals("not a key"));
    }

    @Test
    public void testHashCode() throws InvalidKeyException {
        byte[] keyBytes1 = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes1, (byte)0x42);
        byte[] keyBytes2 = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes2, (byte)0x42);

        WolfCryptSecretKey key1 = new WolfCryptSecretKey("AES", keyBytes1);
        WolfCryptSecretKey key2 = new WolfCryptSecretKey("AES", keyBytes2);

        /* Equal keys should have equal hashcodes */
        assertEquals(key1.hashCode(), key2.hashCode());
    }

    @Test
    public void testDestroy() throws InvalidKeyException {
        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes, (byte)0x42);

        WolfCryptSecretKey key = new WolfCryptSecretKey("AES", keyBytes);

        assertFalse(key.isDestroyed());

        key.destroy();

        assertTrue(key.isDestroyed());

        /* All operations should throw IllegalStateException after destroy */
        try {
            key.getAlgorithm();
            fail("getAlgorithm() should throw IllegalStateException " +
                 "after destroy");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            key.getFormat();
            fail("getFormat() should throw IllegalStateException " +
                 "after destroy");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            key.getEncoded();
            fail("getEncoded() should throw IllegalStateException " +
                 "after destroy");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            key.hashCode();
            fail("hashCode() should throw IllegalStateException " +
                 "after destroy");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            key.equals(key);
            fail("equals() should throw IllegalStateException after destroy");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testKeyIsolation() throws InvalidKeyException {
        byte[] original = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(original, (byte)0x42);

        WolfCryptSecretKey key = new WolfCryptSecretKey("AES", original);

        /* Modify original, should not affect key */
        Arrays.fill(original, (byte)0x00);

        byte[] encoded = key.getEncoded();
        for (int i = 0; i < encoded.length; i++) {
            assertEquals((byte)0x42, encoded[i]);
        }

        /* Modify returned encoded bytes, should not affect key */
        Arrays.fill(encoded, (byte)0x00);

        byte[] encoded2 = key.getEncoded();
        for (int i = 0; i < encoded2.length; i++) {
            assertEquals((byte)0x42, encoded2[i]);
        }
    }
}

