/* AesKeyWrapTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.AesKeyWrap;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class AesKeyWrapTest {

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

    /* Alternative 8-byte IV */
    private static final byte[] ALT_IV = Util.h2b("0011223344556677");

    private static boolean aesKeyWrapEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {

        aesKeyWrapEnabled = FeatureDetect.AesKeyWrapEnabled();

        if (aesKeyWrapEnabled) {
            System.out.println("JNI AesKeyWrap Class");
        }
        else {
            System.out.println("AesKeyWrap test skipped: not compiled in");
        }
    }

    /* Skip per test, keeps the test count stable across native builds */
    private void assumeEnabled() {
        Assume.assumeTrue("AES Key Wrap not compiled in", aesKeyWrapEnabled);
    }

    /** Wrap data and compare to expected, then unwrap and compare to data */
    private void runKat(byte[] kek, byte[] data, byte[] expected) {

        AesKeyWrap wrapper = new AesKeyWrap();
        AesKeyWrap unwrapper = new AesKeyWrap();

        try {
            wrapper.setKey(kek, AesKeyWrap.ENCRYPT_MODE);
            byte[] wrapped = wrapper.wrap(data);

            assertEquals("Wrapped size should be input + 8",
                data.length + AesKeyWrap.KEYWRAP_BLOCK_SIZE, wrapped.length);
            assertArrayEquals("Wrapped data does not match RFC 3394 vector",
                expected, wrapped);

            unwrapper.setKey(kek, AesKeyWrap.DECRYPT_MODE);
            byte[] unwrapped = unwrapper.unwrap(expected);

            assertEquals("Unwrapped size should be input - 8",
                expected.length - AesKeyWrap.KEYWRAP_BLOCK_SIZE,
                unwrapped.length);
            assertArrayEquals("Unwrapped data does not match RFC 3394 " +
                "vector", data, unwrapped);

        } finally {
            wrapper.releaseNativeStruct();
            unwrapper.releaseNativeStruct();
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assumeEnabled();
        assertEquals(NativeStruct.NULL, new AesKeyWrap().getNativeStruct());
    }

    @Test
    public void featureDetectMatchesConstructor() {
        /* Runs on every build, constructor must agree with FeatureDetect */
        if (aesKeyWrapEnabled) {
            assertTrue("AES Key Wrap requires AES", FeatureDetect.AesEnabled());
            AesKeyWrap kw = new AesKeyWrap();
            assertEquals(NativeStruct.NULL, kw.getNativeStruct());
            kw.releaseNativeStruct();
        }
        else {
            try {
                new AesKeyWrap();
                fail("AesKeyWrap constructor should throw when " +
                    "HAVE_AES_KEYWRAP is not compiled in");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
            }
        }
    }

    @Test
    public void sizeHelpers() {
        assertEquals(8, AesKeyWrap.getWrappedSize(0));
        assertEquals(24, AesKeyWrap.getWrappedSize(16));
        assertEquals(40, AesKeyWrap.getWrappedSize(32));
        assertEquals(Integer.MAX_VALUE,
            AesKeyWrap.getWrappedSize(Integer.MAX_VALUE - 8));
        assertEquals(16, AesKeyWrap.getUnwrappedSize(24));
        assertEquals(0, AesKeyWrap.getUnwrappedSize(0));
        assertEquals(0, AesKeyWrap.getUnwrappedSize(7));
        assertEquals(0, AesKeyWrap.getUnwrappedSize(8));
        assertEquals(Integer.MAX_VALUE - 8,
            AesKeyWrap.getUnwrappedSize(Integer.MAX_VALUE));

        try {
            AesKeyWrap.getWrappedSize(Integer.MAX_VALUE - 7);
            fail("inputLen too large should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        try {
            AesKeyWrap.getWrappedSize(-1);
            fail("negative size should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            AesKeyWrap.getUnwrappedSize(-1);
            fail("negative size should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
    }

    @Test
    public void checkSetKeyParams() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap kw = new AesKeyWrap();

        try {
            kw.setKey(null, AesKeyWrap.ENCRYPT_MODE);
            fail("key should not be null");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        int[] badSizes = { 0, 8, 15, 17, 31, 33 };
        for (int sz : badSizes) {
            try {
                kw.setKey(new byte[sz], AesKeyWrap.ENCRYPT_MODE);
                fail("key size " + sz + " should be rejected");
            } catch (WolfCryptException e) {
                /* test must throw */
            }
        }

        try {
            kw.setKey(KEK_128, 2);
            fail("invalid opmode should be rejected");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        /* rejected keys leave the object untouched */
        assertEquals(NativeStruct.NULL, kw.getNativeStruct());

        try {
            kw.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);

            try {
                kw.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);
                fail("setKey twice should throw");
            } catch (IllegalStateException e) {
                /* test must throw */
            }

            kw.releaseNativeStruct();

            /* re-key allowed after release */
            kw.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);
        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void rfc3394Vector41() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());
        runKat(KEK_128, DATA_128, WRAP_128_KEK128);
    }

    @Test
    public void rfc3394Vector42() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes192Enabled());
        runKat(KEK_192, DATA_128, WRAP_128_KEK192);
    }

    @Test
    public void rfc3394Vector43() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());
        runKat(KEK_256, DATA_128, WRAP_128_KEK256);
    }

    @Test
    public void rfc3394Vector44() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes192Enabled());
        runKat(KEK_192, DATA_192, WRAP_192_KEK192);
    }

    @Test
    public void rfc3394Vector45() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());
        runKat(KEK_256, DATA_192, WRAP_192_KEK256);
    }

    @Test
    public void rfc3394Vector46() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());
        runKat(KEK_256, DATA_256, WRAP_256_KEK256);
    }

    @Test
    public void roundTripAllKeyAndDataSizes() {
        assumeEnabled();
        byte[][] keks = { KEK_128, KEK_192, KEK_256 };
        boolean[] enabled = {
            FeatureDetect.Aes128Enabled(),
            FeatureDetect.Aes192Enabled(),
            FeatureDetect.Aes256Enabled()
        };
        int[] dataSizes = { 16, 24, 32, 40, 64, 128, 1024, 4096 };
        Random rand = new Random();

        for (int k = 0; k < keks.length; k++) {
            if (!enabled[k]) {
                continue;
            }

            for (int sz : dataSizes) {
                byte[] data = new byte[sz];
                rand.nextBytes(data);

                AesKeyWrap wrapper = new AesKeyWrap();
                AesKeyWrap unwrapper = new AesKeyWrap();
                try {
                    wrapper.setKey(keks[k], AesKeyWrap.ENCRYPT_MODE);
                    unwrapper.setKey(keks[k], AesKeyWrap.DECRYPT_MODE);

                    byte[] wrapped = wrapper.wrap(data);
                    assertEquals(sz + 8, wrapped.length);
                    assertFalse("wrapped data should differ from input",
                        Arrays.equals(data,
                            Arrays.copyOfRange(wrapped, 8, wrapped.length)));

                    byte[] unwrapped = unwrapper.unwrap(wrapped);
                    assertArrayEquals("round trip failed, KEK " +
                        (keks[k].length * 8) + " data " + sz, data, unwrapped);

                    /* same object can wrap repeatedly */
                    assertArrayEquals(wrapped, wrapper.wrap(data));
                } finally {
                    wrapper.releaseNativeStruct();
                    unwrapper.releaseNativeStruct();
                }
            }
        }
    }

    @Test
    public void corruptedWrappedDataFailsIntegrityCheck() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap kw = new AesKeyWrap();
        kw.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);

        try {
            /* flip a bit in every byte position, one at a time */
            for (int i = 0; i < WRAP_128_KEK128.length; i++) {
                byte[] corrupt = WRAP_128_KEK128.clone();
                corrupt[i] ^= 0x01;

                try {
                    kw.unwrap(corrupt);
                    fail("corrupted byte " + i + " should fail unwrap");
                } catch (WolfCryptException e) {
                    assertEquals("expected BAD_KEYWRAP_IV_E for byte " + i,
                        WolfCryptError.BAD_KEYWRAP_IV_E, e.getError());
                }
            }

            /* Output array must be untouched when integrity check fails */
            byte[] corrupt = WRAP_128_KEK128.clone();
            corrupt[0] ^= 0x01;
            byte[] out = new byte[DATA_128.length];
            Arrays.fill(out, (byte)0x55);

            try {
                kw.unwrap(corrupt, 0, corrupt.length, out, 0, null);
                fail("corrupted data should fail unwrap");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.BAD_KEYWRAP_IV_E, e.getError());
            }

            for (int i = 0; i < out.length; i++) {
                assertEquals("output byte " + i + " was modified on failed " +
                    "unwrap", (byte)0x55, out[i]);
            }

            /* object still works after a failed unwrap */
            assertArrayEquals(DATA_128, kw.unwrap(WRAP_128_KEK128));

        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void wrongKekFailsIntegrityCheck() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        byte[] wrongKek = KEK_128.clone();
        wrongKek[0] ^= 0x01;

        AesKeyWrap kw = new AesKeyWrap();
        kw.setKey(wrongKek, AesKeyWrap.DECRYPT_MODE);

        try {
            kw.unwrap(WRAP_128_KEK128);
            fail("wrong KEK should fail unwrap");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.BAD_KEYWRAP_IV_E, e.getError());
        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void alternativeIvRoundTrip() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap wrapper = new AesKeyWrap();
        AesKeyWrap unwrapper = new AesKeyWrap();

        try {
            wrapper.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);
            unwrapper.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);

            byte[] wrappedAlt = wrapper.wrap(DATA_128, ALT_IV);
            byte[] wrappedDef = wrapper.wrap(DATA_128, null);

            assertEquals(DATA_128.length + 8, wrappedAlt.length);
            assertFalse("different IV should give different output",
                Arrays.equals(wrappedAlt, wrappedDef));
            assertArrayEquals("null IV must equal RFC 3394 default IV",
                WRAP_128_KEK128, wrappedDef);

            /* matching IV unwraps */
            assertArrayEquals(DATA_128, unwrapper.unwrap(wrappedAlt, ALT_IV));

            /* default IV against alternative-IV data fails */
            try {
                unwrapper.unwrap(wrappedAlt);
                fail("default IV should not unwrap alternative IV data");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.BAD_KEYWRAP_IV_E, e.getError());
            }

            /* alternative IV against default-IV data fails */
            try {
                unwrapper.unwrap(wrappedDef, ALT_IV);
                fail("alternative IV should not unwrap default IV data");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.BAD_KEYWRAP_IV_E, e.getError());
            }

            /* a different alternative IV fails */
            byte[] otherIv = ALT_IV.clone();
            otherIv[7] ^= 0x01;
            try {
                unwrapper.unwrap(wrappedAlt, otherIv);
                fail("mismatched IV should not unwrap");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.BAD_KEYWRAP_IV_E, e.getError());
            }

            /* IV length is validated before native */
            int[] badIvSizes = { 0, 7, 9, 16 };
            for (int sz : badIvSizes) {
                try {
                    wrapper.wrap(DATA_128, new byte[sz]);
                    fail("IV size " + sz + " should be rejected on wrap");
                } catch (WolfCryptException e) {
                    /* Java argument check, not a native error code */
                    assertNull(e.getError());
                }
                try {
                    unwrapper.unwrap(wrappedAlt, new byte[sz]);
                    fail("IV size " + sz + " should be rejected on unwrap");
                } catch (WolfCryptException e) {
                    /* Java argument check, not a native error code */
                    assertNull(e.getError());
                }
            }

        } finally {
            wrapper.releaseNativeStruct();
            unwrapper.releaseNativeStruct();
        }
    }

    @Test
    public void wrapInputLengthValidation() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap kw = new AesKeyWrap();
        kw.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);

        try {
            try {
                kw.wrap((byte[])null);
                fail("null input should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }

            int[] badSizes = { 0, 1, 7, 8, 15, 17, 20, 23, 25 };
            for (int sz : badSizes) {
                try {
                    kw.wrap(new byte[sz]);
                    fail("wrap input size " + sz + " should be rejected");
                } catch (WolfCryptException e) {
                    /* expected */
                }
            }

            /* 16 is the minimum */
            assertEquals(24, kw.wrap(new byte[16]).length);

        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void unwrapInputLengthValidation() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap kw = new AesKeyWrap();
        kw.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);

        try {
            try {
                kw.unwrap((byte[])null);
                fail("null input should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }

            int[] badSizes = { 0, 1, 8, 15, 16, 17, 23, 25, 31 };
            for (int sz : badSizes) {
                try {
                    kw.unwrap(new byte[sz]);
                    fail("unwrap input size " + sz + " should be rejected");
                } catch (WolfCryptException e) {
                    /* Java argument check, not a native error code */
                    assertNull("size " + sz + " should fail before the " +
                        "integrity check", e.getError());
                }
            }

        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void offsetVariants() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap wrapper = new AesKeyWrap();
        AesKeyWrap unwrapper = new AesKeyWrap();

        try {
            wrapper.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);
            unwrapper.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);

            /* input at offset 3 inside a larger array, output at offset 5 */
            byte[] inBuf = new byte[3 + DATA_128.length + 4];
            Arrays.fill(inBuf, (byte)0xAA);
            System.arraycopy(DATA_128, 0, inBuf, 3, DATA_128.length);

            byte[] outBuf = new byte[5 + WRAP_128_KEK128.length + 2];
            Arrays.fill(outBuf, (byte)0xBB);

            int ret = wrapper.wrap(inBuf, 3, DATA_128.length, outBuf, 5,
                null);
            assertEquals(WRAP_128_KEK128.length, ret);
            assertArrayEquals(WRAP_128_KEK128,
                Arrays.copyOfRange(outBuf, 5, 5 + ret));

            /* bytes outside the output region are untouched */
            for (int i = 0; i < 5; i++) {
                assertEquals((byte)0xBB, outBuf[i]);
            }
            for (int i = 5 + ret; i < outBuf.length; i++) {
                assertEquals((byte)0xBB, outBuf[i]);
            }

            /* unwrap from offset 5 back into an offset output */
            byte[] plainBuf = new byte[2 + DATA_128.length + 1];
            Arrays.fill(plainBuf, (byte)0xCC);
            ret = unwrapper.unwrap(outBuf, 5, WRAP_128_KEK128.length,
                plainBuf, 2, null);
            assertEquals(DATA_128.length, ret);
            assertArrayEquals(DATA_128,
                Arrays.copyOfRange(plainBuf, 2, 2 + ret));
            assertEquals((byte)0xCC, plainBuf[0]);
            assertEquals((byte)0xCC, plainBuf[1]);
            assertEquals((byte)0xCC, plainBuf[plainBuf.length - 1]);

            /* same array for input and output, overlapping regions */
            byte[] same = new byte[DATA_128.length + 8];
            System.arraycopy(DATA_128, 0, same, 0, DATA_128.length);
            ret = wrapper.wrap(same, 0, DATA_128.length, same, 0, null);
            assertEquals(WRAP_128_KEK128.length, ret);
            assertArrayEquals(WRAP_128_KEK128, same);

            /* output too small */
            try {
                wrapper.wrap(DATA_128, 0, DATA_128.length,
                    new byte[DATA_128.length + 7], 0, null);
                fail("short output should throw on wrap");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(DATA_128, 0, DATA_128.length,
                    new byte[DATA_128.length + 8], 1, null);
                fail("short output with offset should throw on wrap");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, 0, WRAP_128_KEK128.length,
                    new byte[DATA_128.length - 1], 0, null);
                fail("short output should throw on unwrap");
            } catch (WolfCryptException e) {
                /* expected */
            }

            /* bad offsets and lengths */
            byte[] out = new byte[64];
            try {
                wrapper.wrap(DATA_128, -1, DATA_128.length, out, 0, null);
                fail("negative input offset should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(DATA_128, 0, -8, out, 0, null);
                fail("negative length should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(DATA_128, 0, DATA_128.length, out, -1, null);
                fail("negative output offset should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(DATA_128, 8, DATA_128.length, out, 0, null);
                fail("input offset + length past array should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(DATA_128, Integer.MAX_VALUE, 16, out, 0, null);
                fail("input offset overflow should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(DATA_128, 0, DATA_128.length, out,
                    Integer.MAX_VALUE, null);
                fail("output offset overflow should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(DATA_128, 0, DATA_128.length, null, 0, null);
                fail("null output should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                wrapper.wrap(null, 0, DATA_128.length, out, 0, null);
                fail("null input should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }

            /* same argument checks on the unwrap side */
            byte[] plain = new byte[64];
            int wLen = WRAP_128_KEK128.length;
            try {
                unwrapper.unwrap(null, 0, wLen, plain, 0, null);
                fail("unwrap null input should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, 0, wLen, null, 0, null);
                fail("unwrap null output should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, -1, wLen, plain, 0, null);
                fail("unwrap negative input offset should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, 0, -8, plain, 0, null);
                fail("unwrap negative length should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, 0, wLen, plain, -1, null);
                fail("unwrap negative output offset should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, 8, wLen, plain, 0, null);
                fail("unwrap input offset + length past array should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, Integer.MAX_VALUE, wLen,
                    plain, 0, null);
                fail("unwrap input offset overflow should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, 0, wLen, plain,
                    Integer.MAX_VALUE, null);
                fail("unwrap output offset overflow should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                unwrapper.unwrap(WRAP_128_KEK128, 0, wLen, plain, 0,
                    new byte[7]);
                fail("unwrap 7 byte IV should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }

            /* none of the failures above disturbed the object */
            assertArrayEquals(DATA_128, unwrapper.unwrap(WRAP_128_KEK128));
            assertArrayEquals(WRAP_128_KEK128, wrapper.wrap(DATA_128));

        } finally {
            wrapper.releaseNativeStruct();
            unwrapper.releaseNativeStruct();
        }
    }

    @Test
    public void directionIsEnforced() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap kw = new AesKeyWrap();

        try {
            kw.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);
            try {
                kw.wrap(DATA_128);
                fail("wrap with DECRYPT_MODE key should throw");
            } catch (IllegalStateException e) {
                /* expected */
            }
            kw.releaseNativeStruct();

            kw.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);
            try {
                kw.unwrap(WRAP_128_KEK128);
                fail("unwrap with ENCRYPT_MODE key should throw");
            } catch (IllegalStateException e) {
                /* expected */
            }

        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void useWithoutKeyThrows() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap kw = new AesKeyWrap();

        try {
            try {
                kw.wrap(DATA_128);
                fail("wrap without key should throw");
            } catch (IllegalStateException e) {
                /* expected */
            }
            try {
                kw.unwrap(WRAP_128_KEK128);
                fail("unwrap without key should throw");
            } catch (IllegalStateException e) {
                /* expected */
            }

            /* after release, key must be set again before use */
            kw.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);
            kw.releaseNativeStruct();
            try {
                kw.wrap(DATA_128);
                fail("wrap after release should throw");
            } catch (IllegalStateException e) {
                /* expected */
            }
        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void releaseAndReuseShouldWork() {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes128Enabled());

        AesKeyWrap kw = new AesKeyWrap();

        try {
            kw.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);
            byte[] first = kw.wrap(DATA_128);
            kw.releaseNativeStruct();

            /* second release must be a safe no-op */
            kw.releaseNativeStruct();

            /* object must re-init cleanly after release */
            kw.setKey(KEK_128, AesKeyWrap.ENCRYPT_MODE);
            byte[] second = kw.wrap(DATA_128);

            assertArrayEquals("wrap after re-init should match", first,
                second);
            assertArrayEquals(WRAP_128_KEK128, second);

            /* and can switch direction after release */
            kw.releaseNativeStruct();
            kw.setKey(KEK_128, AesKeyWrap.DECRYPT_MODE);
            assertArrayEquals(DATA_128, kw.unwrap(second));

        } finally {
            kw.releaseNativeStruct();
        }
    }

    @Test
    public void threadedWrapUnwrap() throws InterruptedException {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    int ret = 0;
                    AesKeyWrap wrapper = new AesKeyWrap();
                    AesKeyWrap unwrapper = new AesKeyWrap();

                    try {
                        wrapper.setKey(KEK_256, AesKeyWrap.ENCRYPT_MODE);
                        unwrapper.setKey(KEK_256, AesKeyWrap.DECRYPT_MODE);

                        for (int j = 0; j < 50; j++) {
                            byte[] wrapped = wrapper.wrap(DATA_256);
                            if (!Arrays.equals(WRAP_256_KEK256, wrapped)) {
                                ret = 1;
                            }
                            byte[] unwrapped = unwrapper.unwrap(wrapped);
                            if (!Arrays.equals(DATA_256, unwrapped)) {
                                ret = 1;
                            }
                        }

                    } catch (Throwable t) {
                        t.printStackTrace();
                        ret = 1;
                    } finally {
                        wrapper.releaseNativeStruct();
                        unwrapper.releaseNativeStruct();
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
                fail("Threading error in AesKeyWrap thread test");
            }
        }
    }

    /** One wrapper and one unwrapper shared by threads, exercises
     *  synchronized/pointerLock paths */
    @Test
    public void threadedSharedObject() throws InterruptedException {
        assumeEnabled();
        Assume.assumeTrue(FeatureDetect.Aes256Enabled());

        final AesKeyWrap wrapper = new AesKeyWrap();
        final AesKeyWrap unwrapper = new AesKeyWrap();

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        try {
            wrapper.setKey(KEK_256, AesKeyWrap.ENCRYPT_MODE);
            unwrapper.setKey(KEK_256, AesKeyWrap.DECRYPT_MODE);

            for (int i = 0; i < numThreads; i++) {
                service.submit(new Runnable() {
                    @Override
                    public void run() {
                        int ret = 0;

                        try {
                            for (int j = 0; j < 50; j++) {
                                byte[] wrapped = wrapper.wrap(DATA_256);
                                if (!Arrays.equals(WRAP_256_KEK256, wrapped)) {
                                    ret = 1;
                                }
                                if (!Arrays.equals(DATA_256,
                                        unwrapper.unwrap(wrapped))) {
                                    ret = 1;
                                }
                                byte[] alt = wrapper.wrap(DATA_256, ALT_IV);
                                if (!Arrays.equals(DATA_256,
                                        unwrapper.unwrap(alt, ALT_IV))) {
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

            for (Integer cur : results) {
                if (cur == 1) {
                    fail("Threading error in shared AesKeyWrap thread test");
                }
            }
        } finally {
            wrapper.releaseNativeStruct();
            unwrapper.releaseNativeStruct();
        }
    }
}
