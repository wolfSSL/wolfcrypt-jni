/* ShakeTest.java
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

import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.LinkedBlockingQueue;
import javax.crypto.ShortBufferException;

import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.Shake;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class ShakeTest {

    /* SHAKE-128 rate (block size) in bytes */
    private static final int SHAKE128_RATE = 168;
    /* SHAKE-256 rate (block size) in bytes */
    private static final int SHAKE256_RATE = 136;

    /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    private static final String MSG56 =
        "6162636462636465636465666465666765666768666768696768696A68696A6B" +
        "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071";

    /* SHAKE128("abc"), 336-byte XOF output (Python hashlib, first 114
     * bytes match the NIST vector in native wolfCrypt test.c). Shorter
     * outputs are prefixes of this stream, anchoring all length KATs */
    private static final String SHAKE128_ABC_336 =
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8" +
        "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378" +
        "9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232" +
        "a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4" +
        "a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a" +
        "cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd" +
        "4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b4" +
        "75375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e50732f5cfc904b1" +
        "319795000d7361d9e5e1b77b4b8f5774aa1482cfa58f83096bdb2e06a3eed543" +
        "a38919b57ecbec737f4086be007f8ef80094ceea8807193d46e9be540b6e99b4" +
        "c1c71507095028a024e8d39aa8f4c585";

    /* SHAKE128(""), 32-byte XOF output */
    private static final String SHAKE128_EMPTY_32 =
        "7f9c2ba4e88f827d616045507605853e" +
        "d73b8093f6efbc88eb1a6eacfa66ef26";

    /* SHAKE256(MSG56), 64-byte XOF output */
    private static final String SHAKE256_MSG56_64 =
        "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e" +
        "332940d8688a4e6a59aa8060f1f9bc996c05aca3c696a8b66279dc672c74" +
        "0bb224ec";

    /* SHAKE256("abc"), 272-byte XOF output, same anchoring approach */
    private static final String SHAKE256_ABC_272 =
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4" +
        "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78" +
        "dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334" +
        "e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3" +
        "3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67" +
        "7513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195" +
        "bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412" +
        "fc346b1bb39b878330e026b12ddf384a";

    @Rule(order = Integer.MIN_VALUE)
    public TestRule watcher = TimedTestWatcher.create();

    private static boolean shakeEnabled = false;

    @BeforeClass
    public static void checkShakeIsAvailable() {
        shakeEnabled = FeatureDetect.Shake128Enabled() ||
            FeatureDetect.Shake256Enabled();
        if (shakeEnabled) {
            System.out.println("JNI Shake Class");
        }
        else {
            System.out.println("ShakeTest skipped: " +
                WolfCryptError.NOT_COMPILED_IN);
        }
    }

    /* Tests pinned to one variant have their own Assume guards */
    private void assumeEnabled() {
        Assume.assumeTrue("SHAKE not compiled in", shakeEnabled);
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        assertEquals(NativeStruct.NULL,
            new Shake(Shake.TYPE_SHAKE_256).getNativeStruct());
    }

    @Test
    public void invalidHashTypeShouldThrow() {
        assumeEnabled();
        try {
            new Shake(0);
            fail("Shake(0) should have thrown for invalid hash type");
        } catch (WolfCryptException e) {
            /* expected */
        }
    }

    @Test
    public void invalidOutputLengthShouldThrow() {
        assumeEnabled();
        if (FeatureDetect.Shake128Enabled()) {
            try {
                new Shake(Shake.TYPE_SHAKE_128, 0);
                fail("Shake(type, 0) should have thrown for invalid outLen");
            } catch (WolfCryptException e) {
                /* expected */
            }
        }

        if (FeatureDetect.Shake256Enabled()) {
            try {
                new Shake(Shake.TYPE_SHAKE_256, -1);
                fail("Shake(type, -1) should have thrown for invalid outLen");
            } catch (WolfCryptException e) {
                /* expected */
            }
        }
    }

    @Test
    public void updateExceedingBufferLengthShouldThrow() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        Shake shake = new Shake(Shake.TYPE_SHAKE_256);
        byte[] data = new byte[8];

        /* len larger than remaining array capacity must be rejected */
        try {
            shake.update(data, 1, Integer.MAX_VALUE);
            fail("update() should have thrown, len exceeds data length");
        } catch (IllegalStateException e) {
            /* init failure is not the bounds rejection */
            throw e;
        } catch (RuntimeException e) {
            /* expected */
        } finally {
            shake.releaseNativeStruct();
        }
    }

    @Test
    public void shake128HashShouldMatchUsingByteArray() {
        String[] dataVector = new String[] {
            "", /* empty string */
            "616263",  /* "abc" */
            MSG56
        };

        /* SHAKE-128, 32-byte default output length */
        byte[][] hashVector = new byte[][] {
            Util.h2b(SHAKE128_EMPTY_32),
            Arrays.copyOf(Util.h2b(SHAKE128_ABC_336), Shake.DIGEST_SIZE_128),
            Util.h2b("1a96182b50fb8c7e74e0a707788f55e9" +
                "8209b8d91fade8f32f8dd5cff7bf21f5")
        };

        Assume.assumeTrue(FeatureDetect.Shake128Enabled());

        for (int i = 0; i < dataVector.length; i++) {
            Shake shake = new Shake(Shake.TYPE_SHAKE_128);
            byte[] data = Util.h2b(dataVector[i]);

            assertEquals(Shake.DIGEST_SIZE_128, shake.digestSize());

            shake.update(data);
            byte[] result = shake.digest();

            assertArrayEquals(hashVector[i], result);

            shake.releaseNativeStruct();
        }
    }

    @Test
    public void shake256HashShouldMatchUsingByteArray() {
        String[] dataVector = new String[] {
            "", /* empty string */
            "616263",  /* "abc" */
            MSG56
        };

        /* SHAKE-256, 64-byte default output length */
        byte[][] hashVector = new byte[][] {
            Util.h2b(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c" +
                "27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49" +
                "479ab48640292eacb3b7c4be"),
            Arrays.copyOf(Util.h2b(SHAKE256_ABC_272), Shake.DIGEST_SIZE_256),
            Util.h2b(SHAKE256_MSG56_64)
        };

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        for (int i = 0; i < dataVector.length; i++) {
            Shake shake = new Shake(Shake.TYPE_SHAKE_256);
            byte[] data = Util.h2b(dataVector[i]);

            assertEquals(Shake.DIGEST_SIZE_256, shake.digestSize());

            shake.update(data);
            byte[] result = shake.digest();

            assertArrayEquals(hashVector[i], result);

            shake.releaseNativeStruct();
        }
    }

    @Test
    public void shake128XofOutputLengthsShouldMatchPrefix() {
        byte[] data = Util.h2b("616263"); /* "abc" */
        byte[] expected = Util.h2b(SHAKE128_ABC_336);

        /* XOF lens spanning the 168-byte boundary and multiple rate blocks */
        int[] outLens = { 1, 16, 32, 64, 113, 114, 136,
                          SHAKE128_RATE - 1, SHAKE128_RATE,
                          SHAKE128_RATE + 1, 200, 336 };

        Assume.assumeTrue(FeatureDetect.Shake128Enabled());

        for (int outLen : outLens) {
            Shake shake = new Shake(Shake.TYPE_SHAKE_128, outLen);

            assertEquals(outLen, shake.digestSize());

            shake.update(data);
            byte[] result = shake.digest();

            assertEquals(outLen, result.length);
            assertArrayEquals(Arrays.copyOf(expected, outLen), result);

            shake.releaseNativeStruct();
        }
    }

    @Test
    public void shake256XofOutputLengthsShouldMatchPrefix() {
        byte[] data = Util.h2b("616263"); /* "abc" */
        byte[] expected = Util.h2b(SHAKE256_ABC_272);

        /* XOF lens spanning the 136-byte boundary and multiple rate blocks */
        int[] outLens = { 1, 16, 32, 64, 104,
                          SHAKE256_RATE - 1, SHAKE256_RATE,
                          SHAKE256_RATE + 1, 200, 272 };

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        for (int outLen : outLens) {
            Shake shake = new Shake(Shake.TYPE_SHAKE_256, outLen);

            assertEquals(outLen, shake.digestSize());

            shake.update(data);
            byte[] result = shake.digest();

            assertEquals(outLen, result.length);
            assertArrayEquals(Arrays.copyOf(expected, outLen), result);

            shake.releaseNativeStruct();
        }
    }

    @Test
    public void emptyInputXofShouldMatchPrefix() {
        /* Empty input at an odd XOF length, must prefix the KAT */
        byte[] expected = Util.h2b(SHAKE128_EMPTY_32);

        Assume.assumeTrue(FeatureDetect.Shake128Enabled());

        Shake shake = new Shake(Shake.TYPE_SHAKE_128, 17);
        shake.update(new byte[0]);
        byte[] result = shake.digest();

        assertArrayEquals(Arrays.copyOf(expected, 17), result);

        shake.releaseNativeStruct();
    }

    @Test
    public void largeInputHashShouldMatch() {
        assumeEnabled();
        /* 100 updates of 1024-byte buffer, matches large input test in
         * native wolfCrypt test.c */
        byte[] pattern = new byte[1024];
        for (int i = 0; i < pattern.length; i++) {
            pattern[i] = (byte)(i & 0xFF);
        }

        if (FeatureDetect.Shake128Enabled()) {
            byte[] expected = Util.h2b(
                "88d70e8646726b3d7d22e1a92d02db35" +
                "924f1b0390eea3ced13a083ad74e10df");

            Shake shake = new Shake(Shake.TYPE_SHAKE_128);
            for (int i = 0; i < 100; i++) {
                shake.update(pattern);
            }
            assertArrayEquals(expected, shake.digest());
            shake.releaseNativeStruct();
        }

        if (FeatureDetect.Shake256Enabled()) {
            byte[] expected = Util.h2b(
                "90324accd1dfb80b791fb8c85b54c8e745f5606b3826b20aee3801f3" +
                "d9fa969f6ad715dfb6c2f420334455e82a092b682e18655e659328bc" +
                "b19ee2b192ea98ac");

            Shake shake = new Shake(Shake.TYPE_SHAKE_256);
            for (int i = 0; i < 100; i++) {
                shake.update(pattern);
            }
            assertArrayEquals(expected, shake.digest());
            shake.releaseNativeStruct();
        }
    }

    @Test
    public void byteBufferHashShouldMatch() throws ShortBufferException {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        /* Exercise the direct ByteBuffer JNI update/final paths */
        byte[] data = Util.h2b("616263"); /* "abc" */
        byte[] expected = Arrays.copyOf(
            Util.h2b(SHAKE256_ABC_272), Shake.DIGEST_SIZE_256);

        ByteBuffer dataBuf = ByteBuffer.allocateDirect(data.length);
        ByteBuffer hashBuf =
            ByteBuffer.allocateDirect(Shake.DIGEST_SIZE_256);

        dataBuf.put(data);
        dataBuf.flip();

        Shake shake = new Shake(Shake.TYPE_SHAKE_256);
        shake.update(dataBuf);
        shake.digest(hashBuf);
        hashBuf.flip();

        byte[] result = new byte[hashBuf.remaining()];
        hashBuf.get(result);

        assertArrayEquals(expected, result);

        shake.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        Shake shake = new Shake(Shake.TYPE_SHAKE_256);
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] data2 = new byte[] { 0x05, 0x06, 0x07, 0x08, 0x09 };

        shake.update(data);
        byte[] result = shake.digest();

        /* test reusing existing object after a call to digest() */
        shake.update(data2);
        byte[] result2 = shake.digest();

        assertNotNull(result);
        assertNotNull(result2);
        assertFalse(Arrays.equals(result, result2));

        shake.releaseNativeStruct();
    }

    @Test
    public void copyObject() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        Shake shake = new Shake(Shake.TYPE_SHAKE_256);
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };

        shake.update(data);

        /* test making copy of Shake, should retain same state */
        Shake shakeCopy = (Shake)shake.clone();

        byte[] result = shake.digest();
        byte[] result2 = shakeCopy.digest();

        assertArrayEquals(result, result2);

        shake.releaseNativeStruct();
        shakeCopy.releaseNativeStruct();
    }

    @Test
    public void copyObjectKeepsCustomOutputLength() {
        Assume.assumeTrue(FeatureDetect.Shake128Enabled());

        Shake shake = new Shake(Shake.TYPE_SHAKE_128, 100);
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };

        shake.update(data);

        Shake shakeCopy = (Shake)shake.clone();
        assertEquals(100, shakeCopy.digestSize());

        byte[] result = shake.digest();
        byte[] result2 = shakeCopy.digest();

        assertEquals(100, result.length);
        assertArrayEquals(result, result2);

        shake.releaseNativeStruct();
        shakeCopy.releaseNativeStruct();
    }

    @Test
    public void threadedHashTest() throws InterruptedException {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();
        final LinkedBlockingQueue<String> errors =
            new LinkedBlockingQueue<>();
        final byte[] rand10kBuf = new byte[10240];

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand10kBuf);

        /* generate hash over input data concurrently across numThreads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    Shake shake = null;

                    try {
                        shake = new Shake(Shake.TYPE_SHAKE_256);

                        /* process/update in 1024-byte chunks */
                        for (int j = 0; j < rand10kBuf.length; j+= 1024) {
                            shake.update(rand10kBuf, j, 1024);
                        }

                        /* get final hash */
                        byte[] hash = shake.digest();
                        results.add(hash.clone());

                    } catch (Exception e) {
                        errors.add(e.toString());
                    } finally {
                        if (shake != null) {
                            shake.releaseNativeStruct();
                        }
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        assertTrue("timed out waiting for threads to finish",
            latch.await(120, TimeUnit.SECONDS));
        service.shutdown();

        /* a failed worker must fail the test, not blend in */
        assertTrue("worker errors: " + errors, errors.isEmpty());
        assertEquals(numThreads, results.size());

        /* compare all digests, all should be the same across threads */
        Iterator<byte[]> listIterator = results.iterator();
        byte[] current = listIterator.next();
        while (listIterator.hasNext()) {
            byte[] next = listIterator.next();
            if (!Arrays.equals(current, next)) {
                fail("Found two non-identical digests in thread test");
            }
            current = next;
        }
    }

    @Test
    public void blockRateEdgeCases() {
        assumeEnabled();
        /* Input sizes around the SHAKE rate (block) boundaries */
        int[] rates = { SHAKE128_RATE, SHAKE256_RATE };
        int[] types = { Shake.TYPE_SHAKE_128, Shake.TYPE_SHAKE_256 };

        for (int i = 0; i < rates.length; i++) {
            if (!FeatureDetect.Shake128Enabled() &&
                types[i] == Shake.TYPE_SHAKE_128) {
                continue;
            }
            if (!FeatureDetect.Shake256Enabled() &&
                types[i] == Shake.TYPE_SHAKE_256) {
                continue;
            }

            /* Test exactly rate size */
            byte[] blockData = new byte[rates[i]];
            Arrays.fill(blockData, (byte)0x61); /* fill with 'a' */

            Shake shake = new Shake(types[i]);
            shake.update(blockData);
            byte[] result1 = shake.digest();
            shake.releaseNativeStruct();

            /* Test one byte less than rate size */
            byte[] underData = new byte[rates[i] - 1];
            Arrays.fill(underData, (byte)0x61);

            shake = new Shake(types[i]);
            shake.update(underData);
            byte[] result2 = shake.digest();
            shake.releaseNativeStruct();

            /* Test one byte more than rate size */
            byte[] overData = new byte[rates[i] + 1];
            Arrays.fill(overData, (byte)0x61);

            shake = new Shake(types[i]);
            shake.update(overData);
            byte[] result3 = shake.digest();
            shake.releaseNativeStruct();

            /* Results should all be different */
            assertFalse(Arrays.equals(result1, result2));
            assertFalse(Arrays.equals(result2, result3));
            assertFalse(Arrays.equals(result1, result3));
        }
    }

    @Test
    public void streamingUpdates() {
        /* Test streaming updates with known test vector */
        String expected = SHAKE256_MSG56_64;

        byte[] data = Util.h2b(MSG56);

        /* Test different chunk sizes */
        int[] chunks = {1, 3, 7, 13, 17, 32, 64};

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        for (int chunkSize : chunks) {
            Shake shake = new Shake(Shake.TYPE_SHAKE_256);

            /* Update in chunks */
            for (int i = 0; i < data.length; i += chunkSize) {
                int len = Math.min(chunkSize, data.length - i);
                shake.update(data, i, len);
            }

            byte[] result = shake.digest();
            assertArrayEquals(Util.h2b(expected), result);

            shake.releaseNativeStruct();
        }
    }

    @Test
    public void releaseAndReleaseAgainShouldNotError() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        /* Double release must be safe */
        Shake shake = new Shake(Shake.TYPE_SHAKE_256);
        shake.update(new byte[] { 0x00, 0x01, 0x02 });
        shake.releaseNativeStruct();
        shake.releaseNativeStruct();
    }

    @Test
    public void cloneOfUnusedObjectsShouldWork() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        byte[] abc = Util.h2b("616263"); /* "abc" */
        byte[] expected = Arrays.copyOf(
            Util.h2b(SHAKE256_ABC_272), Shake.DIGEST_SIZE_256);

        /* Clone before first use */
        Shake fresh = new Shake(Shake.TYPE_SHAKE_256);
        Shake freshCopy = (Shake)fresh.clone();

        fresh.update(abc);
        freshCopy.update(abc);
        assertArrayEquals(expected, fresh.digest());
        assertArrayEquals(expected, freshCopy.digest());

        fresh.releaseNativeStruct();
        freshCopy.releaseNativeStruct();

        /* Pending constructor data must be absorbed into the copy */
        Shake withData = new Shake(abc, Shake.TYPE_SHAKE_256);
        Shake withDataCopy = (Shake)withData.clone();

        assertArrayEquals(expected, withData.digest());
        assertArrayEquals(expected, withDataCopy.digest());

        withData.releaseNativeStruct();
        withDataCopy.releaseNativeStruct();
    }

    @Test
    public void heapByteBufferUpdateShouldThrow() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        /* Non-direct buffers have no native address, native update must
         * reject them */
        ByteBuffer heapBuf = ByteBuffer.allocate(16);

        Shake shake = new Shake(Shake.TYPE_SHAKE_256);
        try {
            shake.update(heapBuf);
            fail("update() should have thrown for heap ByteBuffer");
        } catch (WolfCryptException e) {
            /* expected */
        } finally {
            shake.releaseNativeStruct();
        }
    }

    @Test
    public void shortOutputBufferShouldThrow() {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        /* Custom XOF length makes digest size caller-controlled, short
         * output buffers must throw ShortBufferException */
        Shake shake = new Shake(Shake.TYPE_SHAKE_256, 100);
        shake.update(Util.h2b("616263")); /* "abc" */

        try {
            shake.digest(new byte[64]);
            fail("digest(byte[64]) should have thrown for 100-byte outLen");
        } catch (ShortBufferException e) {
            /* expected */
        }

        try {
            shake.digest(ByteBuffer.allocateDirect(64));
            fail("digest(ByteBuffer) should have thrown for 100-byte outLen");
        } catch (ShortBufferException e) {
            /* expected */
        }

        /* State kept after rejected digests, output still correct */
        byte[] result = shake.digest();
        assertArrayEquals(
            Arrays.copyOf(Util.h2b(SHAKE256_ABC_272), 100), result);

        shake.releaseNativeStruct();
    }

    /* XOF output of outLen bytes into an over-sized direct buffer at a
     * non-zero position, only that window may change */
    private static void xofIntoDirectBuffer(int type, int outLen,
        byte[] expected) throws ShortBufferException {

        final int hashPos = 10;
        final byte fill = (byte)0xA5;
        ByteBuffer dataBuf = ByteBuffer.allocateDirect(3);
        ByteBuffer hashBuf = ByteBuffer.allocateDirect(hashPos + outLen + 6);

        dataBuf.put(Util.h2b("616263")); /* "abc" */
        dataBuf.flip();
        while (hashBuf.hasRemaining()) {
            hashBuf.put(fill);
        }
        hashBuf.position(hashPos);

        Shake shake = new Shake(type, outLen);
        shake.update(dataBuf);
        shake.digest(hashBuf);
        shake.releaseNativeStruct();

        assertEquals(hashPos + outLen, hashBuf.position());
        byte[] all = new byte[hashBuf.capacity()];
        hashBuf.position(0);
        hashBuf.get(all);
        assertArrayEquals(expected,
            Arrays.copyOfRange(all, hashPos, hashPos + outLen));
        for (int i = 0; i < all.length; i++) {
            if (i < hashPos || i >= hashPos + outLen) {
                assertEquals("fill byte changed at " + i, fill, all[i]);
            }
        }
    }

    @Test
    public void byteBufferXofOutputLength256ShouldMatch()
        throws ShortBufferException {
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        xofIntoDirectBuffer(Shake.TYPE_SHAKE_256, 100,
            Arrays.copyOf(Util.h2b(SHAKE256_ABC_272), 100));
    }

    @Test
    public void byteBufferXofOutputLength128ShouldMatch()
        throws ShortBufferException {
        Assume.assumeTrue(FeatureDetect.Shake128Enabled());

        /* 200 bytes crosses the 168 byte SHAKE-128 rate boundary */
        xofIntoDirectBuffer(Shake.TYPE_SHAKE_128, 200,
            Arrays.copyOf(Util.h2b(SHAKE128_ABC_336), 200));
    }

    @Test
    public void byteBufferNonZeroPositionShouldMatch()
        throws ShortBufferException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        byte[] abc = Util.h2b("616263"); /* "abc" */
        byte[] expected = Arrays.copyOf(
            Util.h2b(SHAKE256_ABC_272), Shake.DIGEST_SIZE_256);
        final int dataPos = 5;
        final int hashPos = 10;
        final byte fill = (byte)0xA5;

        /* Exercise native buffer + offset arithmetic: input read window
         * and output write position both at non-zero positions of
         * over-sized direct buffers */
        ByteBuffer dataBuf = ByteBuffer.allocateDirect(32);
        dataBuf.position(dataPos);
        dataBuf.put(abc);
        dataBuf.position(dataPos);
        dataBuf.limit(dataPos + abc.length);

        ByteBuffer hashBuf =
            ByteBuffer.allocateDirect(hashPos + Shake.DIGEST_SIZE_256 + 6);
        while (hashBuf.hasRemaining()) {
            hashBuf.put(fill);
        }
        hashBuf.position(hashPos);

        Shake shake = new Shake(Shake.TYPE_SHAKE_256);
        shake.update(dataBuf);
        shake.digest(hashBuf);
        shake.releaseNativeStruct();

        assertEquals(dataPos + abc.length, dataBuf.position());
        assertEquals(hashPos + Shake.DIGEST_SIZE_256, hashBuf.position());

        /* Digest written at hashPos, surrounding fill bytes untouched */
        byte[] all = new byte[hashBuf.capacity()];
        hashBuf.position(0);
        hashBuf.limit(hashBuf.capacity());
        hashBuf.get(all);

        for (int i = 0; i < hashPos; i++) {
            assertEquals(fill, all[i]);
        }
        assertArrayEquals(expected, Arrays.copyOfRange(all, hashPos,
            hashPos + Shake.DIGEST_SIZE_256));
        for (int i = hashPos + Shake.DIGEST_SIZE_256; i < all.length; i++) {
            assertEquals(fill, all[i]);
        }
    }
}
