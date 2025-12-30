/* Sha3Test.java
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

import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import com.wolfssl.wolfcrypt.Sha3;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class Sha3Test {
    private ByteBuffer data = ByteBuffer.allocateDirect(32);
    private ByteBuffer result = ByteBuffer.allocateDirect(Sha3.DIGEST_SIZE_512);
    private ByteBuffer expected = ByteBuffer.allocateDirect(Sha3.DIGEST_SIZE_512);

    @Rule(order = Integer.MIN_VALUE)
    public TestRule watcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkSha3IsAvailable() {
        try {
            Sha3 sha = new Sha3(Sha3.TYPE_SHA3_256);
            System.out.println("JNI Sha3 Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("Sha3Test skipped: " + e.getError());
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL,
                    new Sha3(Sha3.TYPE_SHA3_256).getNativeStruct());
    }

    @Test
    public void sha3_256HashShouldMatchUsingByteArray() {
        /* Test vectors from NIST FIPS 202 - SHA-3 Standard */
        String[] dataVector = new String[] {
            "", /* empty string */
            "616263",  /* "abc" */
            /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
            "6162636462636465636465666465666765666768666768696768696A68696A6B" +
            "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"
        };

        String[] hashVector = new String[] {
            /* NIST FIPS 202 A.1 - SHA3-256 Empty Test Vector */
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            /* NIST FIPS 202 A.1 - SHA3-256 abc Test Vector */
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            /* NIST FIPS 202 A.1 - SHA3-256 Long Test Vector */
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
        };

        for (int i = 0; i < dataVector.length; i++) {
            Sha3 sha = new Sha3(Sha3.TYPE_SHA3_256);
            byte[] data = Util.h2b(dataVector[i]);
            byte[] expected = Util.h2b(hashVector[i]);

            sha.update(data);
            byte[] result = sha.digest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    public void sha3_224HashShouldMatchUsingByteArray() {
        /* Test vectors from NIST FIPS 202 - SHA-3 Standard */
        String[] dataVector = new String[] {
            "", /* empty string */
            "616263",  /* "abc" */
            /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
            "6162636462636465636465666465666765666768666768696768696A68696A6B" +
            "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"
        };

        String[] hashVector = new String[] {
            /* NIST FIPS 202 A.1 - SHA3-224 Empty Test Vector */
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
            /* NIST FIPS 202 A.1 - SHA3-224 abc Test Vector */
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
            /* NIST FIPS 202 A.1 - SHA3-224 Long Test Vector */
            "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
        };

        for (int i = 0; i < dataVector.length; i++) {
            Sha3 sha = new Sha3(Sha3.TYPE_SHA3_224);
            byte[] data = Util.h2b(dataVector[i]);
            byte[] expected = Util.h2b(hashVector[i]);

            sha.update(data);
            byte[] result = sha.digest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    public void sha3_384HashShouldMatchUsingByteArray() {
        /* Test vectors from NIST FIPS 202 - SHA-3 Standard */
        String[] dataVector = new String[] {
            "", /* empty string */
            "616263",  /* "abc" */
            /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
            "6162636462636465636465666465666765666768666768696768696A68696A6B" +
            "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"
        };

        String[] hashVector = new String[] {
            /* NIST FIPS 202 A.1 - SHA3-384 Empty Test Vector */
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a" +
            "c3713831264adb47fb6bd1e058d5f004",
            /* NIST FIPS 202 A.1 - SHA3-384 abc Test Vector */
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2" +
            "98d88cea927ac7f539f1edf228376d25",
            /* NIST FIPS 202 A.1 - SHA3-384 Long Test Vector */
            "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5a" +
            "a04a1f076e62fea19eef51acd0657c22"
        };

        for (int i = 0; i < dataVector.length; i++) {
            Sha3 sha = new Sha3(Sha3.TYPE_SHA3_384);
            byte[] data = Util.h2b(dataVector[i]);
            byte[] expected = Util.h2b(hashVector[i]);

            sha.update(data);
            byte[] result = sha.digest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    public void sha3_512HashShouldMatchUsingByteArray() {
        /* Test vectors from NIST FIPS 202 - SHA-3 Standard */
        String[] dataVector = new String[] {
            "", /* empty string */
            "616263",  /* "abc" */
            /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
            "6162636462636465636465666465666765666768666768696768696A68696A6B" +
            "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"
        };

        String[] hashVector = new String[] {
            /* NIST FIPS 202 A.1 - SHA3-512 Empty Test Vector */
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" +
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            /* NIST FIPS 202 A.1 - SHA3-512 abc Test Vector */
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" +
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            /* NIST FIPS 202 A.1 - SHA3-512 Long Test Vector */
            "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d" +
            "ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
        };

        for (int i = 0; i < dataVector.length; i++) {
            Sha3 sha = new Sha3(Sha3.TYPE_SHA3_512);
            byte[] data = Util.h2b(dataVector[i]);
            byte[] expected = Util.h2b(hashVector[i]);

            sha.update(data);
            byte[] result = sha.digest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    public void reuseObject() {
        Sha3 sha = new Sha3(Sha3.TYPE_SHA3_256);
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] data2 = new byte[] { 0x05, 0x06, 0x07, 0x08, 0x09 };

        sha.update(data);
        byte[] result = sha.digest();

        /* test reusing existing object after a call to digest() */
        sha.update(data2);
        byte[] result2 = sha.digest();

        assertNotNull(result);
        assertNotNull(result2);
        assertFalse(Arrays.equals(result, result2));

        sha.releaseNativeStruct();
    }

    @Test
    public void copyObject() {
        Sha3 sha = new Sha3(Sha3.TYPE_SHA3_256);
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };

        sha.update(data);

        /* test making copy of Sha3, should retain same state */
        Sha3 shaCopy = (Sha3)sha.clone();

        byte[] result = sha.digest();
        byte[] result2 = shaCopy.digest();

        assertArrayEquals(result, result2);

        sha.releaseNativeStruct();
        shaCopy.releaseNativeStruct();
    }

    @Test
    public void threadedHashTest() throws InterruptedException {
        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();
        final byte[] rand10kBuf = new byte[10240];

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand10kBuf);

        /* generate hash over input data concurrently across numThreads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    Sha3 sha = new Sha3(Sha3.TYPE_SHA3_256);

                    /* process/update in 1024-byte chunks */
                    for (int j = 0; j < rand10kBuf.length; j+= 1024) {
                        sha.update(rand10kBuf, j, 1024);
                    }

                    /* get final hash */
                    byte[] hash = sha.digest();
                    results.add(hash.clone());

                    sha.releaseNativeStruct();
                    latch.countDown();
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<byte[]> listIterator = results.iterator();
        byte[] current = listIterator.next();
        while (listIterator.hasNext()) {
            byte[] next = listIterator.next();
            if (!Arrays.equals(current, next)) {
                fail("Found two non-identical digests in thread test");
            }
            if (listIterator.hasNext()) {
                current = listIterator.next();
            }
        }
    }

    @Test
    public void blockSizeEdgeCases() {
        /* Test vectors for block size edge cases */
        int[] sizes = {
            136,  /* SHA3-224 block size */
            104,  /* SHA3-256 block size */
            72,   /* SHA3-384 block size */
            72    /* SHA3-512 block size */
        };
        int[] types = {
            Sha3.TYPE_SHA3_224,
            Sha3.TYPE_SHA3_256,
            Sha3.TYPE_SHA3_384,
            Sha3.TYPE_SHA3_512
        };

        for (int i = 0; i < sizes.length; i++) {
            /* Test exactly block size */
            byte[] blockData = new byte[sizes[i]];
            Arrays.fill(blockData, (byte)0x61); /* fill with 'a' */
            
            Sha3 sha = new Sha3(types[i]);
            sha.update(blockData);
            byte[] result1 = sha.digest();
            
            /* Test one byte less than block size */
            byte[] underData = new byte[sizes[i] - 1];
            Arrays.fill(underData, (byte)0x61);
            
            sha = new Sha3(types[i]);
            sha.update(underData);
            byte[] result2 = sha.digest();
            
            /* Test one byte more than block size */
            byte[] overData = new byte[sizes[i] + 1];
            Arrays.fill(overData, (byte)0x61);
            
            sha = new Sha3(types[i]);
            sha.update(overData);
            byte[] result3 = sha.digest();
            
            /* Results should all be different */
            assertFalse(Arrays.equals(result1, result2));
            assertFalse(Arrays.equals(result2, result3));
            assertFalse(Arrays.equals(result1, result3));
        }
    }

    @Test
    public void streamingUpdates() {
        /* Test streaming updates with known test vector */
        String input =
            "6162636462636465636465666465666765666768666768696768696A68696A6B" +
            "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071";
        String expected =
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376";
        
        byte[] data = Util.h2b(input);
        
        /* Test different chunk sizes */
        int[] chunks = {1, 3, 7, 13, 17, 32, 64};
        
        for (int chunkSize : chunks) {
            Sha3 sha = new Sha3(Sha3.TYPE_SHA3_256);
            
            /* Update in chunks */
            for (int i = 0; i < data.length; i += chunkSize) {
                int len = Math.min(chunkSize, data.length - i);
                sha.update(data, i, len);
            }
            
            byte[] result = sha.digest();
            assertArrayEquals(Util.h2b(expected), result);
        }
    }
} 

