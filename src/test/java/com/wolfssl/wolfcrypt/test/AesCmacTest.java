/* AesCmacTest.java
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

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.AesCmac;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class AesCmacTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {
        try {
            new AesCmac();
            System.out.println("JNI AesCmac Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("AesCmac test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesCmac().getNativeStruct());
    }

    @Test
    public void aesCmacShouldMatchNistTestVectors() {
        /* NIST SP 800-38B AES-CMAC test vectors */
        String[] keyVector = new String[] {
            "2b7e151628aed2a6abf7158809cf4f3c", /* AES-128 key */
            "2b7e151628aed2a6abf7158809cf4f3c", /* AES-128 key */
            "2b7e151628aed2a6abf7158809cf4f3c", /* AES-128 key */
            "2b7e151628aed2a6abf7158809cf4f3c"  /* AES-128 key */
        };
        String[] dataVector = new String[] {
            "",  /* Empty message */
            "6bc1bee22e409f96e93d7e117393172a", /* Single block */
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411", /* Multi-block */
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710" /* Longer multi-block */
        };
        String[] macVector = new String[] {
            /* Expected MAC for empty message */
            "bb1d6929e95937287fa37d129b756746",
            /* Expected MAC for single block */
            "070a16b46b4d4144f79bdd9dd04a287c",
            /* Expected MAC for multi-block */
            "dfa66747de9ae63030ca32611497c827",
            /* Expected MAC for longer multi-block */
            "51f0bebf7e3b9d92fc49741779363cfe"
        };

        for (int i = 0; i < dataVector.length; i++) {
            try {
                AesCmac cmac = new AesCmac();
                byte[] key = Util.h2b(keyVector[i]);
                byte[] data = (dataVector[i].length() > 0) ?
                    Util.h2b(dataVector[i]) : new byte[0];
                byte[] expected = Util.h2b(macVector[i]);

                cmac.setKey(key);

                if (data.length > 0) {
                    for (byte b : data)
                        cmac.update(b);
                } else {
                    /* Empty message test */
                }

                byte[] result = cmac.doFinal();
                assertArrayEquals("Test vector " + i + " failed",
                    expected, result);

                /* Test reset and doFinal with data */
                cmac.setKey(key);
                byte[] result2 = cmac.doFinal(data);
                assertArrayEquals("Test vector " + i + " reset test failed",
                    expected, result2);

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("AesCmac test skipped: " + e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void aesCmacByteBufferShouldWork() {
        try {
            ByteBuffer buffer = ByteBuffer.allocateDirect(128);
            String key = "2b7e151628aed2a6abf7158809cf4f3c";
            String data = "6bc1bee22e409f96e93d7e117393172a";
            String expected = "070a16b46b4d4144f79bdd9dd04a287c";

            byte[] keyBytes = Util.h2b(key);
            byte[] dataBytes = Util.h2b(data);
            byte[] expectedBytes = Util.h2b(expected);

            buffer.put(dataBytes);
            buffer.flip();

            AesCmac cmac = new AesCmac();
            cmac.setKey(keyBytes);
            cmac.update(buffer);

            byte[] result = cmac.doFinal();
            assertArrayEquals(expectedBytes, result);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac ByteBuffer test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacStaticMethodsShouldWork() {
        try {
            String key = "2b7e151628aed2a6abf7158809cf4f3c";
            String data = "6bc1bee22e409f96e93d7e117393172a";
            String expected = "070a16b46b4d4144f79bdd9dd04a287c";

            byte[] keyBytes = Util.h2b(key);
            byte[] dataBytes = Util.h2b(data);
            byte[] expectedBytes = Util.h2b(expected);

            /* Test generate static method */
            byte[] result = AesCmac.generate(dataBytes, keyBytes);
            assertArrayEquals(expectedBytes, result);

            /* Test verify static method */
            assertTrue(AesCmac.verify(expectedBytes, dataBytes, keyBytes));

            /* Test verify with wrong MAC */
            byte[] wrongMac = new byte[16];
            assertFalse(AesCmac.verify(wrongMac, dataBytes, keyBytes));

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac static methods test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacAlgorithmInfoShouldWork() {
        try {
            String key = "2b7e151628aed2a6abf7158809cf4f3c";
            byte[] keyBytes = Util.h2b(key);

            AesCmac cmac = new AesCmac();
            cmac.setKey(keyBytes);

            assertEquals("AES-CMAC", cmac.getAlgorithm());
            assertEquals(Aes.BLOCK_SIZE, cmac.getMacLength());

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac algorithm info test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacPartialUpdateShouldWork() {
        try {
            String key = "2b7e151628aed2a6abf7158809cf4f3c";
            String data = "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411";
            String expected = "dfa66747de9ae63030ca32611497c827";

            byte[] keyBytes = Util.h2b(key);
            byte[] dataBytes = Util.h2b(data);
            byte[] expectedBytes = Util.h2b(expected);

            AesCmac cmac = new AesCmac();
            cmac.setKey(keyBytes);

            /* Update with partial data */
            cmac.update(dataBytes, 0, 16);
            cmac.update(dataBytes, 16, 16);
            cmac.update(dataBytes, 32, dataBytes.length - 32);

            byte[] result = cmac.doFinal();
            assertArrayEquals(expectedBytes, result);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac partial update test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacThreadedAccessShouldWork() throws Exception {

        final int numThreads = 5;
        final ExecutorService service =
            Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Object> results = new LinkedBlockingQueue<>();
        final String key = "2b7e151628aed2a6abf7158809cf4f3c";
        final String data = "6bc1bee22e409f96e93d7e117393172a";
        final String expected = "070a16b46b4d4144f79bdd9dd04a287c";

        /* Use static methods instead of instance methods to avoid
         * potential threading issues with object lifecycle */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        byte[] keyBytes = Util.h2b(key);
                        byte[] dataBytes = Util.h2b(data);
                        byte[] expectedBytes = Util.h2b(expected);

                        /* Use static method instead of instance methods */
                        byte[] result = AesCmac.generate(dataBytes, keyBytes);

                        if (Arrays.equals(expectedBytes, result)) {
                            results.add("success");
                        } else {
                            results.add("failure");
                        }
                    } catch (Exception e) {
                        results.add(e);
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        service.shutdown();

        Iterator<Object> i = results.iterator();
        while (i.hasNext()) {
            Object result = i.next();
            if (result instanceof Exception) {
                if (result instanceof WolfCryptException) {
                    if (((WolfCryptException) result).getError() ==
                        WolfCryptError.NOT_COMPILED_IN) {
                        System.out.println("AesCmac threaded test skipped: " +
                            ((WolfCryptException) result).getError());
                        return;
                    }
                }
                throw (Exception) result;
            } else {
                assertEquals("success", result);
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void aesCmacShouldThrowOnUpdateBeforeSetKey() {
        try {
            AesCmac cmac = new AesCmac();
            cmac.update((byte) 0x00);
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac exception test skipped: " +
                    e.getError());
                throw new IllegalStateException("Skipped");
            } else {
                throw e;
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void aesCmacShouldThrowOnDoFinalBeforeSetKey() {
        try {
            AesCmac cmac = new AesCmac();
            cmac.doFinal();
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac exception test skipped: " +
                    e.getError());
                throw new IllegalStateException("Skipped");
            } else {
                throw e;
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void aesCmacShouldThrowOnGetAlgorithmBeforeSetKey() {
        try {
            AesCmac cmac = new AesCmac();
            cmac.getAlgorithm();
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac exception test skipped: " +
                    e.getError());
                throw new IllegalStateException("Skipped");
            } else {
                throw e;
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void aesCmacShouldThrowOnGetMacLengthBeforeSetKey() {
        try {
            AesCmac cmac = new AesCmac();
            cmac.getMacLength();
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac exception test skipped: " +
                    e.getError());
                throw new IllegalStateException("Skipped");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacShouldWorkWithDifferentKeySizes() {
        try {
            /* Test with AES-128, AES-192, and AES-256 keys */
            String[] keys = {
                /* 128-bit */
                "2b7e151628aed2a6abf7158809cf4f3c",
                /* 192-bit */
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                /* 256-bit */
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d7" +
                "2d9810a30914dff4"
            };
            String data = "6bc1bee22e409f96e93d7e117393172a";

            for (String keyHex : keys) {
                AesCmac cmac = new AesCmac();
                byte[] key = Util.h2b(keyHex);
                byte[] dataBytes = Util.h2b(data);

                cmac.setKey(key);
                cmac.update(dataBytes);
                byte[] result = cmac.doFinal();

                /* Should produce 16-byte result regardless of key size */
                assertEquals("MAC length incorrect for key size " + key.length,
                    Aes.BLOCK_SIZE, result.length);
            }

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac key size test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacShouldHandleEmptyData() {
        try {
            String key = "2b7e151628aed2a6abf7158809cf4f3c";
            byte[] keyBytes = Util.h2b(key);
            byte[] emptyData = new byte[0];

            AesCmac cmac = new AesCmac();
            cmac.setKey(keyBytes);

            /* Test empty update */
            cmac.update(emptyData);
            byte[] result1 = cmac.doFinal();
            assertEquals(Aes.BLOCK_SIZE, result1.length);

            /* Test doFinal with empty data */
            cmac.setKey(keyBytes);
            byte[] result2 = cmac.doFinal(emptyData);
            assertArrayEquals("Empty data results should match",
                result1, result2);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac empty data test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacShouldHandleByteArrayUpdateVariants() {
        try {
            String key = "2b7e151628aed2a6abf7158809cf4f3c";
            String data = "6bc1bee22e409f96e93d7e117393172a";
            byte[] keyBytes = Util.h2b(key);
            byte[] dataBytes = Util.h2b(data);

            /* Test update(byte[]) */
            AesCmac cmac1 = new AesCmac();
            cmac1.setKey(keyBytes);
            cmac1.update(dataBytes);
            byte[] result1 = cmac1.doFinal();

            /* Test update(byte[], 0, length) */
            AesCmac cmac2 = new AesCmac();
            cmac2.setKey(keyBytes);
            cmac2.update(dataBytes, 0, dataBytes.length);
            byte[] result2 = cmac2.doFinal();

            /* Results should be identical */
            assertArrayEquals(
                "Different update methods should produce same result",
                result1, result2);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac update variants test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacShouldHandleObjectReuse() {
        try {
            String key1 = "2b7e151628aed2a6abf7158809cf4f3c";
            String key2 = "603deb1015ca71be2b73aef0857d7781" +
                          "1f352c073b6108d72d9810a30914dff4";
            String data = "6bc1bee22e409f96e93d7e117393172a";

            byte[] key1Bytes = Util.h2b(key1);
            byte[] key2Bytes = Util.h2b(key2);
            byte[] dataBytes = Util.h2b(data);

            AesCmac cmac = new AesCmac();

            /* First use */
            cmac.setKey(key1Bytes);
            cmac.update(dataBytes);
            byte[] result1 = cmac.doFinal();

            /* Reuse with different key */
            cmac.setKey(key2Bytes);
            cmac.update(dataBytes);
            byte[] result2 = cmac.doFinal();

            /* Results should be different */
            assertFalse("Different keys should produce different results",
                Arrays.equals(result1, result2));

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac object reuse test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesCmacStaticMethodsShouldHandleEdgeCases() {
        try {
            String key = "2b7e151628aed2a6abf7158809cf4f3c";
            byte[] keyBytes = Util.h2b(key);
            byte[] emptyData = new byte[0];

            /* Test generate with empty data */
            byte[] result = AesCmac.generate(emptyData, keyBytes);
            assertEquals(Aes.BLOCK_SIZE, result.length);

            /* Test verify with empty data */
            assertTrue("Empty data verification should succeed",
                AesCmac.verify(result, emptyData, keyBytes));

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesCmac static edge cases test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }
}
