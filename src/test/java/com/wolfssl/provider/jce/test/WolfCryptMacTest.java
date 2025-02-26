/* wolfCryptMacTest.java
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
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.Assume;
import org.junit.BeforeClass;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.test.Util;

public class WolfCryptMacTest {

    private static String wolfJCEAlgos[] = {
        "HmacMD5",
        "HmacSHA1",
        "HmacSHA224",
        "HmacSHA256",
        "HmacSHA384",
        "HmacSHA512",
        "HmacSHA3-224",
        "HmacSHA3-256",
        "HmacSHA3-384",
        "HmacSHA3-512"
    };

    private static ArrayList<String> enabledAlgos =
        new ArrayList<String>();

    /* expected digest sizes, order must match wolfJCEAlgos */
    private static int wolfJCEMacLengths[] = {
        16,
        20,
        28,
        32,
        48,
        64,
        28,
        32,
        48,
        64
    };

    private static ArrayList<Integer> enabledAlgoLengths =
        new ArrayList<Integer>();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptMac Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* populate enabledAlgos, some native features may be
         * compiled out */
        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            try {
                Mac mac = Mac.getInstance(wolfJCEAlgos[i], "wolfJCE");
                assertNotNull(mac);
                enabledAlgos.add(wolfJCEAlgos[i]);
                enabledAlgoLengths.add(wolfJCEMacLengths[i]);
            } catch (NoSuchAlgorithmException e) {
                /* algo not compiled in */
            }
        }
    }

    @Test
    public void testGetMacFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* try to get all available options we expect to have */
        for (int i = 0; i < enabledAlgos.size(); i++) {
            Mac mac = Mac.getInstance(enabledAlgos.get(i), "wolfJCE");
            assertNotNull(mac);
        }

        /* getting a garbage algorithm should throw an exception */
        try {
            Mac.getInstance("NotValid", "wolfJCE");

            fail("Mac.getInstance should throw NoSuchAlgorithmException " +
                 "when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testMacDigestSizes()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Mac mac;

        for (int i = 0; i < enabledAlgos.size(); i++) {
            mac = Mac.getInstance(enabledAlgos.get(i), "wolfJCE");

            if (mac.getMacLength() != enabledAlgoLengths.get(i))
                fail("Expected MAC length did not match, " +
                        "algo = " + enabledAlgos.get(i));
        }
    }

    @Test
    public void testMacMd5SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        HmacVector[] vectors = new HmacVector[] {
            /* HMAC vectors { key, input, output } */
            new HmacVector(
                new byte[] {
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                },
                "Hi There".getBytes(),
                new byte[] {
                    (byte)0x92, (byte)0x94, (byte)0x72, (byte)0x7a,
                    (byte)0x36, (byte)0x38, (byte)0xbb, (byte)0x1c,
                    (byte)0x13, (byte)0xf4, (byte)0x8e, (byte)0xf8,
                    (byte)0x15, (byte)0x8b, (byte)0xfc, (byte)0x9d
                }
            ),
            new HmacVector(
                "Jefe".getBytes(),
                "what do ya want for nothing?".getBytes(),
                new byte[] {
                    (byte)0x75, (byte)0x0c, (byte)0x78, (byte)0x3e,
                    (byte)0x6a, (byte)0xb0, (byte)0xb5, (byte)0x03,
                    (byte)0xea, (byte)0xa8, (byte)0x6e, (byte)0x31,
                    (byte)0x0a, (byte)0x5d, (byte)0xb7, (byte)0x38
                }
            ),
            new HmacVector(
                new byte[] {
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                },
                new byte[] {
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD
                },
                new byte[] {
                    (byte)0x56, (byte)0xbe, (byte)0x34, (byte)0x52,
                    (byte)0x1d, (byte)0x14, (byte)0x4c, (byte)0x88,
                    (byte)0xdb, (byte)0xb8, (byte)0xc7, (byte)0x33,
                    (byte)0xf0, (byte)0xe8, (byte)0xb3, (byte)0xf6
                }
            )
        };

        /* FIPS>v2 does not support HMAC-MD5 in CAST, skip test */
        if (Fips.fipsVersion > 2) {
            Assume.assumeTrue(false);
        }

        for (int i = 0; i < vectors.length; i++) {

            if ((i == 1) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec keyspec =
                new SecretKeySpec(vectors[i].getKey(), "MD5");

            try {
                Mac mac = Mac.getInstance("HmacMD5", "wolfJCE");

                mac.init(keyspec);
                mac.update(vectors[i].getInput());

                byte out[] = mac.doFinal();

                assertArrayEquals(out, vectors[i].getOutput());

            } catch (NoSuchAlgorithmException e) {
                /* skip test if not available */
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testMacSha1SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        HmacVector[] vectors = new HmacVector[] {
            /* HMAC vectors { key, input, output } */
            new HmacVector(
                new byte[] {
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                },
                "Hi There".getBytes(),
                new byte[] {
                    (byte)0xb6, (byte)0x17, (byte)0x31, (byte)0x86,
                    (byte)0x55, (byte)0x05, (byte)0x72, (byte)0x64,
                    (byte)0xe2, (byte)0x8b, (byte)0xc0, (byte)0xb6,
                    (byte)0xfb, (byte)0x37, (byte)0x8c, (byte)0x8e,
                    (byte)0xf1, (byte)0x46, (byte)0xbe, (byte)0x00
                }
            ),
            new HmacVector(
                "Jefe".getBytes(),
                "what do ya want for nothing?".getBytes(),
                new byte[] {
                    (byte)0xef, (byte)0xfc, (byte)0xdf, (byte)0x6a,
                    (byte)0xe5, (byte)0xeb, (byte)0x2f, (byte)0xa2,
                    (byte)0xd2, (byte)0x74, (byte)0x16, (byte)0xd5,
                    (byte)0xf1, (byte)0x84, (byte)0xdf, (byte)0x9c,
                    (byte)0x25, (byte)0x9a, (byte)0x7c, (byte)0x79
                }
            ),
            new HmacVector(
                new byte[] {
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
                },
                new byte[] {
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD
                },
                new byte[] {
                    (byte)0x12, (byte)0x5d, (byte)0x73, (byte)0x42,
                    (byte)0xb9, (byte)0xac, (byte)0x11, (byte)0xcd,
                    (byte)0x91, (byte)0xa3, (byte)0x9a, (byte)0xf4,
                    (byte)0x8a, (byte)0xa1, (byte)0x7b, (byte)0x4f,
                    (byte)0x63, (byte)0xf1, (byte)0x75, (byte)0xd3
                }
            )
        };

        for (int i = 0; i < vectors.length; i++) {

            if ((i == 1) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec keyspec =
                new SecretKeySpec(vectors[i].getKey(), "SHA1");

            try {
                Mac mac = Mac.getInstance("HmacSHA1", "wolfJCE");

                mac.init(keyspec);
                mac.update(vectors[i].getInput());

                byte out[] = mac.doFinal();

                assertArrayEquals(out, vectors[i].getOutput());

            } catch (NoSuchAlgorithmException e) {
                /* skip test if not available */
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testMacSha224SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        HmacVector[] vectors = new HmacVector[] {
            /* HMAC vectors { key, input, output } */
            /* Test vectors match test.c, from RFC 4231 section 4 */
            new HmacVector(
                new byte[] {
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                },
                "Hi There".getBytes(),
                new byte[] {
                    (byte)0x89, (byte)0x6f, (byte)0xb1, (byte)0x12,
                    (byte)0x8a, (byte)0xbb, (byte)0xdf, (byte)0x19,
                    (byte)0x68, (byte)0x32, (byte)0x10, (byte)0x7c,
                    (byte)0xd4, (byte)0x9d, (byte)0xf3, (byte)0x3f,
                    (byte)0x47, (byte)0xb4, (byte)0xb1, (byte)0x16,
                    (byte)0x99, (byte)0x12, (byte)0xba, (byte)0x4f,
                    (byte)0x53, (byte)0x68, (byte)0x4b, (byte)0x22
                }
            ),
            new HmacVector(
                "Jefe".getBytes(),
                "what do ya want for nothing?".getBytes(),
                new byte[] {
                    (byte)0xa3, (byte)0x0e, (byte)0x01, (byte)0x09,
                    (byte)0x8b, (byte)0xc6, (byte)0xdb, (byte)0xbf,
                    (byte)0x45, (byte)0x69, (byte)0x0f, (byte)0x3a,
                    (byte)0x7e, (byte)0x9e, (byte)0x6d, (byte)0x0f,
                    (byte)0x8b, (byte)0xbe, (byte)0xa2, (byte)0xa3,
                    (byte)0x9e, (byte)0x61, (byte)0x48, (byte)0x00,
                    (byte)0x8f, (byte)0xd0, (byte)0x5e, (byte)0x44
                }
            ),
            new HmacVector(
                new byte[] {
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
                },
                new byte[] {
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD
                },
                new byte[] {
                    (byte)0x7f, (byte)0xb3, (byte)0xcb, (byte)0x35,
                    (byte)0x88, (byte)0xc6, (byte)0xc1, (byte)0xf6,
                    (byte)0xff, (byte)0xa9, (byte)0x69, (byte)0x4d,
                    (byte)0x7d, (byte)0x6a, (byte)0xd2, (byte)0x64,
                    (byte)0x93, (byte)0x65, (byte)0xb0, (byte)0xc1,
                    (byte)0xf6, (byte)0x5d, (byte)0x69, (byte)0xd1,
                    (byte)0xec, (byte)0x83, (byte)0x33, (byte)0xea
                }
            ),
            new HmacVector(
                new byte[] {
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA
                },
                "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(),
                new byte[] {
                    (byte)0x95, (byte)0xe9, (byte)0xa0, (byte)0xdb,
                    (byte)0x96, (byte)0x20, (byte)0x95, (byte)0xad,
                    (byte)0xae, (byte)0xbe, (byte)0x9b, (byte)0x2d,
                    (byte)0x6f, (byte)0x0d, (byte)0xbc, (byte)0xe2,
                    (byte)0xd4, (byte)0x99, (byte)0xf1, (byte)0x12,
                    (byte)0xf2, (byte)0xd2, (byte)0xb7, (byte)0x27,
                    (byte)0x3f, (byte)0xa6, (byte)0x87, (byte)0x0e
                }
            )
        };

        for (int i = 0; i < vectors.length; i++) {

            if ((i == 1) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec keyspec =
                new SecretKeySpec(vectors[i].getKey(), "SHA224");

            try {
                Mac mac = Mac.getInstance("HmacSHA224", "wolfJCE");

                mac.init(keyspec);
                mac.update(vectors[i].getInput());

                byte out[] = mac.doFinal();

                assertArrayEquals(out, vectors[i].getOutput());

            } catch (NoSuchAlgorithmException e) {
                /* skip test if not available */
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testMacSha256SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        HmacVector[] vectors = new HmacVector[] {
            /* HMAC vectors { key, input, output } */
            new HmacVector(
                new byte[] {
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                },
                "Hi There".getBytes(),
                new byte[] {
                    (byte)0xb0, (byte)0x34, (byte)0x4c, (byte)0x61,
                    (byte)0xd8, (byte)0xdb, (byte)0x38, (byte)0x53,
                    (byte)0x5c, (byte)0xa8, (byte)0xaf, (byte)0xce,
                    (byte)0xaf, (byte)0x0b, (byte)0xf1, (byte)0x2b,
                    (byte)0x88, (byte)0x1d, (byte)0xc2, (byte)0x00,
                    (byte)0xc9, (byte)0x83, (byte)0x3d, (byte)0xa7,
                    (byte)0x26, (byte)0xe9, (byte)0x37, (byte)0x6c,
                    (byte)0x2e, (byte)0x32, (byte)0xcf, (byte)0xf7
                }
            ),
            new HmacVector(
                "Jefe".getBytes(),
                "what do ya want for nothing?".getBytes(),
                new byte[] {
                    (byte)0x5b, (byte)0xdc, (byte)0xc1, (byte)0x46,
                    (byte)0xbf, (byte)0x60, (byte)0x75, (byte)0x4e,
                    (byte)0x6a, (byte)0x04, (byte)0x24, (byte)0x26,
                    (byte)0x08, (byte)0x95, (byte)0x75, (byte)0xc7,
                    (byte)0x5a, (byte)0x00, (byte)0x3f, (byte)0x08,
                    (byte)0x9d, (byte)0x27, (byte)0x39, (byte)0x83,
                    (byte)0x9d, (byte)0xec, (byte)0x58, (byte)0xb9,
                    (byte)0x64, (byte)0xec, (byte)0x38, (byte)0x43
                }
            ),
            new HmacVector(
                new byte[] {
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
                },
                new byte[] {
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD
                },
                new byte[] {
                    (byte)0x77, (byte)0x3e, (byte)0xa9, (byte)0x1e,
                    (byte)0x36, (byte)0x80, (byte)0x0e, (byte)0x46,
                    (byte)0x85, (byte)0x4d, (byte)0xb8, (byte)0xeb,
                    (byte)0xd0, (byte)0x91, (byte)0x81, (byte)0xa7,
                    (byte)0x29, (byte)0x59, (byte)0x09, (byte)0x8b,
                    (byte)0x3e, (byte)0xf8, (byte)0xc1, (byte)0x22,
                    (byte)0xd9, (byte)0x63, (byte)0x55, (byte)0x14,
                    (byte)0xce, (byte)0xd5, (byte)0x65, (byte)0xfe
                }
            )
        };

        for (int i = 0; i < vectors.length; i++) {

            if ((i == 1) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec keyspec =
                new SecretKeySpec(vectors[i].getKey(), "SHA256");

            try {
                Mac mac = Mac.getInstance("HmacSHA256", "wolfJCE");

                mac.init(keyspec);
                mac.update(vectors[i].getInput());

                byte out[] = mac.doFinal();

                assertArrayEquals(out, vectors[i].getOutput());

            } catch (NoSuchAlgorithmException e) {
                /* skip test if not available */
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testMacSha384SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        HmacVector[] vectors = new HmacVector[] {
            /* HMAC vectors { key, input, output } */
            new HmacVector(
                new byte[] {
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                },
                "Hi There".getBytes(),
                new byte[] {
                    (byte)0xaf, (byte)0xd0, (byte)0x39, (byte)0x44,
                    (byte)0xd8, (byte)0x48, (byte)0x95, (byte)0x62,
                    (byte)0x6b, (byte)0x08, (byte)0x25, (byte)0xf4,
                    (byte)0xab, (byte)0x46, (byte)0x90, (byte)0x7f,
                    (byte)0x15, (byte)0xf9, (byte)0xda, (byte)0xdb,
                    (byte)0xe4, (byte)0x10, (byte)0x1e, (byte)0xc6,
                    (byte)0x82, (byte)0xaa, (byte)0x03, (byte)0x4c,
                    (byte)0x7c, (byte)0xeb, (byte)0xc5, (byte)0x9c,
                    (byte)0xfa, (byte)0xea, (byte)0x9e, (byte)0xa9,
                    (byte)0x07, (byte)0x6e, (byte)0xde, (byte)0x7f,
                    (byte)0x4a, (byte)0xf1, (byte)0x52, (byte)0xe8,
                    (byte)0xb2, (byte)0xfa, (byte)0x9c, (byte)0xb6
                }
            ),
            new HmacVector(
                "Jefe".getBytes(),
                "what do ya want for nothing?".getBytes(),
                new byte[] {
                    (byte)0xaf, (byte)0x45, (byte)0xd2, (byte)0xe3,
                    (byte)0x76, (byte)0x48, (byte)0x40, (byte)0x31,
                    (byte)0x61, (byte)0x7f, (byte)0x78, (byte)0xd2,
                    (byte)0xb5, (byte)0x8a, (byte)0x6b, (byte)0x1b,
                    (byte)0x9c, (byte)0x7e, (byte)0xf4, (byte)0x64,
                    (byte)0xf5, (byte)0xa0, (byte)0x1b, (byte)0x47,
                    (byte)0xe4, (byte)0x2e, (byte)0xc3, (byte)0x73,
                    (byte)0x63, (byte)0x22, (byte)0x44, (byte)0x5e,
                    (byte)0x8e, (byte)0x22, (byte)0x40, (byte)0xca,
                    (byte)0x5e, (byte)0x69, (byte)0xe2, (byte)0xc7,
                    (byte)0x8b, (byte)0x32, (byte)0x39, (byte)0xec,
                    (byte)0xfa, (byte)0xb2, (byte)0x16, (byte)0x49
                }
            ),
            new HmacVector(
                new byte[] {
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
                },
                new byte[] {
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD
                },
                new byte[] {
                    (byte)0x88, (byte)0x06, (byte)0x26, (byte)0x08,
                    (byte)0xd3, (byte)0xe6, (byte)0xad, (byte)0x8a,
                    (byte)0x0a, (byte)0xa2, (byte)0xac, (byte)0xe0,
                    (byte)0x14, (byte)0xc8, (byte)0xa8, (byte)0x6f,
                    (byte)0x0a, (byte)0xa6, (byte)0x35, (byte)0xd9,
                    (byte)0x47, (byte)0xac, (byte)0x9f, (byte)0xeb,
                    (byte)0xe8, (byte)0x3e, (byte)0xf4, (byte)0xe5,
                    (byte)0x59, (byte)0x66, (byte)0x14, (byte)0x4b,
                    (byte)0x2a, (byte)0x5a, (byte)0xb3, (byte)0x9d,
                    (byte)0xc1, (byte)0x38, (byte)0x14, (byte)0xb9,
                    (byte)0x4e, (byte)0x3a, (byte)0xb6, (byte)0xe1,
                    (byte)0x01, (byte)0xa3, (byte)0x4f, (byte)0x27
                }
            )
        };

        for (int i = 0; i < vectors.length; i++) {

            if ((i == 1) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec keyspec =
                new SecretKeySpec(vectors[i].getKey(), "SHA384");

            try {
                Mac mac = Mac.getInstance("HmacSHA384", "wolfJCE");

                mac.init(keyspec);
                mac.update(vectors[i].getInput());

                byte out[] = mac.doFinal();

                assertArrayEquals(out, vectors[i].getOutput());

            } catch (NoSuchAlgorithmException e) {
                /* skip test if not available */
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testMacSha512SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        HmacVector[] vectors = new HmacVector[] {
            /* HMAC vectors { key, input, output } */
            new HmacVector(
                new byte[] {
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                },
                "Hi There".getBytes(),
                new byte[] {
                    (byte)0x87, (byte)0xaa, (byte)0x7c, (byte)0xde,
                    (byte)0xa5, (byte)0xef, (byte)0x61, (byte)0x9d,
                    (byte)0x4f, (byte)0xf0, (byte)0xb4, (byte)0x24,
                    (byte)0x1a, (byte)0x1d, (byte)0x6c, (byte)0xb0,
                    (byte)0x23, (byte)0x79, (byte)0xf4, (byte)0xe2,
                    (byte)0xce, (byte)0x4e, (byte)0xc2, (byte)0x78,
                    (byte)0x7a, (byte)0xd0, (byte)0xb3, (byte)0x05,
                    (byte)0x45, (byte)0xe1, (byte)0x7c, (byte)0xde,
                    (byte)0xda, (byte)0xa8, (byte)0x33, (byte)0xb7,
                    (byte)0xd6, (byte)0xb8, (byte)0xa7, (byte)0x02,
                    (byte)0x03, (byte)0x8b, (byte)0x27, (byte)0x4e,
                    (byte)0xae, (byte)0xa3, (byte)0xf4, (byte)0xe4,
                    (byte)0xbe, (byte)0x9d, (byte)0x91, (byte)0x4e,
                    (byte)0xeb, (byte)0x61, (byte)0xf1, (byte)0x70,
                    (byte)0x2e, (byte)0x69, (byte)0x6c, (byte)0x20,
                    (byte)0x3a, (byte)0x12, (byte)0x68, (byte)0x54
                }
            ),
            new HmacVector(
                "Jefe".getBytes(),
                "what do ya want for nothing?".getBytes(),
                new byte[] {
                    (byte)0x16, (byte)0x4b, (byte)0x7a, (byte)0x7b,
                    (byte)0xfc, (byte)0xf8, (byte)0x19, (byte)0xe2,
                    (byte)0xe3, (byte)0x95, (byte)0xfb, (byte)0xe7,
                    (byte)0x3b, (byte)0x56, (byte)0xe0, (byte)0xa3,
                    (byte)0x87, (byte)0xbd, (byte)0x64, (byte)0x22,
                    (byte)0x2e, (byte)0x83, (byte)0x1f, (byte)0xd6,
                    (byte)0x10, (byte)0x27, (byte)0x0c, (byte)0xd7,
                    (byte)0xea, (byte)0x25, (byte)0x05, (byte)0x54,
                    (byte)0x97, (byte)0x58, (byte)0xbf, (byte)0x75,
                    (byte)0xc0, (byte)0x5a, (byte)0x99, (byte)0x4a,
                    (byte)0x6d, (byte)0x03, (byte)0x4f, (byte)0x65,
                    (byte)0xf8, (byte)0xf0, (byte)0xe6, (byte)0xfd,
                    (byte)0xca, (byte)0xea, (byte)0xb1, (byte)0xa3,
                    (byte)0x4d, (byte)0x4a, (byte)0x6b, (byte)0x4b,
                    (byte)0x63, (byte)0x6e, (byte)0x07, (byte)0x0a,
                    (byte)0x38, (byte)0xbc, (byte)0xe7, (byte)0x37
                }
            ),
            new HmacVector(
                new byte[] {
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
                },
                new byte[] {
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                    (byte)0xDD, (byte)0xDD
                },
                new byte[] {
                    (byte)0xfa, (byte)0x73, (byte)0xb0, (byte)0x08,
                    (byte)0x9d, (byte)0x56, (byte)0xa2, (byte)0x84,
                    (byte)0xef, (byte)0xb0, (byte)0xf0, (byte)0x75,
                    (byte)0x6c, (byte)0x89, (byte)0x0b, (byte)0xe9,
                    (byte)0xb1, (byte)0xb5, (byte)0xdb, (byte)0xdd,
                    (byte)0x8e, (byte)0xe8, (byte)0x1a, (byte)0x36,
                    (byte)0x55, (byte)0xf8, (byte)0x3e, (byte)0x33,
                    (byte)0xb2, (byte)0x27, (byte)0x9d, (byte)0x39,
                    (byte)0xbf, (byte)0x3e, (byte)0x84, (byte)0x82,
                    (byte)0x79, (byte)0xa7, (byte)0x22, (byte)0xc8,
                    (byte)0x06, (byte)0xb4, (byte)0x85, (byte)0xa4,
                    (byte)0x7e, (byte)0x67, (byte)0xc8, (byte)0x07,
                    (byte)0xb9, (byte)0x46, (byte)0xa3, (byte)0x37,
                    (byte)0xbe, (byte)0xe8, (byte)0x94, (byte)0x26,
                    (byte)0x74, (byte)0x27, (byte)0x88, (byte)0x59,
                    (byte)0xe1, (byte)0x32, (byte)0x92, (byte)0xfb
                }
            )
        };

        for (int i = 0; i < vectors.length; i++) {

            if ((i == 1) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec keyspec =
                new SecretKeySpec(vectors[i].getKey(), "SHA512");

            try {
                Mac mac =
                    Mac.getInstance("HmacSHA512", "wolfJCE");

                mac.init(keyspec);
                mac.update(vectors[i].getInput());

                byte out[] = mac.doFinal();

                assertArrayEquals(out, vectors[i].getOutput());

            } catch (NoSuchAlgorithmException e) {
                /* skip test if not available */
                Assume.assumeTrue(false);
            }
        }
    }

    /**
     * Shared SHA-3 test key and data vectors.
     */
    static final String[] sha3KeyVector = new String[] {
        "4A656665", /* Jefe  */
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0102030405060708010203040506070801020304050607080102030405060708" +
        "0102030405060708010203040506070801020304050607080102030405060708" +
        "0102030405060708010203040506070801020304050607080102030405060708" +
        "0102030405060708010203040506070801020304050607080102030405060708" +
        "0102030405060708010203040506070801020304050607080102030405060708"
    };
    static final String[] sha3DataVector = new String[] {
        /* what do ya want for nothing? */
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        /* Hi There */
        "4869205468657265",
        "dddddddddddddddddddd" +
        "dddddddddddddddddddd" +
        "dddddddddddddddddddd" +
        "dddddddddddddddddddd" +
        "dddddddddddddddddddd",
        /* Big Key Input */
        "426967204b657920496e707574"
    };

    @Test
    public void testMacSha3_224SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        String[] hashVector = new String[] {
            "7fdb8dd88bd2f60d1b798634ad386811" +
            "c2cfc85bfaf5d52bbace5e66",
            "3b16546bbc7be2706a031dcafd56373d" +
            "9884367641d8c59af3c860f7",
            "676cfc7d16153638780390692be142d2" +
            "df7ce924b909c0c08dbfdc1a",
            "29e05e46c4a45e4674bfd72d1ad866db" +
            "2d0d104e2bfaad537d15698b"
        };

        if (!enabledAlgos.contains("HmacSHA3-224")) {
            return;
        }

        Mac mac = Mac.getInstance("HmacSHA3-224", "wolfJCE");

        for (int i = 0; i < hashVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec key = new SecretKeySpec(
                Util.h2b(sha3KeyVector[i]), "HmacSHA3-224");
            mac.init(key);
            mac.update(Util.h2b(sha3DataVector[i]));
            byte[] result = mac.doFinal();

            assertArrayEquals(Util.h2b(hashVector[i]), result);
        }
    }

    @Test
    public void testMacSha3_256SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        String[] hashVector = new String[] {
            "c7d4072e788877ae3596bbb0da73b887" +
            "c9171f93095b294ae857fbe2645e1ba5",
            "ba85192310dffa96e2a3a40e69774351" +
            "140bb7185e1202cdcc917589f95e16bb",
            "84ec79124a27107865cedd8bd82da996" +
            "5e5ed8c37b0ac98005a7f39ed58a4207",
            "b55b8d64b69c21d0bf205ca2f7b9b14e" +
            "8821612c66c391ae6c95168583e6f49b"
        };

        if (!enabledAlgos.contains("HmacSHA3-256")) {
            return;
        }

        Mac mac = Mac.getInstance("HmacSHA3-256", "wolfJCE");

        for (int i = 0; i < hashVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec key = new SecretKeySpec(
                Util.h2b(sha3KeyVector[i]), "HmacSHA3-256");
            mac.init(key);
            mac.update(Util.h2b(sha3DataVector[i]));
            byte[] result = mac.doFinal();

            assertArrayEquals(Util.h2b(hashVector[i]), result);
        }
    }

    @Test
    public void testMacSha3_384SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        String[] hashVector = new String[] {
            "f1101f8cbf9766fd6764d2ed61903f21" +
            "ca9b18f57cf3e1a23ca13508a93243ce" +
            "48c045dc007f26a21b3f5e0e9df4c20a",
            "68d2dcf7fd4ddd0a2240c8a437305f61" +
            "fb7334cfb5d0226e1bc27dc10a2e723a" +
            "20d370b47743130e26ac7e3d532886bd",
            "275cd0e661bb8b151c64d288f1f782fb" +
            "91a8abd56858d72babb2d476f0458373" +
            "b41b6ab5bf174bec422e53fc3135ac6e",
            "aa91b3a62f56a1be8c3e7438db58d9d3" +
            "34dea0606d8d46e0eca9f6063514e6ed" +
            "83e67c77246c11b59082b575da7b832d"
        };

        if (!enabledAlgos.contains("HmacSHA3-384")) {
            return;
        }

        Mac mac = Mac.getInstance("HmacSHA3-384", "wolfJCE");

        for (int i = 0; i < hashVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec key = new SecretKeySpec(
                Util.h2b(sha3KeyVector[i]), "HmacSHA3-384");
            mac.init(key);
            mac.update(Util.h2b(sha3DataVector[i]));
            byte[] result = mac.doFinal();

            assertArrayEquals(Util.h2b(hashVector[i]), result);
        }
    }

    @Test
    public void testMacSha3_512SingleUpdate()
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException {

        String[] hashVector = new String[] {
            "5a4bfeab6166427c7a3647b747292b83" +
            "84537cdb89afb3bf5665e4c5e709350b" +
            "287baec921fd7ca0ee7a0c31d022a95e" +
            "1fc92ba9d77df883960275beb4e62024",
            "eb3fbd4b2eaab8f5c504bd3a41465aac" +
            "ec15770a7cabac531e482f860b5ec7ba" +
            "47ccb2c6f2afce8f88d22b6dc61380f2" +
            "3a668fd3888bb80537c0a0b86407689e",
            "309e99f9ec075ec6c6d475eda1180687" +
            "fcf1531195802a99b5677449a8625182" +
            "851cb332afb6a89c411325fbcbcd42af" +
            "cb7b6e5aab7ea42c660f97fd8584bf03",
            "1cc3a9244a4a3fbdc72000169b794703" +
            "78752cb5f12e627cbeef4e8f0b112b32" +
            "a0eec9d04d64640b37f4dd66f78bb3ad" +
            "52526b6512de0d7cc08b60016c37d7a8"
        };

        if (!enabledAlgos.contains("HmacSHA3-512")) {
            return;
        }

        Mac mac = Mac.getInstance("HmacSHA3-512", "wolfJCE");

        for (int i = 0; i < hashVector.length; i++) {

            if ((i == 0) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec key = new SecretKeySpec(
                Util.h2b(sha3KeyVector[i]), "HmacSHA3-512");
            mac.init(key);
            mac.update(Util.h2b(sha3DataVector[i]));
            byte[] result = mac.doFinal();

            assertArrayEquals(Util.h2b(hashVector[i]), result);
        }
    }

    private void threadRunnerMacTest(String hmacAlgo, String digest,
        HmacVector vector) throws InterruptedException {

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
        final String currentAlgo = hmacAlgo;
        final String mdAlgo = digest;
        final byte[] key = vector.getKey();
        final byte[] input = vector.getInput();
        final byte[] output = vector.getOutput();

        /* Do MAC in parallel across numThreads threads, all ops should pass */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int failed = 0;
                    SecretKeySpec keyspec = null;
                    Mac mac = null;

                    try {
                        keyspec = new SecretKeySpec(key, mdAlgo);
                        mac = Mac.getInstance(currentAlgo, "wolfJCE");

                        mac.init(keyspec);
                        mac.update(input);
                        byte out[] = mac.doFinal();

                        if (!Arrays.equals(out, output)) {
                            failed = 1;
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        failed = 1;

                    } finally {
                        latch.countDown();
                    }

                    if (failed == 1) {
                        results.add(1);
                    }
                    else {
                        results.add(0);
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* Look for any failures that happened */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in MAC thread test: " + currentAlgo);
            }
        }
    }

    @Test
    public void testThreadedMac() throws InterruptedException {

        HmacVector md5Vector = new HmacVector(
            new byte[] {
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
            },
            new byte[] {
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD
            },
            new byte[] {
                (byte)0x56, (byte)0xbe, (byte)0x34, (byte)0x52,
                (byte)0x1d, (byte)0x14, (byte)0x4c, (byte)0x88,
                (byte)0xdb, (byte)0xb8, (byte)0xc7, (byte)0x33,
                (byte)0xf0, (byte)0xe8, (byte)0xb3, (byte)0xf6
            }
        );

        HmacVector sha1Vector = new HmacVector(
            new byte[] {
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
            },
            new byte[] {
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD
            },
            new byte[] {
                (byte)0x12, (byte)0x5d, (byte)0x73, (byte)0x42,
                (byte)0xb9, (byte)0xac, (byte)0x11, (byte)0xcd,
                (byte)0x91, (byte)0xa3, (byte)0x9a, (byte)0xf4,
                (byte)0x8a, (byte)0xa1, (byte)0x7b, (byte)0x4f,
                (byte)0x63, (byte)0xf1, (byte)0x75, (byte)0xd3
            }
        );

        HmacVector sha224Vector = new HmacVector(
            new byte[] {
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
            },
            new byte[] {
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD
            },
            new byte[] {
                (byte)0x7f, (byte)0xb3, (byte)0xcb, (byte)0x35,
                (byte)0x88, (byte)0xc6, (byte)0xc1, (byte)0xf6,
                (byte)0xff, (byte)0xa9, (byte)0x69, (byte)0x4d,
                (byte)0x7d, (byte)0x6a, (byte)0xd2, (byte)0x64,
                (byte)0x93, (byte)0x65, (byte)0xb0, (byte)0xc1,
                (byte)0xf6, (byte)0x5d, (byte)0x69, (byte)0xd1,
                (byte)0xec, (byte)0x83, (byte)0x33, (byte)0xea
            }
        );

        HmacVector sha256Vector = new HmacVector(
            new byte[] {
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
            },
            new byte[] {
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD
            },
            new byte[] {
                (byte)0x77, (byte)0x3e, (byte)0xa9, (byte)0x1e,
                (byte)0x36, (byte)0x80, (byte)0x0e, (byte)0x46,
                (byte)0x85, (byte)0x4d, (byte)0xb8, (byte)0xeb,
                (byte)0xd0, (byte)0x91, (byte)0x81, (byte)0xa7,
                (byte)0x29, (byte)0x59, (byte)0x09, (byte)0x8b,
                (byte)0x3e, (byte)0xf8, (byte)0xc1, (byte)0x22,
                (byte)0xd9, (byte)0x63, (byte)0x55, (byte)0x14,
                (byte)0xce, (byte)0xd5, (byte)0x65, (byte)0xfe
            }
        );

        HmacVector sha384Vector = new HmacVector(
            new byte[] {
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
            },
            new byte[] {
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD
            },
            new byte[] {
                (byte)0x88, (byte)0x06, (byte)0x26, (byte)0x08,
                (byte)0xd3, (byte)0xe6, (byte)0xad, (byte)0x8a,
                (byte)0x0a, (byte)0xa2, (byte)0xac, (byte)0xe0,
                (byte)0x14, (byte)0xc8, (byte)0xa8, (byte)0x6f,
                (byte)0x0a, (byte)0xa6, (byte)0x35, (byte)0xd9,
                (byte)0x47, (byte)0xac, (byte)0x9f, (byte)0xeb,
                (byte)0xe8, (byte)0x3e, (byte)0xf4, (byte)0xe5,
                (byte)0x59, (byte)0x66, (byte)0x14, (byte)0x4b,
                (byte)0x2a, (byte)0x5a, (byte)0xb3, (byte)0x9d,
                (byte)0xc1, (byte)0x38, (byte)0x14, (byte)0xb9,
                (byte)0x4e, (byte)0x3a, (byte)0xb6, (byte)0xe1,
                (byte)0x01, (byte)0xa3, (byte)0x4f, (byte)0x27
            }
        );

        HmacVector sha512Vector = new HmacVector(
            new byte[] {
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
            },
            new byte[] {
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                (byte)0xDD, (byte)0xDD
            },
            new byte[] {
                (byte)0xfa, (byte)0x73, (byte)0xb0, (byte)0x08,
                (byte)0x9d, (byte)0x56, (byte)0xa2, (byte)0x84,
                (byte)0xef, (byte)0xb0, (byte)0xf0, (byte)0x75,
                (byte)0x6c, (byte)0x89, (byte)0x0b, (byte)0xe9,
                (byte)0xb1, (byte)0xb5, (byte)0xdb, (byte)0xdd,
                (byte)0x8e, (byte)0xe8, (byte)0x1a, (byte)0x36,
                (byte)0x55, (byte)0xf8, (byte)0x3e, (byte)0x33,
                (byte)0xb2, (byte)0x27, (byte)0x9d, (byte)0x39,
                (byte)0xbf, (byte)0x3e, (byte)0x84, (byte)0x82,
                (byte)0x79, (byte)0xa7, (byte)0x22, (byte)0xc8,
                (byte)0x06, (byte)0xb4, (byte)0x85, (byte)0xa4,
                (byte)0x7e, (byte)0x67, (byte)0xc8, (byte)0x07,
                (byte)0xb9, (byte)0x46, (byte)0xa3, (byte)0x37,
                (byte)0xbe, (byte)0xe8, (byte)0x94, (byte)0x26,
                (byte)0x74, (byte)0x27, (byte)0x88, (byte)0x59,
                (byte)0xe1, (byte)0x32, (byte)0x92, (byte)0xfb
            }
        );

        if (enabledAlgos.contains("HmacMD5")) {
            threadRunnerMacTest("HmacMD5", "MD5", md5Vector);
        }

        if (enabledAlgos.contains("HmacSHA1")) {
            threadRunnerMacTest("HmacSHA1", "SHA1", sha1Vector);
        }

        if (enabledAlgos.contains("HmacSHA224")) {
            threadRunnerMacTest("HmacSHA224", "SHA224", sha224Vector);
        }

        if (enabledAlgos.contains("HmacSHA256")) {
            threadRunnerMacTest("HmacSHA256", "SHA256", sha256Vector);
        }

        if (enabledAlgos.contains("HmacSHA384")) {
            threadRunnerMacTest("HmacSHA384", "SHA384", sha384Vector);
        }

        if (enabledAlgos.contains("HmacSHA512")) {
            threadRunnerMacTest("HmacSHA512", "SHA512", sha512Vector);
        }


        if (enabledAlgos.contains("HmacSHA3-224")) {
            HmacVector sha3_224Vector = new HmacVector(
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                Util.h2b("4869205468657265"),
                Util.h2b("3b16546bbc7be2706a031dcafd56373d" +
                         "9884367641d8c59af3c860f7")
            );
            threadRunnerMacTest("HmacSHA3-224", "SHA3-224", sha3_224Vector);
        }

        if (enabledAlgos.contains("HmacSHA3-256")) {
            HmacVector sha3_256Vector = new HmacVector(
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                Util.h2b("4869205468657265"),
                Util.h2b("ba85192310dffa96e2a3a40e69774351" +
                         "140bb7185e1202cdcc917589f95e16bb")
            );
            threadRunnerMacTest("HmacSHA3-256", "SHA3-256", sha3_256Vector);
        }

        if (enabledAlgos.contains("HmacSHA3-384")) {
            HmacVector sha3_384Vector = new HmacVector(
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                Util.h2b("4869205468657265"),
                Util.h2b("68d2dcf7fd4ddd0a2240c8a437305f61" +
                         "fb7334cfb5d0226e1bc27dc10a2e723a" +
                         "20d370b47743130e26ac7e3d532886bd")
            );
            threadRunnerMacTest("HmacSHA3-384", "SHA3-384", sha3_384Vector);
        }

        if (enabledAlgos.contains("HmacSHA3-512")) {
            HmacVector sha3_512Vector = new HmacVector(
                Util.h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                Util.h2b("4869205468657265"),
                Util.h2b("eb3fbd4b2eaab8f5c504bd3a41465aac" +
                         "ec15770a7cabac531e482f860b5ec7ba" +
                         "47ccb2c6f2afce8f88d22b6dc61380f2" +
                         "3a668fd3888bb80537c0a0b86407689e")
            );
            threadRunnerMacTest("HmacSHA3-512", "SHA3-512", sha3_512Vector);
        }
    }

    private class HmacVector {

        private byte key[];
        private byte input[];
        private byte output[];

        public HmacVector(byte[] key, byte[] input, byte[] output) {
            this.key = key;
            this.input = input;
            this.output = output;
        }

        public byte[] getKey() {
            return this.key;
        }

        public byte[] getInput() {
            return this.input;
        }

        public byte[] getOutput() {
            return this.output;
        }
    }
}

