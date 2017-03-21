/* wolfCryptMacTest.java
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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptMacTest {

    private String wolfJCEAlgos[] = {
        "HmacMD5",
        "HmacSHA1",
        "HmacSHA256",
        "HmacSHA384",
        "HmacSHA512"
    };

    /* expected digest sizes, order must match wolfJCEAlgos */
    private int wolfJCEMacLengths[] = {
        16,
        20,
        32,
        48,
        64
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        /* install wolfJCE provider at runtime */
        Security.addProvider(new WolfCryptProvider());

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);
    }

    @Test
    public void testGetMacFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Mac mac;

        /* try to get all available options we expect to have */
        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            mac = Mac.getInstance(wolfJCEAlgos[i], "wolfJCE");
        }

        /* getting a garbage algorithm should throw an exception */
        try {
            mac = Mac.getInstance("NotValid", "wolfJCE");

            fail("Mac.getInstance should throw NoSuchAlgorithmException " +
                 "when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testMacDigestSizes()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Mac mac;

        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            mac = Mac.getInstance(wolfJCEAlgos[i], "wolfJCE");

            if (mac.getMacLength() != wolfJCEMacLengths[i])
                fail("Expected MAC length did not match, " +
                        "algo = " + wolfJCEAlgos[i]);
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

        for (int i = 0; i < vectors.length; i++) {

            if ((i == 1) && Fips.enabled) {
                /* FIPS doesn't allow short key lengths */
                continue;
            }

            SecretKeySpec keyspec =
                new SecretKeySpec(vectors[i].getKey(), "MD5");

            Mac mac = Mac.getInstance("HmacMD5", "wolfJCE");
            mac.init(keyspec);
            mac.update(vectors[i].getInput());

            byte out[] = mac.doFinal();

            assertArrayEquals(out, vectors[i].getOutput());
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

            Mac mac = Mac.getInstance("HmacSHA1", "wolfJCE");
            mac.init(keyspec);
            mac.update(vectors[i].getInput());

            byte out[] = mac.doFinal();

            assertArrayEquals(out, vectors[i].getOutput());
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

            Mac mac = Mac.getInstance("HmacSHA256", "wolfJCE");
            mac.init(keyspec);
            mac.update(vectors[i].getInput());

            byte out[] = mac.doFinal();

            assertArrayEquals(out, vectors[i].getOutput());
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

            Mac mac = Mac.getInstance("HmacSHA384", "wolfJCE");
            mac.init(keyspec);
            mac.update(vectors[i].getInput());

            byte out[] = mac.doFinal();

            assertArrayEquals(out, vectors[i].getOutput());
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

            Mac mac = Mac.getInstance("HmacSHA512", "wolfJCE");
            mac.init(keyspec);
            mac.update(vectors[i].getInput());

            byte out[] = mac.doFinal();

            assertArrayEquals(out, vectors[i].getOutput());
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

        public void setKey(byte[] key) {
            this.key = key;
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

        public byte[] getInput() {
            return this.input;
        }

        public byte[] getOutput() {
            return this.output;
        }
    }
}

