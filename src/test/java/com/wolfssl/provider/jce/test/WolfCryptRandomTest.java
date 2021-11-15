/* wolfCryptRandomTest.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.BeforeClass;

import java.util.Arrays;

import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptRandomTest {

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        /* install wolfJCE provider at runtime */
        Security.addProvider(new WolfCryptProvider());

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);
    }

    @Test
    public void testGetRandomFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");
    }

    @Test
    public void testNextBytes()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] valuesA = new byte[128];
        byte[] valuesB = new byte[128];

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");

        rand.nextBytes(valuesA);
        for (int i = 0; i < 10; i++) {
            rand.nextBytes(valuesB);

            if(Arrays.equals(valuesA, valuesB))
                fail("SecureRandom generated two equal consecutive arrays");

            valuesA = Arrays.copyOf(valuesB, valuesB.length);
        }
    }

    @Test
    public void testGenerateSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] valuesA = new byte[128];
        byte[] valuesB = new byte[128];

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");

        valuesA = rand.generateSeed(valuesA.length);
        for (int i = 0; i < 10; i++) {
            valuesB = rand.generateSeed(valuesB.length);

            if(Arrays.equals(valuesA, valuesB))
                fail("SecureRandom generated two equal consecutive arrays");

            valuesA = Arrays.copyOf(valuesB, valuesB.length);
        }
    }

    @Test
    public void testGetSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] valuesA = new byte[128];
        byte[] valuesB = new byte[128];

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");

        valuesA = rand.getSeed(valuesA.length);
        for (int i = 0; i < 10; i++) {
            valuesB = rand.getSeed(valuesB.length);

            if(Arrays.equals(valuesA, valuesB))
                fail("SecureRandom generated two equal consecutive arrays");

            valuesA = Arrays.copyOf(valuesB, valuesB.length);
        }
    }

    @Test
    public void testSetSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        long seed = 123456789;

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");
        rand.setSeed(seed);
    }
}

