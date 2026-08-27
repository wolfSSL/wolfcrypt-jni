/* AesXtsExample.java
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

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Example demonstrating AES-XTS (IEEE 1619 / NIST SP 800-38E) with wolfJCE.
 *
 *   - Transformation "AES/XTS/NoPadding".
 *   - The SecretKey is two concatenated AES keys of equal size, the data
 *     key followed by the tweak key: 32 bytes for AES-128-XTS or 64 bytes
 *     for AES-256-XTS. The two halves must differ.
 *   - The 16 byte tweak is passed as the IvParameterSpec. For disk style
 *     use it is the data unit (sector) number as a little-endian 64-bit
 *     value, zero padded.
 *   - Each doFinal() is one data unit. A data unit must be at least 16
 *     bytes, and output length always equals input length, so a partial
 *     last block needs no padding (ciphertext stealing).
 *   - Every data unit needs its own tweak, so init() is called per sector.
 *     A second doFinal() without init() would reuse the previous tweak.
 *
 * This example encrypts and decrypts a few simulated 512 byte sectors,
 * then a data unit that is not a multiple of the block size.
 */
public class AesXtsExample {

    private static final int SECTOR_SIZE = 512;
    private static final int NUM_SECTORS = 4;

    /**
     * Build the XTS tweak for a sector number: little-endian 64-bit value
     * zero padded to 16 bytes, as used by wolfCrypt wc_AesXtsEncryptSector().
     */
    private static IvParameterSpec sectorTweak(long sector) {

        byte[] tweak = new byte[16];

        for (int i = 0; i < Long.BYTES; i++) {
            tweak[i] = (byte)(sector >>> (Byte.SIZE * i));
        }

        return new IvParameterSpec(tweak);
    }

    public static void main(String[] args) throws Exception {

        SecureRandom rand = new SecureRandom();

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        System.out.println("=======================");
        System.out.println("AES-XTS wolfJCE example");
        System.out.println("=======================");

        Cipher cipher = Cipher.getInstance("AES/XTS/NoPadding", "wolfJCE");

        /* AES-256-XTS key: two 32 byte AES-256 keys concatenated. A random
         * 64 byte key has differing halves. */
        byte[] keyBytes = new byte[64];
        rand.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        System.out.println("key: " + keyBytes.length + " byte AES-256-XTS " +
            "key (data key + tweak key)");

        /* 1. Encrypt and decrypt whole sectors, one data unit each, with
         *    the sector number as the tweak. */
        byte[][] plain = new byte[NUM_SECTORS][SECTOR_SIZE];
        byte[][] enc = new byte[NUM_SECTORS][];

        for (int sector = 0; sector < NUM_SECTORS; sector++) {
            rand.nextBytes(plain[sector]);

            cipher.init(Cipher.ENCRYPT_MODE, key, sectorTweak(sector));
            enc[sector] = cipher.doFinal(plain[sector]);

            System.out.println("sector " + sector + ": encrypted " +
                plain[sector].length + " bytes -> " + enc[sector].length +
                " bytes");
        }

        for (int sector = 0; sector < NUM_SECTORS; sector++) {
            cipher.init(Cipher.DECRYPT_MODE, key, sectorTweak(sector));
            byte[] dec = cipher.doFinal(enc[sector]);

            if (!Arrays.equals(plain[sector], dec)) {
                throw new RuntimeException("sector " + sector +
                    " did not decrypt to the original plaintext");
            }
            System.out.println("sector " + sector + ": decrypted OK");
        }

        /* Same plaintext under a different sector number gives different
         * ciphertext, tweak separates data units. */
        cipher.init(Cipher.ENCRYPT_MODE, key, sectorTweak(NUM_SECTORS));
        byte[] other = cipher.doFinal(plain[0]);
        System.out.println("sector 0 data under sector " + NUM_SECTORS +
            " tweak differs: " + !Arrays.equals(enc[0], other));

        /* 2. A data unit that is not a multiple of 16 bytes. No padding is
         *    added, ciphertext stealing keeps the length. Data is fed
         *    through update() then doFinal() as one data unit. */
        byte[] partial = new byte[SECTOR_SIZE + 5];
        rand.nextBytes(partial);

        cipher.init(Cipher.ENCRYPT_MODE, key, sectorTweak(NUM_SECTORS + 1));
        byte[] head = cipher.update(partial, 0, 100);
        byte[] tail = cipher.doFinal(partial, 100, partial.length - 100);

        /* update() may return null when no output is produced yet */
        if (head == null) {
            head = new byte[0];
        }

        byte[] encPartial = new byte[head.length + tail.length];
        System.arraycopy(head, 0, encPartial, 0, head.length);
        System.arraycopy(tail, 0, encPartial, head.length, tail.length);

        System.out.println("partial data unit: " + partial.length +
            " bytes -> " + encPartial.length + " bytes (no padding)");

        cipher.init(Cipher.DECRYPT_MODE, key, sectorTweak(NUM_SECTORS + 1));
        byte[] decPartial = cipher.doFinal(encPartial);

        if (!Arrays.equals(partial, decPartial)) {
            throw new RuntimeException(
                "partial data unit did not decrypt to the original plaintext");
        }
        System.out.println("partial data unit: decrypted OK");

        Arrays.fill(keyBytes, (byte)0);

        System.out.println("\nDone.");
    }
}
