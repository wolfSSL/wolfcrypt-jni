/* ShakeExample.java
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

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.Shake;

/**
 * Example demonstrating SHAKE-128 and SHAKE-256 (FIPS 202 XOF) with wolfJCE.
 *
 * This example:
 *   1. Hashes a message with the MessageDigest "SHAKE128-256" (32-byte output)
 *      and "SHAKE256-512" (64-byte output), one-shot and with incremental
 *      updates.
 *   2. Resolves the "SHAKE128"/"SHAKE256" and NIST OID aliases.
 *   3. Produces arbitrary-length XOF output with com.wolfssl.wolfcrypt.Shake,
 *      and shows that shorter SHAKE outputs are prefixes of longer ones over
 *      the same input.
 */
public class ShakeExample {

    private static String toHex(byte[] in) {
        StringBuilder sb = new StringBuilder();
        for (byte b : in) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        System.out.println("================================================");
        System.out.println("SHAKE-128 / SHAKE-256 (FIPS 202) wolfJCE example");
        System.out.println("================================================");

        /* SHAKE needs native wolfSSL built with --enable-shake128 and
         * --enable-shake256 (or --enable-all) */
        try {
            MessageDigest.getInstance("SHAKE128-256", "wolfJCE");
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
        } catch (Exception e) {
            System.out.println("SHAKE not available in this wolfJCE build.");
            System.out.println("Rebuild native wolfSSL with " +
                "--enable-shake128 --enable-shake256 (or --enable-all).");
            return;
        }

        byte[] message = "wolfSSL SHAKE example message".getBytes();

        /* 1. Fixed-length JCE MessageDigest algorithms. */
        String[] algos = { "SHAKE128-256", "SHAKE256-512" };

        for (String algo : algos) {
            System.out.println("\n" + algo + ":");

            MessageDigest md = MessageDigest.getInstance(algo, "wolfJCE");
            byte[] oneShot = md.digest(message);

            System.out.println("  digest length: " + md.getDigestLength() +
                " bytes");
            System.out.println("  digest: " + toHex(oneShot));

            /* Incremental updates produce the same digest. */
            for (byte b : message) {
                md.update(b);
            }
            System.out.println("  incremental update matches: " +
                Arrays.equals(oneShot, md.digest()));
        }

        /* 2. Short-name and NIST aliases resolve to same algos. */
        System.out.println("\nAliases:");
        String[][] aliases = {
            { "SHAKE128", "2.16.840.1.101.3.4.2.11" },
            { "SHAKE256", "2.16.840.1.101.3.4.2.12" }
        };

        for (String[] pair : aliases) {
            for (String alias : pair) {
                MessageDigest md =
                    MessageDigest.getInstance(alias, "wolfJCE");
                System.out.println("  " + alias + " resolves, digest " +
                    "length " + md.getDigestLength() + " bytes");
            }
        }

        /* 3. Arbitrary-length XOF output via the JNI Shake class. JCA
         *    MessageDigest API has no way to request a custom XOF output len,
         *    but com.wolfssl.wolfcrypt.Shake does. */
        System.out.println("\nXOF output via com.wolfssl.wolfcrypt.Shake:");

        Shake xof = new Shake(Shake.TYPE_SHAKE_256, 100);
        xof.update(message);
        byte[] out100 = xof.digest();
        xof.releaseNativeStruct();

        System.out.println("  SHAKE-256, 100-byte output:");
        System.out.println("    " + toHex(out100));

        /* Any SHAKE output is a prefix of the same XOF stream, so the 64-byte
         * "SHAKE256-512" digest is a prefix of the 100-byte output above. */
        MessageDigest md =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
        byte[] out64 = md.digest(message);

        System.out.println("  64-byte digest is prefix of 100-byte output: " +
            Arrays.equals(out64, Arrays.copyOf(out100, out64.length)));

        System.out.println("\nDone.");
    }
}
