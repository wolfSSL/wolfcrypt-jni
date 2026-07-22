/* MlKemExample.java
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

import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Example demonstrating ML-KEM (FIPS 203) with the wolfJCE provider.
 *
 * For each parameter set (ML-KEM-512/768/1024) this example:
 *   1. Generates an ML-KEM key pair.
 *   2. Encapsulates to the public key and decapsulates with the private key
 *      using the javax.crypto.KEM API, confirming the shared secrets match.
 *   3. Round-trips the keys through X.509/PKCS#8 encodings via KeyFactory.
 *
 * The javax.crypto.KEM API requires JDK 21 or later.
 */
public class MlKemExample {

    public static void main(String[] args) throws Exception {

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        System.out.println("ML-KEM (FIPS 203) wolfJCE example");
        System.out.println("=================================");

        String[] sets = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

        for (String set : sets) {
            System.out.println("\n" + set + ":");

            /* 1. Generate an ML-KEM key pair with wolfJCE. */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(set, "wolfJCE");
            KeyPair kp = kpg.generateKeyPair();
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            System.out.println("  generated key pair, alg=" +
                pub.getAlgorithm() + ", public " +
                pub.getEncoded().length + " bytes (X.509), private " +
                priv.getEncoded().length + " bytes (PKCS#8)");

            /* 2. Encapsulate and decapsulate via the KEM API. */
            KEM kem = KEM.getInstance("ML-KEM", "wolfJCE");

            KEM.Encapsulator enc = kem.newEncapsulator(pub);
            KEM.Encapsulated e = enc.encapsulate();
            SecretKey secretA = e.key();
            byte[] ciphertext = e.encapsulation();

            System.out.println("  encapsulated: ciphertext " +
                ciphertext.length + " bytes, shared secret " +
                secretA.getEncoded().length + " bytes");

            KEM.Decapsulator dec = kem.newDecapsulator(priv);
            SecretKey secretB = dec.decapsulate(ciphertext);

            boolean match = Arrays.equals(secretA.getEncoded(),
                secretB.getEncoded());

            System.out.println("  decapsulated shared secret matches: " +
                match);
            if (!match) {
                throw new RuntimeException("Shared secret mismatch for " + set);
            }

            /* 3. Round-trip the keys through their encoded forms. */
            KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");
            PublicKey pub2 = kf.generatePublic(
                new X509EncodedKeySpec(pub.getEncoded()));
            PrivateKey priv2 = kf.generatePrivate(
                new PKCS8EncodedKeySpec(priv.getEncoded()));
            boolean encOk =
                Arrays.equals(pub.getEncoded(), pub2.getEncoded()) &&
                Arrays.equals(priv.getEncoded(), priv2.getEncoded());

            System.out.println("  KeyFactory X.509/PKCS#8 round-trip: " +
                encOk);
        }

        System.out.println("\nDone.");
    }
}
