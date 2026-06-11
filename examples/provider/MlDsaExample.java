/* MlDsaExample.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Example demonstrating ML-DSA (FIPS 204) signing and verification using the
 * wolfJCE provider.
 *
 * For each of the three ML-DSA parameter sets (ML-DSA-44, ML-DSA-65,
 * ML-DSA-87) this example:
 *
 *   1. Generates a key pair with KeyPairGenerator.
 *   2. Signs a message with Signature (initSign / update / sign).
 *   3. Verifies the signature with Signature (initVerify / update / verify).
 *   4. Confirms a tampered message fails verification.
 *   5. Encodes the public key to X.509 SubjectPublicKeyInfo DER and the
 *      private key to PKCS#8 DER, decodes both back through KeyFactory, and
 *      verifies the round-tripped keys still work.
 *
 * ML-DSA signatures here use the pure FIPS 204 path with an empty context,
 * matching the JDK 24 (JEP 497) "ML-DSA" Signature semantics.
 *
 * Native wolfSSL must be built with ML-DSA support (for example
 * --enable-dilithium, included with --enable-all). If ML-DSA is not compiled
 * into native wolfCrypt, this example prints a notice and exits cleanly.
 */
public class MlDsaExample {

    /* The three FIPS 204 parameter sets, by JDK 24 (JEP 497) name. */
    private static final String[] LEVELS = {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    };

    public static void main(String[] args) throws Exception {

        /* Install wolfJCE as the highest-priority provider at runtime. */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        /* Detect whether ML-DSA is available in this wolfJCE build. If the
         * native library was built without ML-DSA, KeyPairGenerator lookup
         * for "ML-DSA" will fail, so check once up front. */
        try {
            KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
        } catch (Exception e) {
            System.out.println(
                "ML-DSA not available in this wolfJCE build.");
            System.out.println(
                "Rebuild native wolfSSL with ML-DSA support " +
                "(e.g. --enable-dilithium or --enable-all).");
            return;
        }

        byte[] msg = "Everyone gets Friday off.".getBytes();

        System.out.println("wolfJCE ML-DSA (FIPS 204) Example");
        System.out.println("================================");

        for (String level : LEVELS) {
            runLevel(level, msg);
        }

        System.out.println("\nAll ML-DSA examples completed successfully.");
    }

    /**
     * Run the full sign/verify and key-encoding demonstration for a single
     * ML-DSA parameter set.
     *
     * @param level ML-DSA parameter-set name, e.g. "ML-DSA-65"
     * @param msg message bytes to sign and verify
     */
    private static void runLevel(String level, byte[] msg) throws Exception {

        System.out.println("\n[" + level + "]");

        /* 1. Generate an ML-DSA key pair. */
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance(level, "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("  generated key pair");

        /* 2. Sign the message. The "ML-DSA" generic Signature accepts a key
         *    of any parameter set, the per-level name works too. */
        Signature signer = Signature.getInstance("ML-DSA", "wolfJCE");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        System.out.println("  signed message, signature is " +
            sig.length + " bytes");

        /* 3. Verify the signature. */
        Signature verifier = Signature.getInstance("ML-DSA", "wolfJCE");
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        if (!verifier.verify(sig)) {
            throw new Exception(level + ": signature did not verify");
        }
        System.out.println("  signature verified");

        /* 4. A tampered message must NOT verify. */
        byte[] tampered = msg.clone();
        tampered[0] ^= (byte)0x01;
        Signature badVerifier = Signature.getInstance("ML-DSA", "wolfJCE");
        badVerifier.initVerify(kp.getPublic());
        badVerifier.update(tampered);
        if (badVerifier.verify(sig)) {
            throw new Exception(level + ": tampered message verified");
        }
        System.out.println("  tampered message correctly rejected");

        /* 5. Encode keys to DER, decode through KeyFactory, and confirm the
         *    round-tripped keys still verify the original signature. */
        byte[] pubDer = kp.getPublic().getEncoded();
        byte[] privDer = kp.getPrivate().getEncoded();
        System.out.println("  public key X.509 DER is " +
            pubDer.length + " bytes, private key PKCS#8 DER is " +
            privDer.length + " bytes");

        KeyFactory kf = KeyFactory.getInstance(level, "wolfJCE");
        PublicKey decodedPub =
            kf.generatePublic(new X509EncodedKeySpec(pubDer));
        PrivateKey decodedPriv =
            kf.generatePrivate(new PKCS8EncodedKeySpec(privDer));

        Signature reSigner = Signature.getInstance("ML-DSA", "wolfJCE");
        reSigner.initSign(decodedPriv);
        reSigner.update(msg);
        byte[] sig2 = reSigner.sign();

        Signature reVerifier = Signature.getInstance("ML-DSA", "wolfJCE");
        reVerifier.initVerify(decodedPub);
        reVerifier.update(msg);
        if (!reVerifier.verify(sig2)) {
            throw new Exception(
                level + ": re-encoded key signature did not verify");
        }
        System.out.println("  key encode/decode round trip verified");
    }
}
