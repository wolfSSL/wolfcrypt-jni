/* SlhDsaExample.java
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
import com.wolfssl.provider.jce.WolfCryptContextParameterSpec;

/**
 * Example demonstrating SLH-DSA (FIPS 205) sign and verify using wolfJCE.
 *
 * For each demonstrated SLH-DSA parameter set this example:
 *
 *   1. Generates a key pair with KeyPairGenerator.
 *   2. Signs a message with Signature (initSign / update / sign).
 *   3. Verifies the signature with Signature (initVerify / update / verify).
 *   4. Confirms a tampered message fails verification.
 *   5. Encodes the public key to X.509 SubjectPublicKeyInfo DER and the
 *      private key to PKCS#8 DER, decodes both back through KeyFactory, and
 *      verifies the round-tripped keys still work.
 *
 * It then demonstrates the optional FIPS 205 context string via
 * WolfCryptContextParameterSpec.
 *
 * To keep the run quick this example uses the "fast" (f) parameter sets,
 * which have faster signing than the "small" (s) sets. Any of the 12 FIPS 205
 * parameter sets may be substituted. Native wolfSSL must be built with
 * --enable-slhdsa. If SLH-DSA is not compiled into native wolfCrypt, this
 * example prints a notice and exits cleanly.
 */
public class SlhDsaExample {

    /* A representative selection of FIPS 205 parameter sets (fast variants
     * across the SHA2 and SHAKE families and all three security levels). */
    private static final String[] PARAM_SETS = {
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-256f"
    };

    public static void main(String[] args) throws Exception {

        /* Install wolfJCE as the highest-priority provider at runtime. */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        /* Detect whether SLH-DSA is available in this wolfJCE build. */
        try {
            KeyPairGenerator.getInstance("SLH-DSA", "wolfJCE");
        } catch (Exception e) {
            System.out.println(
                "SLH-DSA key gen not available in this wolfJCE build.");
            System.out.println(
                "Rebuild native wolfSSL with SLH-DSA support " +
                "(--enable-slhdsa). Note that a verify-only native build " +
                "(--enable-slhdsa=yes,verify-only) registers only the " +
                "Signature and KeyFactory services, not KeyPairGenerator.");
            return;
        }

        byte[] msg = "Everyone gets Friday off.".getBytes();

        System.out.println("wolfJCE SLH-DSA (FIPS 205) Example");
        System.out.println("=================================");

        for (String set : PARAM_SETS) {
            runParamSet(set, msg);
        }

        contextStringDemo(msg);

        System.out.println("\nAll SLH-DSA examples completed successfully.");
    }

    /**
     * Run the full sign/verify and key-encoding demonstration for a single
     * SLH-DSA parameter set. A parameter set not compiled into the native
     * build is skipped with a notice.
     *
     * @param set SLH-DSA parameter-set name, e.g. "SLH-DSA-SHA2-128f"
     * @param msg message bytes to sign and verify
     */
    private static void runParamSet(String set, byte[] msg) throws Exception {

        System.out.println("\n[" + set + "]");

        KeyPair kp;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(set, "wolfJCE");
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            System.out.println("  skipping, key generation failed (" +
                e.getMessage() + ")");
            return;
        }
        System.out.println("  generated key pair");

        /* 2. Sign the message. The generic "SLH-DSA" Signature accepts a key
         *    of any parameter set, the per-set name works too. */
        Signature signer = Signature.getInstance("SLH-DSA", "wolfJCE");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        System.out.println("  signed message, signature is " +
            sig.length + " bytes");

        /* 3. Verify the signature. */
        Signature verifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        if (!verifier.verify(sig)) {
            throw new Exception(set + ": signature did not verify");
        }
        System.out.println("  signature verified");

        /* 4. A tampered message must not verify. */
        byte[] tampered = msg.clone();
        tampered[0] ^= (byte)0x01;
        Signature badVerifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        badVerifier.initVerify(kp.getPublic());
        badVerifier.update(tampered);
        if (badVerifier.verify(sig)) {
            throw new Exception(set + ": tampered message verified");
        }
        System.out.println("  tampered message correctly rejected");

        /* 5. Encode keys to DER, decode through KeyFactory, and confirm the
         *    round-tripped keys still verify. */
        byte[] pubDer = kp.getPublic().getEncoded();
        byte[] privDer = kp.getPrivate().getEncoded();
        System.out.println("  public key X.509 DER is " +
            pubDer.length + " bytes, private key PKCS#8 DER is " +
            privDer.length + " bytes");

        KeyFactory kf = KeyFactory.getInstance(set, "wolfJCE");
        PublicKey decodedPub =
            kf.generatePublic(new X509EncodedKeySpec(pubDer));
        PrivateKey decodedPriv =
            kf.generatePrivate(new PKCS8EncodedKeySpec(privDer));

        Signature reSigner = Signature.getInstance("SLH-DSA", "wolfJCE");
        reSigner.initSign(decodedPriv);
        reSigner.update(msg);
        byte[] sig2 = reSigner.sign();

        Signature reVerifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        reVerifier.initVerify(decodedPub);
        reVerifier.update(msg);
        if (!reVerifier.verify(sig2)) {
            throw new Exception(
                set + ": re-encoded key signature did not verify");
        }
        System.out.println("  key encode/decode round trip verified");
    }

    /**
     * Demonstrate the optional FIPS 205 context string. A signature made with
     * a given context only verifies when the same context is supplied.
     *
     * @param msg message bytes to sign and verify
     */
    private static void contextStringDemo(byte[] msg) throws Exception {

        String set = "SLH-DSA-SHA2-128f";

        System.out.println("\n[context string demo, " + set + "]");

        KeyPair kp;
        try {
            kp = KeyPairGenerator.getInstance(set, "wolfJCE")
                .generateKeyPair();
        } catch (Exception e) {
            System.out.println("  skipping, key generation failed (" +
                e.getMessage() + ")");
            return;
        }
        byte[] ctx = "my-application-v1".getBytes();

        Signature signer = Signature.getInstance("SLH-DSA", "wolfJCE");
        signer.setParameter(new WolfCryptContextParameterSpec(ctx));
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        System.out.println("  signed with context \"my-application-v1\"");

        /* Same context verifies. */
        Signature okVerifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        okVerifier.setParameter(new WolfCryptContextParameterSpec(ctx));
        okVerifier.initVerify(kp.getPublic());
        okVerifier.update(msg);
        if (!okVerifier.verify(sig)) {
            throw new Exception("context: same-context verify failed");
        }
        System.out.println("  same context verified");

        /* Empty (default) context must not verify. */
        Signature emptyVerifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        emptyVerifier.initVerify(kp.getPublic());
        emptyVerifier.update(msg);
        if (emptyVerifier.verify(sig)) {
            throw new Exception("context: empty-context verify succeeded");
        }
        System.out.println("  empty context correctly rejected");
    }
}
