/* EdDSAExample.java
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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.provider.jce.WolfCryptEdDSAParameterSpec;
import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Example demonstrating Ed25519 and Ed448 (EdDSA, RFC 8032) signing and
 * verification using wolfJCE.
 *
 * For each curve compiled into native wolfSSL this example:
 *
 *   1. Generates a key pair with KeyPairGenerator.
 *   2. Signs a message with Signature (initSign / update / sign).
 *   3. Verifies the signature with Signature (initVerify / update / verify).
 *   4. Confirms a tampered message fails verification.
 *   5. Encodes the public key to X.509 SubjectPublicKeyInfo DER and the
 *      private key to PKCS#8 DER (RFC 8410), decodes both back through
 *      KeyFactory, and verifies the round-tripped keys still work.
 *   6. Signs with a context string and with the pre-hash variant using
 *      WolfCryptEdDSAParameterSpec (on JDK 15+ the JDK's own
 *      java.security.spec.EdDSAParameterSpec is accepted as well).
 *
 * The "EdDSA" Signature and KeyFactory names accept keys of either curve,
 * matching the JDK SunEC provider. "Ed25519" and "Ed448" are curve specific.
 *
 * Native wolfSSL must be built with --enable-ed25519 and/or --enable-ed448
 * (both are included in --enable-all). If a curve is not compiled into
 * native wolfCrypt it is skipped.
 */
public class EdDSAExample {

    private static final String[] CURVES = { "Ed25519", "Ed448" };

    public static void main(String[] args) throws Exception {

        /* Install wolfJCE as the highest-priority provider at runtime. */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        byte[] msg = "Everyone gets Friday off.".getBytes();
        int ran = 0;

        System.out.println("=======================================");
        System.out.println("wolfJCE EdDSA (Ed25519 / Ed448) Example");
        System.out.println("=======================================");

        for (String curve : CURVES) {
            try {
                KeyPairGenerator.getInstance(curve, "wolfJCE");
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                System.out.println("\n[" + curve + "] key generation not " +
                    "available in this wolfJCE build, rebuild native " +
                    "wolfSSL with --enable-" + curve.toLowerCase() +
                    " (or --enable-all)" + (curve.equals("Ed25519") ?
                    " and without NO_ED25519_MAKE_KEY" : ""));
                continue;
            }
            runCurve(curve, msg);
            ran++;
        }

        if (ran == 0) {
            System.out.println("\nNo EdDSA curve available, nothing run.");
        }
        else {
            System.out.println("\nAll EdDSA examples completed successfully.");
        }
    }

    /**
     * Run full sign/verify and key-encoding demonstration for one curve.
     *
     * @param curve "Ed25519" or "Ed448"
     * @param msg message bytes to sign and verify
     */
    private static void runCurve(String curve, byte[] msg) throws Exception {

        System.out.println("\n[" + curve + "]");

        /* Generate a key pair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(curve, "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("  generated key pair");

        /* Sign the message, generic "EdDSA" accepts Ed25519 or Ed448 */
        Signature signer = Signature.getInstance("EdDSA", "wolfJCE");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        System.out.println("  signed message, sig is " + sig.length + " bytes");

        /* Verify signature */
        Signature verifier = Signature.getInstance(curve, "wolfJCE");
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        if (!verifier.verify(sig)) {
            throw new Exception(curve + ": signature did not verify");
        }
        System.out.println("  signature verified");

        /* A tampered message must not verify */
        byte[] tampered = msg.clone();
        tampered[0] ^= (byte)0x01;
        Signature badVerifier = Signature.getInstance(curve, "wolfJCE");
        badVerifier.initVerify(kp.getPublic());
        badVerifier.update(tampered);
        if (badVerifier.verify(sig)) {
            throw new Exception(curve + ": tampered message verified");
        }
        System.out.println("  tampered message correctly rejected");

        /* Encode keys to DER, decode through KeyFactory, and confirm round
         * trip keys still work */
        byte[] pubDer = kp.getPublic().getEncoded();
        byte[] privDer = kp.getPrivate().getEncoded();
        System.out.println("  public key X.509 DER is " +
            pubDer.length + " bytes, private key PKCS#8 DER is " +
            privDer.length + " bytes");

        KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
        PublicKey decodedPub =
            kf.generatePublic(new X509EncodedKeySpec(pubDer));
        PrivateKey decodedPriv =
            kf.generatePrivate(new PKCS8EncodedKeySpec(privDer));

        Signature reSigner = Signature.getInstance(curve, "wolfJCE");
        reSigner.initSign(decodedPriv);
        reSigner.update(msg);
        byte[] sig2 = reSigner.sign();

        Signature reVerifier = Signature.getInstance(curve, "wolfJCE");
        reVerifier.initVerify(decodedPub);
        reVerifier.update(msg);
        if (!reVerifier.verify(sig2)) {
            throw new Exception(
                curve + ": re-encoded key signature did not verify");
        }
        System.out.println("  key encode/decode round trip verified");

        /* Context string and pre-hash variants (RFC 8032 Ed25519ctx /
         * Ed25519ph, Ed448 with context / Ed448ph). Signer and verifier must
         * use the same parameters */
        byte[] context = "example context".getBytes();

        Signature ctxSigner = Signature.getInstance(curve, "wolfJCE");
        ctxSigner.setParameter(new WolfCryptEdDSAParameterSpec(false, context));
        ctxSigner.initSign(kp.getPrivate());
        ctxSigner.update(msg);
        byte[] ctxSig = ctxSigner.sign();

        Signature ctxVerifier = Signature.getInstance(curve, "wolfJCE");
        ctxVerifier.setParameter(new WolfCryptEdDSAParameterSpec(false,
            context));
        ctxVerifier.initVerify(kp.getPublic());
        ctxVerifier.update(msg);
        if (!ctxVerifier.verify(ctxSig)) {
            throw new Exception(curve + ": context signature did not verify");
        }
        System.out.println("  signature with context verified");

        Signature phSigner = Signature.getInstance(curve, "wolfJCE");
        phSigner.setParameter(new WolfCryptEdDSAParameterSpec(true));
        phSigner.initSign(kp.getPrivate());
        phSigner.update(msg);
        byte[] phSig = phSigner.sign();

        Signature phVerifier = Signature.getInstance(curve, "wolfJCE");
        phVerifier.setParameter(new WolfCryptEdDSAParameterSpec(true));
        phVerifier.initVerify(kp.getPublic());
        phVerifier.update(msg);
        if (!phVerifier.verify(phSig)) {
            throw new Exception(curve + ": pre-hash signature did not verify");
        }
        System.out.println("  pre-hash (" + curve + "ph) signature verified");
    }
}
