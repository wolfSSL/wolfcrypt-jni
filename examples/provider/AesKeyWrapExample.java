/* AesKeyWrapExample.java
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

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Example demonstrating AES Key Wrap (RFC 3394 / NIST SP 800-38F KW).
 *
 * This example:
 *   1. Checks a wolfJCE "AESWrap" wrap against the RFC 3394 4.1 vector.
 *   2. Wraps and unwraps an AES-128 content key under an AES-256 key
 *      encryption key (KEK) with Cipher.WRAP_MODE / UNWRAP_MODE.
 *   3. Does the same with an explicit 8-byte IV (integrity check value).
 *   4. Uses "AES/KW/PKCS5Padding" to wrap an EC public key, whose X.509
 *      encoding is not a multiple of 8 bytes.
 *
 * Native wolfSSL must be built with --enable-aeskeywrap (or --enable-all).
 */
public class AesKeyWrapExample {

    private static String hex(byte[] in) {

        StringBuilder sb = new StringBuilder();

        for (byte b : in) {
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    private static byte[] h2b(String s) {

        byte[] out = new byte[s.length() / 2];

        for (int i = 0; i < out.length; i++) {
            out[i] = (byte)Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }

        return out;
    }

    public static void main(String[] args) throws Exception {

        Cipher wrap;

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        System.out.println("=======================================");
        System.out.println("AES Key Wrap (RFC 3394) wolfJCE example");
        System.out.println("=======================================");

        try {
            wrap = Cipher.getInstance("AESWrap", "wolfJCE");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("AES Key Wrap is not compiled into native " +
                "wolfSSL, rebuild with --enable-aeskeywrap (or --enable-all).");
            return;
        }

        /* 1. RFC 3394 Section 4.1 known answer */
        SecretKeySpec kek128 = new SecretKeySpec(
            h2b("000102030405060708090A0B0C0D0E0F"), "AES");
        SecretKeySpec data128 = new SecretKeySpec(
            h2b("00112233445566778899AABBCCDDEEFF"), "AES");
        byte[] expected = h2b(
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

        wrap.init(Cipher.WRAP_MODE, kek128);
        byte[] wrapped = wrap.wrap(data128);
        System.out.println("\nRFC 3394 4.1 vector:");
        System.out.println("  wrapped  = " + hex(wrapped));
        System.out.println("  expected = " + hex(expected));
        System.out.println("  match    = " + Arrays.equals(expected, wrapped));
        if (!Arrays.equals(expected, wrapped)) {
            throw new RuntimeException("RFC 3394 vector mismatch");
        }

        /* 2. Wrap a generated AES-128 key under a generated AES-256 KEK */
        KeyGenerator kg = KeyGenerator.getInstance("AES", "wolfJCE");
        kg.init(256);
        SecretKey kek = kg.generateKey();
        kg.init(128);
        SecretKey contentKey = kg.generateKey();

        wrap.init(Cipher.WRAP_MODE, kek);
        wrapped = wrap.wrap(contentKey);

        Cipher unwrap = Cipher.getInstance("AESWrap", "wolfJCE");
        unwrap.init(Cipher.UNWRAP_MODE, kek);
        Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        System.out.println("\nAES-256 KEK wrapping an AES-128 key:");
        System.out.println("  content key = " + hex(contentKey.getEncoded()));
        System.out.println("  wrapped     = " + hex(wrapped) + " (" +
            wrapped.length + " bytes)");
        System.out.println("  unwrapped   = " + hex(recovered.getEncoded()));
        System.out.println("  match       = " +
            Arrays.equals(contentKey.getEncoded(), recovered.getEncoded()));

        /* 3. Explicit IV (integrity check value), must match on both sides */
        IvParameterSpec iv = new IvParameterSpec(h2b("0011223344556677"));

        wrap.init(Cipher.WRAP_MODE, kek, iv);
        byte[] wrappedIv = wrap.wrap(contentKey);
        unwrap.init(Cipher.UNWRAP_MODE, kek, iv);
        Key recoveredIv = unwrap.unwrap(wrappedIv, "AES", Cipher.SECRET_KEY);

        System.out.println("\nWith explicit IV " + hex(iv.getIV()) + ":");
        System.out.println("  wrapped     = " + hex(wrappedIv));
        System.out.println("  match       = " +
            Arrays.equals(contentKey.getEncoded(), recoveredIv.getEncoded()));

        unwrap.init(Cipher.UNWRAP_MODE, kek);
        try {
            unwrap.unwrap(wrappedIv, "AES", Cipher.SECRET_KEY);
            System.out.println("  ERROR: default IV unwrapped IV data");
        } catch (java.security.InvalidKeyException e) {
            System.out.println("  unwrap with default IV rejected: " +
                e.getMessage());
        }

        /* 4. AES/KW/PKCS5Padding for encodings not a multiple of 8 bytes */
        try {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            PublicKey pub = kp.getPublic();

            Cipher padWrap =
                Cipher.getInstance("AES/KW/PKCS5Padding", "wolfJCE");
            padWrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrappedPub = padWrap.wrap(pub);

            Cipher padUnwrap =
                Cipher.getInstance("AES/KW/PKCS5Padding", "wolfJCE");
            padUnwrap.init(Cipher.UNWRAP_MODE, kek);
            Key pubOut = padUnwrap.unwrap(wrappedPub, "EC", Cipher.PUBLIC_KEY);

            System.out.println("\nAES/KW/PKCS5Padding wrapping an EC " +
                "public key:");
            System.out.println("  X.509 encoding " + pub.getEncoded().length +
                " bytes -> wrapped " + wrappedPub.length + " bytes");
            System.out.println("  match       = " +
                Arrays.equals(pub.getEncoded(), pubOut.getEncoded()));

        } catch (NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException e) {
            System.out.println("\nSkipping AES/KW/PKCS5Padding public " +
                "key example: " + e.getMessage());
        }

        System.out.println("\nDone.");
    }
}
