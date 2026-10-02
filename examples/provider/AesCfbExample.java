/* AesCfbExample.java
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

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Example demonstrating AES-CFB encryption and decryption using wolfJCE.
 *
 * This example:
 *
 *   1. Encrypts and decrypts a message with AES/CFB/NoPadding (128-bit
 *      feedback) using a random AES-256 key and random 16-byte IV.
 *   2. Repeats the operation as a stream, feeding data to the Cipher in small
 *      update() chunks. CFB is a stream mode, so input does not need to be
 *      block aligned and output length equals input length.
 *   3. Runs the same message through AES/CFB8/NoPadding (8-bit feedback).
 *
 * Native wolfSSL must be built with AES-CFB support (--enable-aescfb, included
 * with --enable-all). If not compiled in, this example exits cleanly.
 */
public class AesCfbExample {

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {

        /* Install wolfJCE as the highest-priority provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        try {
            Cipher.getInstance("AES/CFB/NoPadding", "wolfJCE");
        } catch (Exception e) {
            System.out.println("AES-CFB not available in this wolfJCE build.");
            System.out.println("Rebuild native wolfSSL with AES-CFB support " +
                "(e.g. --enable-aescfb or --enable-all).");
            return;
        }

        byte[] message =
            "Hello AES-CFB from wolfJCE! Stream modes need no padding."
            .getBytes(StandardCharsets.UTF_8);

        /* Generate a random AES-256 key and a random 16-byte IV. The IV must
         * be unique per encryption under the same key. Steps 1 and 2 share
         * one IV only to show that chunked update() calls reproduce the
         * one-shot ciphertext, step 3 uses a fresh IV. */
        KeyGenerator kg = KeyGenerator.getInstance("AES", "wolfJCE");
        kg.init(256);
        SecretKey key = kg.generateKey();

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        System.out.println("plaintext  (" + message.length + " bytes): " +
            new String(message, StandardCharsets.UTF_8));

        /* 1. One-shot encrypt and decrypt with AES/CFB/NoPadding */
        Cipher enc = Cipher.getInstance("AES/CFB/NoPadding", "wolfJCE");
        enc.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ciphertext = enc.doFinal(message);

        System.out.println("AES/CFB ciphertext (" + ciphertext.length +
            " bytes): " + toHex(ciphertext));

        Cipher dec = Cipher.getInstance("AES/CFB/NoPadding", "wolfJCE");
        dec.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = dec.doFinal(ciphertext);

        if (!Arrays.equals(message, decrypted)) {
            throw new Exception("AES/CFB decrypted data does not match");
        }
        System.out.println("AES/CFB one-shot decrypt matched plaintext");

        /* 2. Streaming encrypt with update() in 5-byte chunks, then decrypt
         *    one-shot. Chunked output concatenates to the same ciphertext
         *    as the one-shot call above. */
        Cipher stream = Cipher.getInstance("AES/CFB/NoPadding", "wolfJCE");
        stream.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] streamed = new byte[message.length];
        int outIdx = 0;
        for (int i = 0; i < message.length; i += 5) {
            int sz = Math.min(5, message.length - i);
            byte[] part = stream.update(message, i, sz);
            if (part != null) {
                System.arraycopy(part, 0, streamed, outIdx, part.length);
                outIdx += part.length;
            }
        }
        byte[] fin = stream.doFinal();
        if (fin != null) {
            System.arraycopy(fin, 0, streamed, outIdx, fin.length);
        }

        if (!Arrays.equals(ciphertext, streamed)) {
            throw new Exception("streamed ciphertext does not match");
        }
        System.out.println("AES/CFB streaming update() matched one-shot");

        /* 3. Same message through AES/CFB8/NoPadding (8-bit feedback). */
        Cipher enc8;
        try {
            enc8 = Cipher.getInstance("AES/CFB8/NoPadding", "wolfJCE");
        } catch (NoSuchAlgorithmException e) {
            System.out.println(
                "AES-CFB8 not available in this build, skipping.");
            return;
        }
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec8 = new IvParameterSpec(iv);
        enc8.init(Cipher.ENCRYPT_MODE, key, ivSpec8);
        byte[] ciphertext8 = enc8.doFinal(message);

        System.out.println("AES/CFB8 ciphertext (" + ciphertext8.length +
            " bytes): " + toHex(ciphertext8));

        Cipher dec8 = Cipher.getInstance("AES/CFB8/NoPadding", "wolfJCE");
        dec8.init(Cipher.DECRYPT_MODE, key, ivSpec8);

        if (!Arrays.equals(message, dec8.doFinal(ciphertext8))) {
            throw new Exception("AES/CFB8 decrypted data does not match");
        }
        System.out.println("AES/CFB8 decrypt matched plaintext");
    }
}
