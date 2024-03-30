/* Pwdbased.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

package com.wolfssl.wolfcrypt;

import java.util.Enumeration;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;

/**
 * Password based key derivation class with wraps native wolfCrypt
 * pwdbased.c/h APIs.
 *
 * @author wolfSSL
 */
public class Pwdbased {

    static native byte[] wc_PKCS12_PBKDF(byte[] passwd, int pLen,
        byte[] salt, int sLen, int iterations, int kLen, int typeH,
        int id);
    static native byte[] wc_PBKDF2(byte[] passwd, int pLen, byte[] salt,
        int sLen, int iterations, int kLen, int hashType);

    /**
     * Create new Pwdbased object.
     *
     * Currently all methods in this class are static, so no initialization
     * logic needed.
     */
    public Pwdbased() {
    }

    /**
     * PKCS#12 PBKDF (Password Based Key Derivation Function).
     *
     * Implements the PBKDF from RFC 7292 Appendix B. This method converts
     * an input password with a concatenated salt into a more secure key,
     * which it returns as output. It allows a user to select any of the
     * supported HMAC hash functions.
     *
     * @param passwd byte array containing the password to use for key
     *        derivation
     * @param salt byte array containing salt to use for key generation
     * @param iterations number of times to process the hash
     * @param kLen desired length of the derived key
     * @param typeH the hashing algorithm to use
     * @param id byte identifier indicating the purpose of the key
     *        generation. It is used to diversify the key output, and should
     *        be assigned as follows:
     *          ID=1: pseudorandom bits are to be used as key material for
     *                performing encryption or decryption
     *          ID=2: pseduorandom bits are to be used as asn IV (Initial
     *                Value) for encryption or decryption.
     *          ID=3: pseudorandom bits are to be used as an integrity key
     *                for MACing.
     *
     * @return new byte[] containing derived key
     *
     * @throws WolfCryptException on native wolfCrypt error
     */
    public static synchronized byte[] PKCS12_PBKDF(byte[] passwd, byte[] salt,
        int iterations, int kLen, int typeH, int id) throws WolfCryptException {

        /* Throws WolfCryptException with error on failure */
        return wc_PKCS12_PBKDF(passwd, passwd.length, salt, salt.length,
                               iterations, kLen, typeH, id);
    }

    /**
     * Implements the PBKDF2 from PKCS#5. This method converts and input
     * password with a concatenated salt into a more secure key,
     * which it returns as output. It allows a user to select any of the
     * supported hash functions.
     *
     * @param passwd byte array containing the password to use for key
     *        derivation, can be null
     * @param salt byte array containing salt to use for key generation
     * @param iterations number of times to process the hash
     * @param kLen desired length of the derived key
     * @param hashType the hashing algorithm to use, from WolfCrypt class and
     *        one of the following:
     *            WolfCrypt.WC_HASH_TYPE_MD5
     *            WolfCrypt.WC_HASH_TYPE_SHA
     *            WolfCrypt.WC_HASH_TYPE_SHA224
     *            WolfCrypt.WC_HASH_TYPE_SHA256
     *            WolfCrypt.WC_HASH_TYPE_SHA384
     *            WolfCrypt.WC_HASH_TYPE_SHA512
     *            WolfCrypt.WC_HASH_TYPE_SHA3_224
     *            WolfCrypt.WC_HASH_TYPE_SHA3_256
     *            WolfCrypt.WC_HASH_TYPE_SHA3_384
     *            WolfCrypt.WC_HASH_TYPE_SHA3_512
     *
     * @return new byte[] containing derived key
     *
     * @throws IllegalArgumentException on invalid arguments
     * @throws WolfCryptException on native wolfCrypt error
     */
    public static synchronized byte[] PBKDF2(byte[] passwd, byte[] salt,
        int iterations, int kLen, int hashType) throws WolfCryptException {

        int passLen = 0;

        if (passwd != null) {
            passLen = passwd.length;
        }

        /* Throws WolfCryptException with error on failure */
        return wc_PBKDF2(passwd, passLen, salt, salt.length,
                         iterations, kLen, hashType);
    }
}

