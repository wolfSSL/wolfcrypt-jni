/* WolfCrypt.java
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Main wrapper for the native WolfCrypt implementation
 */
public class WolfCrypt extends WolfObject {

    /** wolfCrypt SUCCESS code */
    public static final int SUCCESS = 0;
    /** wolfCrypt FAILURE code */
    public static final int FAILURE = -1;

    /** wolfSSL SUCCESS code */
    public static final int WOLFSSL_SUCCESS = 1;

    /** Size of 128 bits in bytes */
    public static final int SIZE_OF_128_BITS = 16;
    /** Size of 160 bits in bytes */
    public static final int SIZE_OF_160_BITS = 20;
    /** Size of 192 bits in bytes */
    public static final int SIZE_OF_192_BITS = 24;
    /** Size of 256 bits in bytes */
    public static final int SIZE_OF_256_BITS = 32;
    /** Size of 384 bits in bytes */
    public static final int SIZE_OF_384_BITS = 48;
    /** Size of 512 bits in bytes */
    public static final int SIZE_OF_512_BITS = 64;
    /** Size of 1024 bits in bytes */
    public static final int SIZE_OF_1024_BITS = 128;
    /** Size of 2048 bits in bytes */
    public static final int SIZE_OF_2048_BITS = 256;

    /** Maximum UTF-8 encoded password size for encrypted PEM conversion */
    public static final int MAX_PEM_PASSWORD_SIZE = 64 * 1024;

    /*
     * Native wolfCrypt hash types, from wolfssl/wolfcrypt/types.h
     * wc_HashType enum.
     */

    /** wolfSSL hash type: None */
    public static final int WC_HASH_TYPE_NONE =
        WolfCrypt.getWC_HASH_TYPE_NONE();

    /** wolfSSL hash type: MD2 */
    public static final int WC_HASH_TYPE_MD2 =
        WolfCrypt.getWC_HASH_TYPE_MD2();

    /** wolfSSL hash type: MD4 */
    public static final int WC_HASH_TYPE_MD4 =
        WolfCrypt.getWC_HASH_TYPE_MD4();

    /** wolfSSL hash type: MD5 */
    public static final int WC_HASH_TYPE_MD5 =
        WolfCrypt.getWC_HASH_TYPE_MD5();

    /** wolfSSL hash type: SHA-1 */
    public static final int WC_HASH_TYPE_SHA =
        WolfCrypt.getWC_HASH_TYPE_SHA();

    /** wolfSSL hash type: SHA-224 */
    public static final int WC_HASH_TYPE_SHA224 =
        WolfCrypt.getWC_HASH_TYPE_SHA224();

    /** wolfSSL hash type: SHA-256 */
    public static final int WC_HASH_TYPE_SHA256 =
        WolfCrypt.getWC_HASH_TYPE_SHA256();

    /** wolfSSL hash type: SHA-384 */
    public static final int WC_HASH_TYPE_SHA384 =
        WolfCrypt.getWC_HASH_TYPE_SHA384();

    /** wolfSSL hash type: SHA-512 */
    public static final int WC_HASH_TYPE_SHA512 =
        WolfCrypt.getWC_HASH_TYPE_SHA512();

    /** wolfSSL hash type: MD5-SHA */
    public static final int WC_HASH_TYPE_MD5_SHA =
        WolfCrypt.getWC_HASH_TYPE_MD5_SHA();

    /** wolfSSL hash type: SHA3-224 */
    public static final int WC_HASH_TYPE_SHA3_224 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_224();

    /** wolfSSL hash type: SHA3-256 */
    public static final int WC_HASH_TYPE_SHA3_256 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_256();

    /** wolfSSL hash type: SHA3-384 */
    public static final int WC_HASH_TYPE_SHA3_384 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_384();

    /** wolfSSL hash type: SHA3-512 */
    public static final int WC_HASH_TYPE_SHA3_512 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_512();

    /** Native JNI function bindings */
    private static native int getWC_HASH_TYPE_NONE();
    private static native int getWC_HASH_TYPE_MD2();
    private static native int getWC_HASH_TYPE_MD4();
    private static native int getWC_HASH_TYPE_MD5();
    private static native int getWC_HASH_TYPE_SHA();
    private static native int getWC_HASH_TYPE_SHA224();
    private static native int getWC_HASH_TYPE_SHA256();
    private static native int getWC_HASH_TYPE_SHA384();
    private static native int getWC_HASH_TYPE_SHA512();
    private static native int getWC_HASH_TYPE_MD5_SHA();
    private static native int getWC_HASH_TYPE_SHA3_224();
    private static native int getWC_HASH_TYPE_SHA3_256();
    private static native int getWC_HASH_TYPE_SHA3_384();
    private static native int getWC_HASH_TYPE_SHA3_512();
    private static native byte[] wcBase16Encode(byte[] input);
    private static native byte[] wcBase16Decode(byte[] input);
    private static native byte[] wcKeyPemToDer(byte[] pem, byte[] password);
    private static native byte[] wcCertPemToDer(byte[] pem);
    private static native byte[] wcPubKeyPemToDer(byte[] pem);
    private static native void nativeSetIOTimeout(int timeoutSec);

    /* Public mappings of some SSL/TLS level enums/defines */
    /** wolfSSL file type: PEM */
    public static final int SSL_FILETYPE_PEM  = 1;
    /** wolfSSL file type: ASN.1/DER */
    public static final int SSL_FILETYPE_ASN1 = 2;

    /**
     * CRL option, will perform CRL checking on each certificate in the
     * chain. Checking only leaf certificate is the default behavior.
     */
    public static final int WOLFSSL_CRL_CHECKALL = 1;

    /**
     * CRL option, will enable CRL checking on leaf certificate.
     */
    public static final int WOLFSSL_CRL_CHECK    = 2;

    /**
     * OCSP option, will use override URL for OCSP requests.
     * Must match native WOLFSSL_OCSP_URL_OVERRIDE value in ssl.h.
     */
    public static final int WOLFSSL_OCSP_URL_OVERRIDE = 1;

    /**
     * OCSP option, will not send nonce in OCSP requests.
     * Must match native WOLFSSL_OCSP_NO_NONCE value in ssl.h.
     */
    public static final int WOLFSSL_OCSP_NO_NONCE = 2;

    /**
     * OCSP option, will perform OCSP checking on each certificate in the
     * chain. Checking only leaf certificate is the default behavior.
     * Must match native WOLFSSL_OCSP_CHECKALL value in ssl.h.
     */
    public static final int WOLFSSL_OCSP_CHECKALL = 4;

    /**
     * Tests if CRL (HAVE_CRL) has been enabled in native wolfCrypt.
     *
     * @return true if enabled, otherwise false if not compiled in
     */
    public static native boolean CrlEnabled();

    /**
     * Tests if OCSP (HAVE_OCSP) has been enabled in native wolfCrypt.
     *
     * @return true if enabled, otherwise false if not compiled in
     */
    public static native boolean OcspEnabled();

    /**
     * Tests if Base16 (WOLFSSL_BASE16) has been enabled in native wolfCrypt.
     *
     * @return true if enabled, otherwise false if not compiled in
     */
    public static native boolean Base16Enabled();

    /**
     * Tests if I/O timeout (HAVE_IO_TIMEOUT) has been enabled in wolfSSL.
     *
     * @return true if enabled, otherwise false if not compiled in
     */
    public static native boolean IoTimeoutEnabled();

    /** Maximum allowed I/O timeout value in seconds (1 hour) */
    private static final int MAX_IO_TIMEOUT_SEC = 3600;

    /**
     * Set the I/O timeout used by native wolfSSL for HTTP-based operations
     * including OCSP lookups and CRL fetching.
     *
     * Wraps native wolfIO_SetTimeout(). Requires native wolfSSL to be
     * compiled with HAVE_IO_TIMEOUT.
     *
     * This sets a global (library-wide) timeout value in native
     * wolfSSL. All threads and certificate validations in the same
     * JVM share this single timeout setting.
     *
     * @param timeoutSec timeout value in seconds, 0 to 3600 inclusive.
     *        A value of 0 disables the timeout (default behavior).
     *
     * @throws WolfCryptException if HAVE_IO_TIMEOUT is not compiled
     *         into native wolfSSL
     * @throws IllegalArgumentException if timeoutSec is negative or
     *         exceeds 3600 seconds
     */
    public static void setIOTimeout(int timeoutSec) {

        if (timeoutSec < 0) {
            throw new IllegalArgumentException(
                "Timeout value must not be negative");
        }

        if (timeoutSec > MAX_IO_TIMEOUT_SEC) {
            throw new IllegalArgumentException(
                "Timeout value must not exceed " +
                MAX_IO_TIMEOUT_SEC + " seconds");
        }

        nativeSetIOTimeout(timeoutSec);
    }

    /**
     * Constant time byte array comparison.
     *
     * If arrays are of different lengths, return false right away. Apart
     * from length check, this matches native wolfSSL ConstantCompare()
     * logic in misc.c.
     *
     * @param a first byte array for comparison
     * @param b second byte array for comparison
     *
     * @return true if equal, otherwise false
     */
    public static boolean ConstantCompare(byte[] a, byte[] b) {

        int i;
        int compareSum = 0;

        if (a.length != b.length) {
            return false;
        }

        for (i = 0; i < a.length; i++) {
            compareSum |= a[i] ^ b[i];
        }

        return (compareSum == 0);
    }

    /**
     * Convert byte array to hexadecimal string representation.
     *
     * Wraps native Base16_Encode() function. Output uses uppercase hex
     * characters (0-9, A-F), which matches native wolfSSL behavior.
     *
     * @param data byte array to encode as hex string
     *
     * @return hexadecimal string representation of input bytes
     *
     * @throws WolfCryptException if encoding fails, input is null,
     *         or native Base16 support is not compiled in
     */
    public static String toHexString(byte[] data) throws WolfCryptException {

        byte[] hexBytes = null;

        if (data == null) {
            throw new WolfCryptException("Input data is null");
        }

        if (data.length == 0) {
            return "";
        }

        hexBytes = wcBase16Encode(data);

        if (hexBytes == null) {
            throw new WolfCryptException("Base16 encoding failed");
        }

        return new String(hexBytes, StandardCharsets.US_ASCII);
    }

    /**
     * Convert hexadecimal string to byte array.
     *
     * Wraps native Base16_Decode() function. Accepts both uppercase (A-F)
     * and lowercase (a-f) hex characters.
     *
     * @param hexStr hexadecimal string to decode
     *
     * @return decoded byte array
     *
     * @throws WolfCryptException if decoding fails, input is null,
     *         input has odd length, contains invalid hex characters, or
     *         native Base16 support is not compiled in
     */
    public static byte[] hexStringToByteArray(String hexStr)
        throws WolfCryptException {

        if (hexStr == null) {
            throw new WolfCryptException("Input hex string is null");
        }

        if (hexStr.length() == 0) {
            return new byte[0];
        }

        if (hexStr.length() % 2 != 0) {
            throw new WolfCryptException(
                "Hex string must have even length");
        }

        return wcBase16Decode(
            hexStr.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Convert private key from PEM to DER format.
     *
     * Wraps native wc_KeyPemToDer() function. The password is passed to
     * native as standard UTF-8 and may not contain a NUL character. A String
     * password cannot be erased from the Java heap after use, callers holding
     * a password should prefer {@link #encryptedKeyPemToDer(byte[], char[])}.
     *
     * @param pem PEM-encoded private key as byte array
     * @param password password for encrypted PEM, or null if unencrypted
     *
     * @return DER-encoded private key as byte array
     *
     * @throws WolfCryptException if conversion fails, input is larger than
     *         the 1 MB maximum PEM size, the password is not valid UTF-16,
     *         native operation encounters an
     *         error, or native ASN/PEM support is not compiled in
     *         (NO_ASN or WOLFSSL_NO_PEM defined)
     */
    public static byte[] keyPemToDer(byte[] pem, String password)
        throws WolfCryptException {

        byte[] pw = null;
        char[] chars = null;

        if (password != null) {
            chars = password.toCharArray();
            try {
                pw = passwordToBytes(chars);
            } finally {
                Arrays.fill(chars, (char)0);
            }
        }

        return keyPemToDerBytes(pem, pw);
    }

    /**
     * Convert a private key from PEM to DER format using a password the
     * caller can erase afterwards. An unencrypted key is accepted with a
     * null password.
     *
     * Wraps native wc_KeyPemToDer() function. The password is encoded as
     * UTF-8, may not contain a NUL character, and temporary copies are zeroed
     * after use. The array passed in is left unchanged so the caller can
     * clear it if desired.
     *
     * @param pem PEM-encoded private key as byte array
     * @param password password for encrypted PEM, or null if unencrypted
     *
     * @return DER-encoded private key as byte array
     *
     * @throws WolfCryptException if conversion fails, input is larger than
     *         the 1 MB maximum PEM size, the password is not valid UTF-16,
     *         native operation encounters an
     *         error, or native ASN/PEM support is not compiled in
     *         (NO_ASN or WOLFSSL_NO_PEM defined)
     */
    public static byte[] encryptedKeyPemToDer(byte[] pem, char[] password)
        throws WolfCryptException {

        return keyPemToDerBytes(pem, passwordToBytes(password));
    }

    /* Shared native call, UTF-8 password bytes are zeroed afterwards */
    private static byte[] keyPemToDerBytes(byte[] pem, byte[] password)
        throws WolfCryptException {

        try {
            if (pem == null || pem.length == 0) {
                throw new WolfCryptException("PEM input is null or empty");
            }

            if (password != null) {
                checkPemPassword(password);
            }

            return wcKeyPemToDer(pem, password);
        }
        finally {
            if (password != null) {
                Arrays.fill(password, (byte)0);
            }
        }
    }

    /* Reject an oversized password or an embedded NUL */
    private static void checkPemPassword(byte[] password)
        throws WolfCryptException {

        if (password.length > MAX_PEM_PASSWORD_SIZE) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }
        for (byte b : password) {
            if (b == 0) {
                throw new WolfCryptException(
                    WolfCryptError.BAD_FUNC_ARG.getCode());
            }
        }
    }

    /* UTF-8 encode a password without creating a String, malformed UTF-16
     * is rejected rather than altered. A null input returns null. */
    private static byte[] passwordToBytes(char[] pass) {

        byte[] out = null;
        ByteBuffer utf8 = null;
        CharsetEncoder encoder = null;

        if (pass == null) {
            return null;
        }

        if (pass.length > MAX_PEM_PASSWORD_SIZE) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }

        encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);

        utf8 = ByteBuffer.allocate(
            (int)Math.ceil(pass.length * (double)encoder.maxBytesPerChar()));

        try {
            /* Sized by maxBytesPerChar(), so anything but underflow means
             * the password is not valid UTF-16 */
            if (!encoder.encode(CharBuffer.wrap(pass), utf8, true).isUnderflow()
                || !encoder.flush(utf8).isUnderflow()) {
                throw new WolfCryptException(
                    "Password is not valid UTF-16, encoding failed");
            }
            utf8.flip();

            out = new byte[utf8.remaining()];
            utf8.get(out);

        } finally {
            /* Encoder buffer holds another copy, wipe it on every exit */
            Arrays.fill(utf8.array(), (byte)0);
        }

        return out;
    }

    /**
     * Convert X.509 certificate from PEM to DER format.
     *
     * Wraps native wc_CertPemToDer() function.
     *
     * @param pem PEM-encoded certificate as byte array
     *
     * @return DER-encoded certificate as byte array
     *
     * @throws WolfCryptException if conversion fails, input is larger than
     *         the 1 MB maximum PEM size, native operation encounters an
     *         error, or native ASN/PEM support is not compiled in
     *         (NO_ASN or WOLFSSL_NO_PEM defined)
     */
    public static byte[] certPemToDer(byte[] pem) throws WolfCryptException {

        if (pem == null || pem.length == 0) {
            throw new WolfCryptException("PEM input is null or empty");
        }

        return wcCertPemToDer(pem);
    }

    /**
     * Convert public key from PEM to DER format.
     *
     * Wraps native wc_PubKeyPemToDer() function.
     *
     * @param pem PEM-encoded public key as byte array
     *
     * @return DER-encoded public key as byte array
     *
     * @throws WolfCryptException if conversion fails, input is larger than
     *         the 1 MB maximum PEM size, native operation encounters an
     *         error, or native ASN/PEM support is not compiled in
     *         (NO_ASN or WOLFSSL_NO_PEM defined)
     */
    public static byte[] pubKeyPemToDer(byte[] pem) throws WolfCryptException {

        if (pem == null || pem.length == 0) {
            throw new WolfCryptException("PEM input is null or empty");
        }

        return wcPubKeyPemToDer(pem);
    }

    private WolfCrypt() {
    }

}

