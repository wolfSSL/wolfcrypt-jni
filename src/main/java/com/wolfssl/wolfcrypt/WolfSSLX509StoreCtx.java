/* WolfSSLX509StoreCtx.java
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

package com.wolfssl.wolfcrypt;

/**
 * Wrapper class for native WOLFSSL_X509_STORE and WOLFSSL_X509_STORE_CTX.
 *
 * @author wolfSSL
 */
public class WolfSSLX509StoreCtx implements AutoCloseable {

    private boolean active = false;
    private long storePtr = 0;

    /* Lock around active state */
    private final Object stateLock = new Object();

    /* Lock around native pointer use */
    private final Object storeLock = new Object();

    private static native long wolfSSL_X509_STORE_new();
    private static native void wolfSSL_X509_STORE_free(long store);
    private static native int wolfSSL_X509_STORE_add_cert(long store,
        byte[] certDer);
    private static native byte[][] wolfSSL_X509_verify_cert_and_get_chain(
        long store, byte[] targetCertDer, byte[][] intermediateCertsDer,
        int maxPathLength) throws WolfCryptException;
    private static native int isCertPathBuilderSupported();

    /**
     * Check if CertPathBuilder functionality is supported.
     *
     * CertPathBuilder requires wolfSSL version 5.8.0 or later for proper
     * X509_STORE chain building support.
     *
     * @return true if CertPathBuilder is supported, false otherwise
     */
    public static boolean isSupported() {
        try {
            return (isCertPathBuilderSupported() == 1);
        } catch (UnsatisfiedLinkError e) {
            return false;
        }
    }

    /**
     * Create new WolfSSLX509StoreCtx object.
     *
     * Requires wolfSSL version 5.8.0 or later for proper X509_STORE
     * chain building support.
     *
     * @throws WolfCryptException if unable to create native X509_STORE,
     *         or if wolfSSL version is too old (requires 5.8.0+)
     */
    public WolfSSLX509StoreCtx() throws WolfCryptException {

        storePtr = wolfSSL_X509_STORE_new();
        if (storePtr == 0) {
            throw new WolfCryptException(
                "Failed to create native WOLFSSL_X509_STORE. " +
                "CertPathBuilder requires wolfSSL 5.8.0 or later.");
        }
        this.active = true;
    }

    /**
     * Verify this object is active and not freed.
     *
     * @throws IllegalStateException if object has been freed or is invalid
     */
    private void confirmObjectIsActive() throws IllegalStateException {

        synchronized (stateLock) {
            if (!this.active || this.storePtr == 0) {
                throw new IllegalStateException(
                    "WolfSSLX509StoreCtx object has been freed or is invalid");
            }
        }
    }

    /**
     * Add a certificate to the store.
     *
     * Self-signed certificates added as trust anchors. Non self-signed
     * certificates added as intermediate certificates.
     *
     * @param certDer DER-encoded X.509 certificate
     *
     * @throws IllegalStateException if object has been freed
     * @throws WolfCryptException if unable to add certificate
     */
    public void addCertificate(byte[] certDer)
        throws IllegalStateException, WolfCryptException {

        int ret;

        confirmObjectIsActive();

        if (certDer == null || certDer.length == 0) {
            throw new WolfCryptException("Certificate data is null or empty");
        }

        synchronized (storeLock) {
            ret = wolfSSL_X509_STORE_add_cert(this.storePtr, certDer);
            if (ret != WolfCrypt.SUCCESS) {
                throw new WolfCryptException(
                    "Failed to add certificate to store: " + ret);
            }
        }
    }

    /**
     * Build and verify a certificate chain for the target certificate.
     *
     * @param targetCertDer DER-encoded target certificate
     * @param intermediateCertsDer optional array of additional intermediate
     *                             certificates (can be null). If provided,
     *                             each element must be non-null and non-empty.
     * @param maxPathLength maximum path length constraint, or -1 for unlimited
     *
     * @return array of DER-encoded certificates forming the verified chain,
     *         ordered from target certificate to trust anchor
     *
     * @throws IllegalStateException if object has been freed
     * @throws WolfCryptException if chain building or verification fails,
     *         or if any intermediate certificate is null or empty
     */
    public byte[][] buildAndVerifyChain(byte[] targetCertDer,
        byte[][] intermediateCertsDer, int maxPathLength)
        throws IllegalStateException, WolfCryptException {

        byte[][] chain;

        confirmObjectIsActive();

        if (targetCertDer == null || targetCertDer.length == 0) {
            throw new WolfCryptException(
                "Target certificate data is null or empty");
        }

        /* Validate intermediate certificates if provided */
        if (intermediateCertsDer != null) {
            for (int i = 0; i < intermediateCertsDer.length; i++) {
                if (intermediateCertsDer[i] == null ||
                    intermediateCertsDer[i].length == 0) {
                    throw new WolfCryptException(
                        "Intermediate certificate at index " + i +
                        " is null or empty");
                }
            }
        }

        synchronized (storeLock) {
            chain = wolfSSL_X509_verify_cert_and_get_chain(this.storePtr,
                targetCertDer, intermediateCertsDer, maxPathLength);
        }

        if (chain == null) {
            throw new WolfCryptException(
                "Certificate chain verification failed: native error");
        }

        return chain;
    }

    /**
     * Free native resources associated with this object.
     */
    public void free() {
        synchronized (stateLock) {
            if (this.active) {
                synchronized (storeLock) {
                    try {
                        wolfSSL_X509_STORE_free(this.storePtr);
                    } finally {
                        this.storePtr = 0;
                    }
                }
                this.active = false;
            }
        }
    }

    /**
     * Implements AutoCloseable for use with try-with-resources.
     */
    @Override
    public void close() {
        free();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void finalize() throws Throwable {
        try {
            free();
        } finally {
            super.finalize();
        }
    }
}

