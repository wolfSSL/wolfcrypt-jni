/* WolfSSLCertManagerVerifyCallback.java
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
 * Interface for WOLFSSL_CERT_MANAGER verification callback.
 *
 * This callback is invoked during certificate chain verification to allow
 * custom verification logic, including overriding specific error conditions
 * such as certificate date validation errors.
 *
 * The callback is called for each certificate in the chain during
 * verification when native wolfSSL is compiled with WOLFSSL_ALWAYS_VERIFY_CB
 * (enabled with --enable-jni).
 *
 * For thread safety, each WolfSSLCertManager instance has its own callback.
 * making this thread safe when each thread uses its own CertManager.
 *
 * @author wolfSSL
 */
public interface WolfSSLCertManagerVerifyCallback {

    /**
     * Verify callback invoked during certificate chain verification.
     *
     * This method is called by native wolfSSL during certificate
     * verification. Implementations can inspect the verification status
     * and error code, then decide whether to accept or reject the
     * certificate.
     *
     * Common error codes:
     *   0                        = No error
     *   -150 (ASN_BEFORE_DATE_E) = Certificate not yet valid
     *   -151 (ASN_AFTER_DATE_E)  = Certificate expired
     *   -188 (ASN_NO_SIGNER_E)   = Certificate not signed by trusted CA
     *
     * @param preverify  1 if pre-verification passed, 0 if failed
     * @param error      Error code from verification (0 indicates no error)
     * @param errorDepth Certificate depth in chain (0 = end entity cert)
     * @return 1 to accept the certificate, 0 to reject
     */
    int verify(int preverify, int error, int errorDepth);

    /**
     * Verify callback with certificate DER bytes from store context.
     *
     * This overload passes the DER-encoded certificate being verified,
     * extracted from the native WOLFSSL_X509_STORE_CTX. Implementations
     * can override this method to inspect the actual certificate when it
     * is not available through other means (e.g. trust anchors not in a
     * pre-built map).
     *
     * The default implementation delegates to the 3-arg verify() method,
     * so existing implementations are not broken.
     *
     * @param preverify  1 if pre-verification passed, 0 if failed
     * @param error      Error code from verification (0 indicates no error)
     * @param errorDepth Certificate depth in chain (0 = end entity cert)
     * @param certDer    DER-encoded certificate at errorDepth, or null
     *                   if not available from the store context
     * @return 1 to accept the certificate, 0 to reject
     */
    default int verify(int preverify, int error, int errorDepth,
        byte[] certDer) {
        return verify(preverify, error, errorDepth);
    }
}

