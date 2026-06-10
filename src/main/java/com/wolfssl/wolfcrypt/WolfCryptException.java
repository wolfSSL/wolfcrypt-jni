/* WolfCryptException.java
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
 * wolfCrypt exception class
 */
public class WolfCryptException extends RuntimeException {

    private static final long serialVersionUID = 142053665132156225L;
    /** wolfCrypt error for this exception */
    private WolfCryptError error;
    /** wolfCrypt error code for this exception */
    private int code;

    /**
     * Create new WolfCryptException from reason
     *
     * @param reason error reason String
     */
    public WolfCryptException(String reason) {
        super(reason);
    }

    /**
     * Create new WolfCryptException from error code
     *
     * @param code wolfCrypt error code
     */
    public WolfCryptException(int code) {
        super(getErrorMessage(code));

        this.error = WolfCryptError.fromInt(code);
        this.code = code;
    }

    /**
     * Build exception message from error code. For FIPS_NOT_ALLOWED_E
     * errors, queries and appends the current FIPS module status to help
     * diagnose the root cause.
     *
     * @param code wolfCrypt error code
     * @return descriptive error message string
     */
    private static String getErrorMessage(int code) {

        String msg = WolfCryptError.fromInt(code).getDescription();

        /* Get module status for root cause of FIPS not allowed failure */
        if (code == WolfCryptError.FIPS_NOT_ALLOWED_E.getCode()) {
            try {
                if (Fips.enabled) {
                    int status = Fips.wolfCrypt_GetStatus_fips();
                    if (status != 0) {
                        String statusDesc =
                            WolfCryptError.fromInt(status).getDescription();
                        msg += " [FIPS module status: " + status + " (" +
                            statusDesc + ")]";
                    }
                }
            }
            catch (Exception e) {
                /* FIPS status query not available */
            }
        }

        return msg;
    }

    /**
     * Create new WolfCryptException from reason and cause
     *
     * @param reason error reason String
     * @param cause error cause
     */
    public WolfCryptException(String reason, Throwable cause) {
        super(reason, cause);
    }

    /**
     * Create new WolfCryptException from cause
     *
     * @param cause error cause
     */
    public WolfCryptException(Throwable cause) {
        super(cause);
    }

    /**
     * Get WolfCryptError from this exception
     *
     * @return WolfCryptError for this exception
     */
    public WolfCryptError getError() {
        return this.error;
    }

    /**
     * Get wolfCrypt error code from this exception
     *
     * @return wolfCrypt error code
     */
    public int getCode() {
        return this.code;
    }
}

