/* WolfCryptException.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.wolfcrypt;

import com.wolfssl.wolfcrypt.WolfCryptError;

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
		super(WolfCryptError.fromInt(code).getDescription());
        
		this.error = WolfCryptError.fromInt(code);
		this.code = code;
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

