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
 * WolfCrypt exceptions.
 */
public class WolfCryptException extends RuntimeException {

	private static final long serialVersionUID = 142053665132156225L;
    private WolfCryptError error;
    private int code;

	public WolfCryptException(String reason) {
        super(reason);
    }

	public WolfCryptException(int code) {
		super(WolfCryptError.fromInt(code).getDescription());
        
		this.error = WolfCryptError.fromInt(code);
		this.code = code;
    }

    public WolfCryptException(String reason, Throwable cause) {
        super(reason, cause);
    }

    public WolfCryptException(Throwable cause) {
        super(cause);
    }

    public WolfCryptError getError() {
        return this.error;
    }
    
    public int getCode() {
    	return this.code;
    }
}

