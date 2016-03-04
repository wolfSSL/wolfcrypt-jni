/* WolfCryptException.java
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class WolfCryptException extends Exception {

	private static final long serialVersionUID = 142053665132156225L;
    private WolfCryptError error;

	public WolfCryptException(String reason) {
        super(reason);
    }

    public WolfCryptException(String reason, WolfCryptError error) {
        super(reason);
        this.error = error;
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
}

