/* Logging.java
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

/**
 * Wrapper for the native WolfCrypt Logging implementation
 */
public class Logging extends WolfObject {

    /**
     * Turn on native wolfSSL debug logging
     *
     * @return 0 on success, negative on error
     */
    public static native int wolfSSL_Debugging_ON();

    /**
     * Turn off native wolfSSL debug logging
     */
    public static native void wolfSSL_Debugging_OFF();

    /** Default Logging constructor */
    public Logging() { }
}

