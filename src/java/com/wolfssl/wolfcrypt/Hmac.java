/* Hmac.java
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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

/**
 * Wrapper for the native WolfCrypt Hmac implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Hmac extends NativeStruct {
	
	public static final int MD5 = 0;
	public static final int SHA = 1;
	public static final int SHA256 = 2;
	public static final int SHA384 = 5;
	public static final int SHA512 = 4;
	public static final int BLAKE2b = 7;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
