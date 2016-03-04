/* Des3.java
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
 * Wrapper for the native WolfCrypt Des3 implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class Des3 extends NativeStruct {

	public static final int KEY_SIZE = 24;
	public static final int BLOCK_SIZE = 8;
	public static final int ENCRYPT_MODE = 0;
	public static final int DECRYPT_MODE = 1;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
