/* Rsa.java
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt Rsa implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Rsa extends NativeStruct {

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	public native void decodeRawPublicKey(ByteBuffer n, long nSize,
			ByteBuffer e, long eSize);

	public native void exportRawPublicKey(ByteBuffer n, ByteBuffer e);

	public native void makeKey(int size, long e, Rng rng);
}
