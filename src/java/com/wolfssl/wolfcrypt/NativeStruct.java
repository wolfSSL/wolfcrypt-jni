/* NativeStruct.java
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

/**
 * Wrapper for the native WolfCrypt structs.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public abstract class NativeStruct extends WolfObject {

	public static final long NULL = 0;

	protected NativeStruct() {
		setNativeStruct(mallocNativeStruct());
	}

	/* points to the internal native structure */
	private long pointer;

	public long getNativeStruct() {
		return this.pointer;
	}

	protected void setNativeStruct(long nativeStruct) {
		if (this.pointer != NULL)
			xfree(this.pointer);

		this.pointer = nativeStruct;
	}

	/**
	 * Releases the host data stored in a NativeStruct.
	 *
	 * This method provides a way to release host data without depending on the
	 * garbage collector to get around to releasing it. Derived objects whose
	 * native data structures have their own free functions, should be override
	 * this method to call that function.
	 */
	public void releaseNativeStruct() {
		setNativeStruct(NULL);
	}

	protected abstract long mallocNativeStruct() throws OutOfMemoryError;

	private native void xfree(long pointer);

	@Override
	protected void finalize() throws Throwable {
		setNativeStruct(NULL);

		super.finalize();
	}
}
