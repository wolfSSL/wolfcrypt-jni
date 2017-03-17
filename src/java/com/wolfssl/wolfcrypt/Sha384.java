/* Sha384.java
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

import java.nio.ByteBuffer;

import javax.crypto.ShortBufferException;

/**
 * Wrapper for the native WolfCrypt Sha384 implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Sha384 extends NativeStruct {

	public static final int TYPE = 5; /* hash type unique */
	public static final int DIGEST_SIZE = 48;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	protected native long mallocNativeStruct() throws OutOfMemoryError;

    /* native wrappers called by public functions below */
	private native void initSha384();
	private native void sha384Update(ByteBuffer data, int position, int len);
	private native void sha384Update(byte[] data, int offset, int len);
	private native void sha384Final(ByteBuffer hash, int position);
	private native void sha384Final(byte[] hash);

    public void init() {

        if (getNativeStruct() == NULL)
            throw new IllegalStateException("Object has been freed");

        initSha384();
        state = WolfCryptState.INITIALIZED;
    }

    public void update(ByteBuffer data, int len)
        throws ShortBufferException {

        if (getNativeStruct() == NULL)
            throw new IllegalStateException("Object has been freed");

        if (state == WolfCryptState.INITIALIZED) {

            if ((data.remaining() - data.position()) < len)
                throw new ShortBufferException(
                    "Input length is larger than remaining ByteBuffer size");

            sha384Update(data, data.position(), len);

            data.position(data.position() + len);

        } else {
            throw new IllegalStateException(
                "Object must be initialized before use");
        }
    }

    public void update(byte[] data, int len)
        throws ShortBufferException {

        if (getNativeStruct() == NULL)
           throw new IllegalStateException("Object has been freed");

        if (state == WolfCryptState.INITIALIZED) {

            if (data.length < len)
                throw new ShortBufferException(
                    "Input length is larger than input buffer size");

            sha384Update(data, 0, len);

        } else {
            throw new IllegalStateException(
                "Object must be initialized before use");
        }
    }

    public void update(byte[] data, int offset, int len)
        throws ShortBufferException {

        if (getNativeStruct() == NULL)
           throw new IllegalStateException("Object has been freed");

        if (state == WolfCryptState.INITIALIZED) {

            if (data.length - offset < len)
                throw new ShortBufferException(
                    "Input length is larger than remaining input buffer size");

            sha384Update(data, offset, len);

        } else {
            throw new IllegalStateException(
                "Object must be initialized before use");
        }
    }

    public void digest(ByteBuffer hash)
        throws ShortBufferException {

        if (getNativeStruct() == NULL)
           throw new IllegalStateException("Object has been freed");

        if (state == WolfCryptState.INITIALIZED) {

            if ((hash.remaining() - hash.position()) < Sha384.DIGEST_SIZE)
                throw new ShortBufferException(
                    "Input buffer is too small for digest size");

            sha384Final(hash, hash.position());

            hash.position(hash.position() + Sha384.DIGEST_SIZE);

        } else {
            throw new IllegalStateException(
                "Object must be initialized before use");
        }
    }

    public void digest(byte[] hash)
        throws ShortBufferException {

        if (getNativeStruct() == NULL)
           throw new IllegalStateException("Object has been freed");

        if (state == WolfCryptState.INITIALIZED) {

            if (hash.length < Sha384.DIGEST_SIZE)
                throw new ShortBufferException(
                    "Input buffer is too small for digest size");

            sha384Final(hash);

        } else {
            throw new IllegalStateException(
                "Object must be initialized before use");
        }
    }
}

