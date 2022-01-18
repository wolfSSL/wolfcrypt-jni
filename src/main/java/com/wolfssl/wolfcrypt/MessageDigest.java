/* MessageDigest.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * Common API for Message Digests
 */
public abstract class MessageDigest extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /**
     * Initialize native structure
     */
    protected abstract void native_init();

    /**
     * Native update
     *
     * @param data input data
     * @param offset offset into input data
     * @param length length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_update(ByteBuffer data, int offset,
            int length);

    /**
     * Native update
     *
     * @param data input data
     * @param offset offset into input data
     * @param length length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_update(byte[] data, int offset, int length);

    /**
     * Native final - calculate final digest
     *
     * @param hash output buffer to place digest
     * @param offset offset into output buffer to write digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_final(ByteBuffer hash, int offset);

    /**
     * Native final - calculate final digest
     *
     * @param hash output buffer to place digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected abstract void native_final(byte[] hash);

    /**
     * Get digest size
     *
     * @return digest size
     */
    public abstract int digestSize();

    /**
     * Initialize object
     */
    public void init() {
        native_init();
        state = WolfCryptState.READY;
    }

    /**
     * Message digest update
     *
     * @param data input data
     * @param length length of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object not initialized
     */
    public void update(ByteBuffer data, int length) {
        if (state == WolfCryptState.READY) {
            length = Math.min(length, data.remaining());

            native_update(data, data.position(), length);
            data.position(data.position() + length);
        } else {
            throw new IllegalStateException(
                    "Object must be initialized before use");
        }
    }

    /**
     * Message digest update
     *
     * @param data input data, use all data.remaining()
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object not initialized
     */
    public void update(ByteBuffer data) {
        update(data, data.remaining());
    }

    /**
     * Message digest update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object not initialized
     */
    public void update(byte[] data, int offset, int len) {
        if (state == WolfCryptState.READY) {
            if (offset >= data.length || offset < 0 || len < 0)
                return;

            if (data.length - offset < len)
                len = data.length - offset;

            native_update(data, offset, len);
        } else {
            throw new IllegalStateException(
                    "Object must be initialized before use");
        }
    }

    /**
     * Message digest update
     *
     * @param data input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object not initialized
     */
    public void update(byte[] data, int len) {
        update(data, 0, len);
    }

    /**
     * Message digest update
     *
     * @param data input data, use all data.length
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object not initialized
     */
    public void update(byte[] data) {
        update(data, 0, data.length);
    }

    /**
     * Calculate message digest
     *
     * @param hash output message digest
     *
     * @throws WolfCryptException if native operation fails
     * @throws ShortBufferException if input buffer is too small
     * @throws IllegalStateException object not initialized
     */
    public void digest(ByteBuffer hash) throws ShortBufferException {
        if (state == WolfCryptState.READY) {
            if (hash.remaining() < digestSize())
                throw new ShortBufferException(
                        "Input buffer is too small for digest size");

            native_final(hash, hash.position());
            hash.position(hash.position() + digestSize());
        } else {
            throw new IllegalStateException(
                    "Object must be initialized before use");
        }
    }

    /**
     * Calculate message digest
     *
     * @param hash output message digest
     *
     * @throws WolfCryptException if native operation fails
     * @throws ShortBufferException if input buffer is too small
     * @throws IllegalStateException object not initialized
     */
    public void digest(byte[] hash) throws ShortBufferException {
        if (state == WolfCryptState.READY) {
            if (hash.length < digestSize())
                throw new ShortBufferException(
                        "Input buffer is too small for digest size");

            native_final(hash);
        } else {
            throw new IllegalStateException(
                    "Object must be initialized before use");
        }
    }

    /**
     * Calculate message digest
     *
     * @return resulting message digest
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException object not initialized
     */
    public byte[] digest() {
        if (state == WolfCryptState.READY) {
            byte[] hash = new byte[digestSize()];

            native_final(hash);

            return hash;
        } else {
            throw new IllegalStateException(
                    "Object must be initialized before use");
        }
    }

    @Override
    public void releaseNativeStruct() {

        /* reset state first, then free */
        state = WolfCryptState.UNINITIALIZED;
        setNativeStruct(NULL);
    }
}

