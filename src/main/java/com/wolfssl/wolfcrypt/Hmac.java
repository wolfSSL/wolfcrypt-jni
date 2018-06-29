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

import com.wolfssl.wolfcrypt.WolfCrypt;
import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt Hmac implementation.
 *
 * @author Moisés Guimarães
 * @version 2.0, March 2017
 */
public class Hmac extends NativeStruct {

    private enum hashType {
        typeMD5, typeSHA, typeSHA256, typeSHA384, typeSHA512, typeBLAKE2b;
    }

    public static final int MD5     = getHashCode(hashType.typeMD5);
    public static final int SHA     = getHashCode(hashType.typeSHA);
    public static final int SHA256  = getHashCode(hashType.typeSHA256);
    public static final int SHA384  = getHashCode(hashType.typeSHA384);
    public static final int SHA512  = getHashCode(hashType.typeSHA512);
    public static final int BLAKE2b = getHashCode(hashType.typeBLAKE2b);

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;
    private int type = -1;
    private byte[] key;

    public Hmac() {
    }

    public Hmac(int type, byte[] key) {
        setKey(type, key);
    }

    private native void wc_HmacSetKey(int type, byte[] key);

    private native void wc_HmacUpdate(byte data);

    private native void wc_HmacUpdate(byte[] data, int offset, int length);

    private native void wc_HmacUpdate(ByteBuffer data, int offset, int length);

    private native byte[] wc_HmacFinal();

    private native int wc_HmacSizeByType(int type);

    private native static int getCodeMd5();

    private native static int getCodeSha();

    private native static int getCodeSha256();

    private native static int getCodeSha384();

    private native static int getCodeSha512();

    private native static int getCodeBlake2b();

    protected native long mallocNativeStruct() throws OutOfMemoryError;

    public void setKey(int type, byte[] key) {
        wc_HmacSetKey(type, key);
        this.type = type;
        this.key = key;

        state = WolfCryptState.READY;
    }

    public void reset() {
        if (state == WolfCryptState.READY) {
            setKey(type, key);
        } else {
            throw new IllegalStateException(
                "No available key to perform the opperation.");
        }
    }

    public void update(byte data) {
        if (state == WolfCryptState.READY) {
            wc_HmacUpdate(data);
        } else {
            throw new IllegalStateException(
                "No available key to perform the opperation.");
        }
    }

    public void update(byte[] data) {
        if (state == WolfCryptState.READY) {
            wc_HmacUpdate(data, 0, data.length);
        } else {
            throw new IllegalStateException(
                "No available key to perform the opperation.");
        }
    }

    public void update(byte[] data, int offset, int length) {
        if (state == WolfCryptState.READY) {
            wc_HmacUpdate(data, offset, length);
        } else {
            throw new IllegalStateException(
                    "No available key to perform the opperation.");
        }
    }

    public void update(ByteBuffer data) {
        if (state == WolfCryptState.READY) {
            int offset = data.position();
            int length = data.remaining();

            wc_HmacUpdate(data, offset, length);

            data.position(offset + length);
        } else {
            throw new IllegalStateException(
                    "No available key to perform the opperation.");
        }
    }

    public byte[] doFinal() {
        if (state == WolfCryptState.READY) {
            return wc_HmacFinal();
        } else {
            throw new IllegalStateException(
                    "No available key to perform the opperation.");
        }
    }

    public byte[] doFinal(byte[] data) {
        if (state == WolfCryptState.READY) {
            update(data);
            return wc_HmacFinal();
        } else {
            throw new IllegalStateException(
                    "No available key to perform the opperation.");
        }
    }

    public String getAlgorithm() {
        if (state == WolfCryptState.READY) {

            if (type == MD5) {
                return "HmacMD5";
            } 
            else if (type == SHA256) {
                return "HmacSHA256";
            }
            else if (type == SHA384) {
                return "HmacSHA384";
            }
            else if (type == SHA512) {
                return "HmacSHA512";
            }
            else if (type == BLAKE2b) {
                return "HmacBLAKE2b";
            } else {
                return "";
            }

        } else {
            throw new IllegalStateException(
                "No available key to perform the opperation.");
        }
    }

    public int getMacLength() {
        if (state == WolfCryptState.READY) {
            return wc_HmacSizeByType(type);
        } else {
            throw new IllegalStateException(
                "No available key to perform the opperation.");
        }
    }

    private static int getHashCode(hashType hash) {
        switch (hash) {
            case typeMD5:
                return getCodeMd5();
            case typeSHA:
                return getCodeSha();
            case typeSHA256:
                return getCodeSha256();
            case typeSHA384:
                return getCodeSha384();
            case typeSHA512:
                return getCodeSha512();
            case typeBLAKE2b:
                return getCodeBlake2b();
            default:
                return WolfCrypt.FAILURE;
        }
    }
}
