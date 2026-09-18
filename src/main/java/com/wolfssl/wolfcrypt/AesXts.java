/* AesXts.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Wrapper for the native wolfCrypt AES-XTS implementation (IEEE 1619,
 * NIST SP 800-38E).
 *
 * The key is two concatenated AES keys of equal size, data key then tweak
 * key: 32 bytes for AES-128-XTS, 64 bytes for AES-256-XTS, 48 bytes for
 * AES-192-XTS. The halves must differ. Each data unit is processed under a 16
 * byte tweak, must be at least one block and at most MAX_DATA_UNIT_SIZE bytes
 * (2^20 blocks, NIST SP 800-38E), and uses ciphertext stealing for a partial
 * last block, so output length equals input length.
 *
 * APIs: one-shot update() using the tweak from setKey()/setTweak(),
 * updateSector() using a 64-bit sector number as tweak, and streaming
 * streamInit()/streamUpdate()/streamFinal() when native wolfCrypt was built
 * with WOLFSSL_AESXTS_STREAM (isStreamEnabled()). All accept byte arrays or
 * direct ByteBuffers.
 *
 * @author wolfSSL Inc.
 */
public class AesXts extends NativeStruct {

    /** AES-128-XTS key size, two concatenated AES-128 keys */
    public static final int KEY_SIZE_128 = 32;
    /** AES-192-XTS key size, two concatenated AES-192 keys */
    public static final int KEY_SIZE_192 = 48;
    /** AES-256-XTS key size, two concatenated AES-256 keys */
    public static final int KEY_SIZE_256 = 64;
    /** AES block size */
    public static final int BLOCK_SIZE = 16;
    /** AES-XTS tweak size */
    public static final int TWEAK_SIZE = 16;
    /** Maximum data unit size in bytes, 2^20 blocks per NIST SP 800-38E */
    public static final int MAX_DATA_UNIT_SIZE = (1 << 20) * BLOCK_SIZE;

    /** AES encrypt mode */
    public static final int ENCRYPT_MODE = 0;
    /** AES decrypt mode */
    public static final int DECRYPT_MODE = 1;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /** Current operation mode */
    private int opmode;

    /** Tweak for update(), null until set */
    private byte[] tweak = null;

    /** True between streamInit() and streamFinal() */
    private boolean streamActive = false;

    /** Bytes passed to streamUpdate() since streamInit() */
    private long streamLength = 0;

    /* Native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_free();
    private native void native_set_key_internal(byte[] key, int opmode);
    private native int native_update_internal(int opmode, byte[] input,
        int offset, int length, byte[] output, int outputOffset, byte[] tweak);
    private native int native_update_internal(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset,
        byte[] tweak);
    private native int native_update_sector_internal(int opmode, byte[] input,
        int offset, int length, byte[] output, int outputOffset, long sector);
    private native int native_update_sector_internal(int opmode,
        ByteBuffer input, int offset, int length, ByteBuffer output,
        int outputOffset, long sector);
    private native void native_stream_init_internal(int opmode, byte[] tweak);
    private native int native_stream_update_internal(int opmode, byte[] input,
        int offset, int length, byte[] output, int outputOffset,
        boolean isFinal);
    private native int native_stream_update_internal(int opmode,
        ByteBuffer input, int offset, int length, ByteBuffer output,
        int outputOffset, boolean isFinal);

    /**
     * Malloc native AesXts structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails
     */
    protected long mallocNativeStruct()
        throws OutOfMemoryError {

        return mallocNativeStruct_internal();
    }

    /**
     * Set native AES-XTS key
     *
     * @param key concatenated AES-XTS key
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     */
    protected void native_set_key(byte[] key, int opmode) {

        synchronized (pointerLock) {
            native_set_key_internal(key, opmode);
        }
    }

    /**
     * Native one-shot encrypt/decrypt
     *
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     * @param input input array
     * @param offset offset into input
     * @param length number of bytes to process
     * @param output output array
     * @param outputOffset offset into output
     * @param tweak 16 byte tweak
     *
     * @return number of bytes stored in output
     */
    protected int native_update(int opmode, byte[] input, int offset,
        int length, byte[] output, int outputOffset, byte[] tweak) {

        synchronized (pointerLock) {
            return native_update_internal(opmode, input, offset, length,
                output, outputOffset, tweak);
        }
    }

    /**
     * Native one-shot encrypt/decrypt
     *
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     * @param input direct input buffer
     * @param offset offset into input
     * @param length number of bytes to process
     * @param output direct output buffer
     * @param outputOffset offset into output
     * @param tweak 16 byte tweak
     *
     * @return number of bytes stored in output
     */
    protected int native_update(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset,
        byte[] tweak) {

        synchronized (pointerLock) {
            return native_update_internal(opmode, input, offset, length,
                output, outputOffset, tweak);
        }
    }

    /**
     * Native sector encrypt/decrypt
     *
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     * @param input input array
     * @param offset offset into input
     * @param length number of bytes to process
     * @param output output array
     * @param outputOffset offset into output
     * @param sector sector number used as tweak
     *
     * @return number of bytes stored in output
     */
    protected int native_update_sector(int opmode, byte[] input, int offset,
        int length, byte[] output, int outputOffset, long sector) {

        synchronized (pointerLock) {
            return native_update_sector_internal(opmode, input, offset,
                length, output, outputOffset, sector);
        }
    }

    /**
     * Native sector encrypt/decrypt
     *
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     * @param input direct input buffer
     * @param offset offset into input
     * @param length number of bytes to process
     * @param output direct output buffer
     * @param outputOffset offset into output
     * @param sector sector number used as tweak
     *
     * @return number of bytes stored in output
     */
    protected int native_update_sector(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset,
        long sector) {

        synchronized (pointerLock) {
            return native_update_sector_internal(opmode, input, offset,
                length, output, outputOffset, sector);
        }
    }

    /**
     * Native stream init
     *
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     * @param tweak 16 byte tweak
     */
    protected void native_stream_init(int opmode, byte[] tweak) {

        synchronized (pointerLock) {
            native_stream_init_internal(opmode, tweak);
        }
    }

    /**
     * Native stream update/final
     *
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     * @param input input array
     * @param offset offset into input
     * @param length number of bytes to process
     * @param output output array
     * @param outputOffset offset into output
     * @param isFinal true to finalize the data unit
     *
     * @return number of bytes stored in output
     */
    protected int native_stream_update(int opmode, byte[] input, int offset,
        int length, byte[] output, int outputOffset, boolean isFinal) {

        synchronized (pointerLock) {
            return native_stream_update_internal(opmode, input, offset,
                length, output, outputOffset, isFinal);
        }
    }

    /**
     * Native stream update/final
     *
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     * @param input direct input buffer
     * @param offset offset into input
     * @param length number of bytes to process
     * @param output direct output buffer
     * @param outputOffset offset into output
     * @param isFinal true to finalize the data unit
     *
     * @return number of bytes stored in output
     */
    protected int native_stream_update(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset,
        boolean isFinal) {

        synchronized (pointerLock) {
            return native_stream_update_internal(opmode, input, offset,
                length, output, outputOffset, isFinal);
        }
    }

    private void checkStateAndInitialize() {
        synchronized (stateLock) {
            if (state == WolfCryptState.UNINITIALIZED ||
                state == WolfCryptState.RELEASED) {
                initNativeStruct();
                state = WolfCryptState.INITIALIZED;
            }
        }
    }

    private void throwIfKeyExists() throws IllegalStateException {
        synchronized (stateLock) {
            if (state == WolfCryptState.READY) {
                throw new IllegalStateException("Object already has a key");
            }
        }
    }

    private void throwIfKeyNotLoaded() throws IllegalStateException {
        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                throw new IllegalStateException(
                    "No key available to perform the operation");
            }
        }
    }

    private void throwIfNoTweak() throws IllegalStateException {
        synchronized (stateLock) {
            if (this.tweak == null) {
                throw new IllegalStateException(
                    "No AES-XTS tweak set, call setKey() with a tweak or " +
                    "setTweak() first");
            }
        }
    }

    private static void throwIfStreamNotEnabled() throws WolfCryptException {
        if (!isStreamEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    /* Finish or abandon the current data unit */
    private void endStream() {
        synchronized (stateLock) {
            this.streamActive = false;
        }
    }

    private void throwIfStreamNotActive() throws IllegalStateException {
        synchronized (stateLock) {
            if (!this.streamActive) {
                throw new IllegalStateException(
                    "AES-XTS stream not started, call streamInit() first");
            }
        }
    }

    private static void checkKey(byte[] key) throws WolfCryptException {

        if (key == null) {
            throw new WolfCryptException("AES-XTS key cannot be null");
        }

        if (key.length != KEY_SIZE_128 && key.length != KEY_SIZE_192 &&
            key.length != KEY_SIZE_256) {
            throw new WolfCryptException("AES-XTS key must be " +
                KEY_SIZE_128 + ", " + KEY_SIZE_192 + ", or " + KEY_SIZE_256 +
                " bytes (two concatenated AES keys), got " + key.length);
        }
    }

    private static void checkTweak(byte[] tweak) throws WolfCryptException {

        if (tweak == null) {
            throw new WolfCryptException("AES-XTS tweak cannot be null");
        }

        if (tweak.length != TWEAK_SIZE) {
            throw new WolfCryptException("AES-XTS tweak must be " +
                TWEAK_SIZE + " bytes, got " + tweak.length);
        }
    }

    private static void checkInput(byte[] input, int offset, int length)
        throws WolfCryptException {

        if (input == null) {
            throw new WolfCryptException("input buffer cannot be null");
        }

        if (offset < 0 || length < 0) {
            throw new WolfCryptException(
                "offset and length cannot be negative");
        }

        if (((long)offset + (long)length) > input.length) {
            throw new WolfCryptException(
                "offset + length exceeds input buffer length");
        }
    }

    private static void checkBuffers(byte[] input, int offset, int length,
        byte[] output, int outputOffset) throws WolfCryptException {

        checkInput(input, offset, length);

        if (output == null) {
            throw new WolfCryptException("output buffer cannot be null");
        }

        if (outputOffset < 0) {
            throw new WolfCryptException("outputOffset cannot be negative");
        }

        if (((long)outputOffset + (long)length) > output.length) {
            throw new WolfCryptException(
                "outputOffset + length exceeds output buffer length");
        }

        /* only exact in-place aliasing is supported */
        if ((input == output) && (offset != outputOffset) && (length > 0)) {
            throw new WolfCryptException(
                "in-place op requires equal input and output offsets");
        }
    }

    /**
     * Check ByteBuffers, all remaining input bytes must fit in output.
     *
     * @return number of bytes remaining in input
     */
    private static int checkByteBuffers(ByteBuffer input, ByteBuffer output)
        throws WolfCryptException {

        int inputLength;

        if (input == null || output == null) {
            throw new WolfCryptException("input/output buffer cannot be null");
        }

        if (!input.isDirect() || !output.isDirect()) {
            throw new WolfCryptException("input/output buffer must be direct");
        }

        if (output.isReadOnly()) {
            throw new WolfCryptException("output buffer is read-only");
        }

        inputLength = input.remaining();
        if (output.remaining() < inputLength) {
            throw new WolfCryptException("output buffer too small, need " +
                inputLength + " bytes, have " + output.remaining());
        }

        return inputLength;
    }

    private static void checkDataUnitLength(int length)
        throws WolfCryptException {

        if (length < BLOCK_SIZE) {
            throw new WolfCryptException("AES-XTS requires input length >= " +
                BLOCK_SIZE + " bytes, got " + length);
        }

        if (length > MAX_DATA_UNIT_SIZE) {
            throw new WolfCryptException("AES-XTS data unit length must " +
                "be <= " + MAX_DATA_UNIT_SIZE + " bytes, got " + length);
        }
    }

    /* Nothing is consumed on failure, the stream stays active */
    private void checkStreamDataUnitLength(int length)
        throws WolfCryptException {

        if ((this.streamLength + length) > MAX_DATA_UNIT_SIZE) {
            throw new WolfCryptException("AES-XTS data unit length must " +
                "be <= " + MAX_DATA_UNIT_SIZE + " bytes, stream has " +
                this.streamLength + " bytes, got " + length);
        }
    }

    private void clearTweak() {
        synchronized (stateLock) {
            if (this.tweak != null) {
                Arrays.fill(this.tweak, (byte)0);
                this.tweak = null;
            }
        }
    }

    /**
     * Create new AesXts object.
     *
     * @throws WolfCryptException if AES-XTS not compiled into native wolfSSL
     */
    public AesXts() {
        if (!FeatureDetect.AesXtsEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    /**
     * Check if the streaming API is available, requires native wolfSSL
     * built with WOLFSSL_AESXTS_STREAM.
     *
     * @return true if streamInit()/streamUpdate()/streamFinal() can be used
     */
    public static boolean isStreamEnabled() {
        return (FeatureDetect.AesXtsEnabled() &&
                FeatureDetect.AesXtsStreamEnabled());
    }

    /**
     * Set AES-XTS key, optional tweak, and operation direction.
     *
     * @param key two concatenated AES keys, 32/48/64 bytes, halves must differ
     * @param tweak 16 byte tweak for update(), or null to leave the current
     *        tweak unchanged
     * @param opmode ENCRYPT_MODE or DECRYPT_MODE
     *
     * @throws IllegalStateException if key already set
     * @throws WolfCryptException if key or tweak is invalid, or native
     *         rejects the key (identical halves where enforced, AES-192-XTS
     *         under FIPS)
     */
    public synchronized void setKey(byte[] key, byte[] tweak, int opmode)
        throws IllegalStateException, WolfCryptException {

        checkKey(key);

        if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE) {
            throw new WolfCryptException(
                "opmode must be ENCRYPT_MODE or DECRYPT_MODE");
        }

        if (tweak != null) {
            checkTweak(tweak);
        }

        throwIfKeyExists();
        checkStateAndInitialize();

        native_set_key(key, opmode);

        synchronized (stateLock) {
            this.opmode = opmode;
            if (tweak != null) {
                clearTweak();
                this.tweak = tweak.clone();
            }
            this.streamActive = false;
            state = WolfCryptState.READY;
        }
    }

    /**
     * Set the tweak used by subsequent update() calls.
     *
     * @param tweak 16 byte tweak
     *
     * @throws WolfCryptException if tweak is null or not 16 bytes
     */
    public synchronized void setTweak(byte[] tweak) throws WolfCryptException {

        checkTweak(tweak);

        synchronized (stateLock) {
            clearTweak();
            this.tweak = tweak.clone();
        }
    }

    /**
     * Get a copy of the tweak used by update().
     *
     * @return tweak copy, or null if none set
     */
    public synchronized byte[] getTweak() {

        synchronized (stateLock) {
            if (this.tweak == null) {
                return null;
            }
            return this.tweak.clone();
        }
    }

    /**
     * One-shot encrypt/decrypt of one data unit with the current tweak.
     *
     * @param input data unit, 16 to MAX_DATA_UNIT_SIZE bytes
     *
     * @return output, same length as input
     *
     * @throws IllegalStateException if key or tweak not set, or object
     *         released
     * @throws WolfCryptException if input is null, too short, or too long,
     *         or on native error
     */
    public synchronized byte[] update(byte[] input)
        throws IllegalStateException, WolfCryptException {

        if (input == null) {
            throw new WolfCryptException("input buffer cannot be null");
        }

        return update(input, 0, input.length);
    }

    /**
     * One-shot encrypt/decrypt of one data unit with the current tweak.
     *
     * @param input input array
     * @param offset offset into input
     * @param length number of bytes to process, 16 to MAX_DATA_UNIT_SIZE
     *
     * @return output, length bytes
     *
     * @throws IllegalStateException if key or tweak not set, or object
     *         released
     * @throws WolfCryptException if input is null, too short, or too long,
     *         or on native error
     */
    public synchronized byte[] update(byte[] input, int offset, int length)
        throws IllegalStateException, WolfCryptException {

        int outputLength;
        byte[] output;

        throwIfKeyNotLoaded();
        throwIfNoTweak();

        checkInput(input, offset, length);
        checkDataUnitLength(length);
        output = new byte[length];

        outputLength = native_update(opmode, input, offset, length,
            output, 0, this.tweak);

        if (outputLength != length) {
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * One-shot encrypt/decrypt of one data unit with the current tweak.
     * Input and output may be the same array with the same offset.
     *
     * @param input input array
     * @param offset offset into input
     * @param length number of bytes to process, 16 to MAX_DATA_UNIT_SIZE
     * @param output output array
     * @param outputOffset offset into output
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key or tweak not set, or object
     *         released
     * @throws WolfCryptException if arguments are invalid or on native
     *         error
     */
    public synchronized int update(byte[] input, int offset, int length,
        byte[] output, int outputOffset) throws IllegalStateException,
        WolfCryptException {

        throwIfKeyNotLoaded();
        throwIfNoTweak();

        checkBuffers(input, offset, length, output, outputOffset);
        checkDataUnitLength(length);

        return native_update(opmode, input, offset, length, output,
            outputOffset, this.tweak);
    }

    /**
     * One-shot encrypt/decrypt of one data unit with the current tweak,
     * processing all remaining input bytes and advancing both positions.
     *
     * @param input direct input buffer, 16 to MAX_DATA_UNIT_SIZE bytes
     *        remaining
     * @param output direct output buffer
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key or tweak not set, or object
     *         released
     * @throws WolfCryptException if buffers are null, not direct, or too
     *         small, input length is invalid, or on native error
     */
    public synchronized int update(ByteBuffer input, ByteBuffer output)
        throws IllegalStateException, WolfCryptException {

        int ret;
        int inputLength;

        throwIfKeyNotLoaded();
        throwIfNoTweak();

        inputLength = checkByteBuffers(input, output);
        checkDataUnitLength(inputLength);

        ret = native_update(opmode, input, input.position(), inputLength,
            output, output.position(), this.tweak);

        input.position(input.position() + ret);
        if (output != input) {
            output.position(output.position() + ret);
        }

        return ret;
    }

    /**
     * Encrypt/decrypt one data unit using a sector number as tweak. The
     * sector is a little-endian 64-bit value zero padded to 16 bytes, as
     * in wc_AesXtsEncryptSector(), and is treated as unsigned.
     *
     * @param input data unit, 16 to MAX_DATA_UNIT_SIZE bytes
     * @param sector sector number
     *
     * @return output, same length as input
     *
     * @throws IllegalStateException if key not set or object released
     * @throws WolfCryptException if input is null, too short, or too long,
     *         or on native error
     */
    public synchronized byte[] updateSector(byte[] input, long sector)
        throws IllegalStateException, WolfCryptException {

        int outputLength;
        byte[] output;

        if (input == null) {
            throw new WolfCryptException("input buffer cannot be null");
        }

        throwIfKeyNotLoaded();

        checkDataUnitLength(input.length);
        output = new byte[input.length];

        outputLength = native_update_sector(opmode, input, 0, input.length,
            output, 0, sector);

        if (outputLength != input.length) {
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * Encrypt/decrypt one data unit using a sector number as tweak. Input
     * and output may be the same array with the same offset.
     *
     * @param input input array
     * @param offset offset into input
     * @param length number of bytes to process, 16 to MAX_DATA_UNIT_SIZE
     * @param output output array
     * @param outputOffset offset into output
     * @param sector sector number
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key not set or object released
     * @throws WolfCryptException if arguments are invalid or on native
     *         error
     *
     * @see #updateSector(byte[], long)
     */
    public synchronized int updateSector(byte[] input, int offset,
        int length, byte[] output, int outputOffset, long sector)
        throws IllegalStateException, WolfCryptException {

        throwIfKeyNotLoaded();

        checkBuffers(input, offset, length, output, outputOffset);
        checkDataUnitLength(length);

        return native_update_sector(opmode, input, offset, length, output,
            outputOffset, sector);
    }

    /**
     * Encrypt/decrypt one data unit using a sector number as tweak,
     * processing all remaining input bytes and advancing both positions.
     *
     * @param input direct input buffer, 16 to MAX_DATA_UNIT_SIZE bytes
     *        remaining
     * @param output direct output buffer
     * @param sector sector number
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key not set or object released
     * @throws WolfCryptException if buffers are null, not direct, or too
     *         small, input length is invalid, or on native error
     *
     * @see #updateSector(byte[], long)
     */
    public synchronized int updateSector(ByteBuffer input, ByteBuffer output,
        long sector) throws IllegalStateException, WolfCryptException {

        int ret;
        int inputLength;

        throwIfKeyNotLoaded();

        inputLength = checkByteBuffers(input, output);
        checkDataUnitLength(inputLength);

        ret = native_update_sector(opmode, input, input.position(),
            inputLength, output, output.position(), sector);

        input.position(input.position() + ret);
        if (output != input) {
            output.position(output.position() + ret);
        }

        return ret;
    }

    /**
     * Start streaming one data unit under the given tweak. Follow with zero
     * or more streamUpdate() calls and exactly one streamFinal(), passing at
     * most MAX_DATA_UNIT_SIZE bytes in total. The tweak also replaces the one
     * used by update() and getTweak().
     *
     * @param tweak 16 byte tweak
     *
     * @throws IllegalStateException if key not set or object released
     * @throws WolfCryptException if streaming is not compiled in, tweak is
     *         invalid, or on native error
     */
    public synchronized void streamInit(byte[] tweak)
        throws IllegalStateException, WolfCryptException {

        throwIfStreamNotEnabled();
        throwIfKeyNotLoaded();
        checkTweak(tweak);

        native_stream_init(opmode, tweak);

        synchronized (stateLock) {
            clearTweak();
            this.tweak = tweak.clone();
            this.streamActive = true;
            this.streamLength = 0;
        }
    }

    /**
     * Stream encrypt/decrypt of whole blocks. Any trailing partial block,
     * together with at least one full block, must go to streamFinal().
     *
     * @param input non-zero multiple of 16 bytes
     *
     * @return output, same length as input
     *
     * @throws IllegalStateException if key not set, stream not started, or
     *         object released
     * @throws WolfCryptException if input is null, empty, not a multiple of
     *         16 bytes, or past the data unit limit, or on native error
     */
    public synchronized byte[] streamUpdate(byte[] input)
        throws IllegalStateException, WolfCryptException {

        byte[] output;
        int outputLength;

        if (input == null) {
            throw new WolfCryptException("input buffer cannot be null");
        }

        output = new byte[input.length];
        outputLength = streamUpdate(input, 0, input.length, output, 0);

        if (outputLength != input.length) {
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * Stream encrypt/decrypt of whole blocks. Any trailing partial block,
     * together with at least one full block, must go to streamFinal(). A
     * native error abandons the data unit, call streamInit() to start over.
     *
     * @param input input array
     * @param offset offset into input
     * @param length non-zero multiple of 16
     * @param output output array
     * @param outputOffset offset into output
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key not set, stream not started, or
     *         object released
     * @throws WolfCryptException if arguments are invalid, length is zero,
     *         not a multiple of 16, or past the data unit limit, or on
     *         native error
     */
    public synchronized int streamUpdate(byte[] input, int offset,
        int length, byte[] output, int outputOffset)
        throws IllegalStateException, WolfCryptException {

        int ret;

        throwIfStreamNotEnabled();
        throwIfKeyNotLoaded();
        throwIfStreamNotActive();

        checkBuffers(input, offset, length, output, outputOffset);
        if (length == 0 || (length % BLOCK_SIZE) != 0) {
            throw new WolfCryptException(
                "AES-XTS streamUpdate() length must be a non-zero " +
                "multiple of " + BLOCK_SIZE + " bytes, got " + length);
        }

        checkStreamDataUnitLength(length);

        try {
            ret = native_stream_update(opmode, input, offset, length,
                output, outputOffset, false);

        } catch (WolfCryptException e) {
            endStream();
            throw e;
        }

        this.streamLength += length;

        return ret;
    }

    /**
     * Stream encrypt/decrypt of whole blocks, processing all remaining
     * input bytes and advancing both positions. A native error abandons
     * the data unit, call streamInit() to start over.
     *
     * @param input direct input buffer, non-zero multiple of 16 bytes
     *        remaining
     * @param output direct output buffer
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key not set, stream not started, or
     *         object released
     * @throws WolfCryptException if buffers are null, not direct, or too
     *         small, input length is invalid, or on native error
     *
     * @see #streamUpdate(byte[])
     */
    public synchronized int streamUpdate(ByteBuffer input, ByteBuffer output)
        throws IllegalStateException, WolfCryptException {

        int ret;
        int inputLength;

        throwIfStreamNotEnabled();
        throwIfKeyNotLoaded();
        throwIfStreamNotActive();

        inputLength = checkByteBuffers(input, output);
        if (inputLength == 0 || (inputLength % BLOCK_SIZE) != 0) {
            throw new WolfCryptException(
                "AES-XTS streamUpdate() length must be a non-zero " +
                "multiple of " + BLOCK_SIZE + " bytes, got " + inputLength);
        }

        checkStreamDataUnitLength(inputLength);

        try {
            ret = native_stream_update(opmode, input, input.position(),
                inputLength, output, output.position(), false);

        } catch (WolfCryptException e) {
            endStream();
            throw e;
        }

        this.streamLength += inputLength;

        input.position(input.position() + ret);
        if (output != input) {
            output.position(output.position() + ret);
        }

        return ret;
    }

    /**
     * Finish streaming one data unit. Input may be null or empty, otherwise
     * at least one block, optionally ending in a partial block. The stream
     * is finished afterwards, call streamInit() for the next data unit.
     *
     * @param input remaining input, may be null or empty
     *
     * @return output, same length as input
     *
     * @throws IllegalStateException if key not set, stream not started, or
     *         object released
     * @throws WolfCryptException if input is 1 to 15 bytes or past the data
     *         unit limit, or on native error
     */
    public synchronized byte[] streamFinal(byte[] input)
        throws IllegalStateException, WolfCryptException {

        byte[] output;
        byte[] in = input;
        int outputLength;

        if (in == null) {
            in = new byte[0];
        }

        output = new byte[in.length];
        outputLength = streamFinal(in, 0, in.length, output, 0);

        if (outputLength != in.length) {
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * Finish streaming one data unit. Length may be zero, otherwise at
     * least 16, optionally ending in a partial block. The stream is
     * finished afterwards, also on a native error, call streamInit() for
     * the next data unit.
     *
     * @param input input array
     * @param offset offset into input
     * @param length zero or at least 16
     * @param output output array
     * @param outputOffset offset into output
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key not set, stream not started, or
     *         object released
     * @throws WolfCryptException if arguments are invalid, length is 1 to
     *         15 or past the data unit limit, or on native error
     */
    public synchronized int streamFinal(byte[] input, int offset,
        int length, byte[] output, int outputOffset)
        throws IllegalStateException, WolfCryptException {

        int ret;

        throwIfStreamNotEnabled();
        throwIfKeyNotLoaded();
        throwIfStreamNotActive();

        checkBuffers(input, offset, length, output, outputOffset);
        if (length != 0 && length < BLOCK_SIZE) {
            throw new WolfCryptException(
                "AES-XTS streamFinal() length must be 0 or >= " +
                BLOCK_SIZE + " bytes, got " + length);
        }

        checkStreamDataUnitLength(length);

        try {
            ret = native_stream_update(opmode, input, offset, length, output,
                outputOffset, true);

        } finally {
            endStream();
        }

        return ret;
    }

    /**
     * Finish streaming one data unit, processing all remaining input bytes
     * and advancing both positions. The stream is finished afterwards,
     * also on a native error.
     *
     * @param input direct input buffer, zero or at least 16 bytes remaining
     * @param output direct output buffer
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key not set, stream not started, or
     *         object released
     * @throws WolfCryptException if buffers are null, not direct, or too
     *         small, input length is 1 to 15 or past the data unit limit,
     *         or on native error
     *
     * @see #streamFinal(byte[])
     */
    public synchronized int streamFinal(ByteBuffer input, ByteBuffer output)
        throws IllegalStateException, WolfCryptException {

        int ret;
        int inputLength;

        throwIfStreamNotEnabled();
        throwIfKeyNotLoaded();
        throwIfStreamNotActive();

        inputLength = checkByteBuffers(input, output);
        if (inputLength != 0 && inputLength < BLOCK_SIZE) {
            throw new WolfCryptException(
                "AES-XTS streamFinal() length must be 0 or >= " +
                BLOCK_SIZE + " bytes, got " + inputLength);
        }

        checkStreamDataUnitLength(inputLength);

        try {
            ret = native_stream_update(opmode, input, input.position(),
                inputLength, output, output.position(), true);

        } finally {
            endStream();
        }

        input.position(input.position() + ret);
        if (output != input) {
            output.position(output.position() + ret);
        }

        return ret;
    }

    /**
     * Release native AES-XTS structure. The object may be used again after
     * calling setKey().
     */
    @Override
    public synchronized void releaseNativeStruct() {
        synchronized (stateLock) {
            if (state != WolfCryptState.RELEASED) {
                synchronized (pointerLock) {
                    if (getNativeStruct() != NativeStruct.NULL) {
                        native_free();
                    }
                    super.releaseNativeStruct();
                }
                clearTweak();
                this.streamActive = false;
                state = WolfCryptState.RELEASED;
            }
        }
    }
}
