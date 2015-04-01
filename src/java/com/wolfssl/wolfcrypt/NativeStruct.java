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

	protected abstract long mallocNativeStruct() throws OutOfMemoryError;

	private native void xfree(long pointer);

	@Override
	protected void finalize() throws Throwable {
		setNativeStruct(NULL);

		super.finalize();
	}
}
