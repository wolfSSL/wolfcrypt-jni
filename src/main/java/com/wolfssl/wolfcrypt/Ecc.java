/* Ecc.java
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

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.EllipticCurve;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECFieldFp;

/**
 * Wrapper for the native WolfCrypt ecc implementation.
 *
 * @author Moisés Guimarães
 * @version 2.0, February 2017
 */
public class Ecc extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	public Ecc() {
		init();
	}

	@Override
	public void releaseNativeStruct() {
		free();

		super.releaseNativeStruct();
	}

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	private native void wc_ecc_init();

	private native void wc_ecc_free();

	private native void wc_ecc_make_key(Rng rng, int size);

	private native void wc_ecc_make_key_ex(Rng rng, int size, String curveName);

	private native void wc_ecc_check_key();

	private native byte[] wc_ecc_shared_secret(Ecc pubKey);

	private native void wc_ecc_import_private(byte[] privKey, byte[] x963Key,
                                              String curveName);

	private native byte[] wc_ecc_export_private();

	private native void wc_ecc_import_x963(byte[] key);

	private native byte[] wc_ecc_export_x963();

	private native void wc_EccPrivateKeyDecode(byte[] key);

	private native byte[] wc_EccKeyToDer();

	private native void wc_EccPublicKeyDecode(byte[] key);

	private native byte[] wc_EccPublicKeyToDer();

	private native byte[] wc_ecc_sign_hash(byte[] hash, Rng rng);

	private native boolean wc_ecc_verify_hash(byte[] hash, byte[] signature);

    private static native int wc_ecc_get_curve_size_from_name(String name);

    private native byte[] wc_ecc_private_key_to_pkcs8();

    private static native String wc_ecc_get_curve_name_from_id(int curve_id);

    private static native int wc_ecc_get_curve_id_from_params(int fieldSize,
            byte[] prime, byte[] Af, byte[] Bf, byte[] order,
            byte[] Gx, byte[] Gy, int cofactor);

	protected void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			wc_ecc_init();
			state = WolfCryptState.INITIALIZED;
		} else {
			throw new IllegalStateException(
					"Native resources already initialized.");
		}
	}

	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_ecc_free();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

	public void makeKey(Rng rng, int size) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ecc_make_key(rng, size);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

    public void makeKeyOnCurve(Rng rng, int size, String curveName) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_ecc_make_key_ex(rng, size, curveName.toUpperCase());
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

	public void checkKey() {
		if (state == WolfCryptState.READY) {
			wc_ecc_check_key();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void importPrivate(byte[] privKey, byte[] x963Key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ecc_import_private(privKey, x963Key, null);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public void importPrivateOnCurve(byte[] privKey, byte[] x963Key,
            String curveName) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ecc_import_private(privKey, x963Key, curveName);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public byte[] exportPrivate() {
		if (state == WolfCryptState.READY) {
			return wc_ecc_export_private();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void importX963(byte[] key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ecc_import_x963(key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public byte[] exportX963() {
		if (state == WolfCryptState.READY) {
			return wc_ecc_export_x963();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void privateKeyDecode(byte[] key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_EccPrivateKeyDecode(key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public byte[] privateKeyEncode() {
		if (state == WolfCryptState.READY) {
			return wc_EccKeyToDer();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void publicKeyDecode(byte[] key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_EccPublicKeyDecode(key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public byte[] publicKeyEncode() {
		if (state == WolfCryptState.READY) {
			return wc_EccPublicKeyToDer();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] makeSharedSecret(Ecc pubKey) {
		if (state == WolfCryptState.READY) {
			return wc_ecc_shared_secret(pubKey);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] sign(byte[] hash, Rng rng) {
		byte[] signature = new byte[0];

		if (state == WolfCryptState.READY) {
			signature = wc_ecc_sign_hash(hash, rng);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}

		return signature;
	}

	public boolean verify(byte[] hash, byte[] signature) {
		boolean result = false;

		if (state == WolfCryptState.READY) {
			result = wc_ecc_verify_hash(hash, signature);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}

		return result;
	}

    public static int getCurveSizeFromName(String curveName) {
        /* Ecc object doesn't need to be initialied before call */
        return wc_ecc_get_curve_size_from_name(curveName);
    }

    public byte[] privateKeyEncodePKCS8() {
        if (state == WolfCryptState.READY) {
            return wc_ecc_private_key_to_pkcs8();
        } else {
            throw new IllegalStateException(
                    "No available key to perform the operation.");
        }
    }

    public static String getCurveName(ECParameterSpec spec)
        throws InvalidAlgorithmParameterException
    {
        int curve_id;

        /* Ecc object doesn't need to be initialied before call */
        if (!(spec.getCurve().getField() instanceof ECFieldFp)) {
            throw new InvalidAlgorithmParameterException(
                "Currently only ECFieldFp fields supported");
        }
        ECFieldFp field = (ECFieldFp)spec.getCurve().getField();
        EllipticCurve curve = spec.getCurve();

        curve_id = wc_ecc_get_curve_id_from_params(
                    field.getFieldSize(),
                    field.getP().toByteArray(),
                    curve.getA().toByteArray(),
                    curve.getB().toByteArray(),
                    spec.getOrder().toByteArray(),
                    spec.getGenerator().getAffineX().toByteArray(),
                    spec.getGenerator().getAffineY().toByteArray(),
                    spec.getCofactor());

        return wc_ecc_get_curve_name_from_id(curve_id);
    }
}

