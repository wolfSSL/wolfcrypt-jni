/* WolfCryptKeyFactory.java
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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

package com.wolfssl.provider.jce;

import java.security.KeyFactorySpi;
import java.security.KeyPair;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * wolfCrypt JCE KeyFactory wrapper class
 *
 * @author wolfSSL
 * @version 1.0, March 2017
 */
public class WolfCryptKeyFactory extends KeyFactorySpi {

    private WolfCryptKeyFactory() {
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key,
        Class<T> keySpec) throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException {
        return null;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
        } finally {
            super.finalize();
        }
    }

    public static final class wcKeyFactory extends WolfCryptKeyFactory {
        public wcKeyFactory() {
            super();
        }
    }
}

