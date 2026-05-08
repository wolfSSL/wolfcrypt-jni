/* MockNonCrtProvider.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jce.test;

import java.io.Closeable;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Test-only JCE Provider that registers degraded KeyFactory implementations
 * for RSA, RSASSA-PSS, EC, and DH.
 *
 * When installed at higher priority than wolfJCE, any code path that calls
 * {@code KeyFactory.getInstance("RSA"|"EC"|"DH")} without naming a provider
 * resolves to this Provider instead of wolfJCE. The returned keys are
 * intentionally degraded so subsequent wolfJCE operations on them fail in
 * an observable way:
 *
 *   - RSA: returns an RSAPrivateKey that does not implement RSAPrivateCrtKey,
 *          with null getEncoded().
 *   - EC:  returns ECPrivateKey/ECPublicKey with null getParams() and null
 *          getEncoded().
 *   - DH:  returns DHPrivateKey/DHPublicKey with zero values, null
 *          getParams(), and null getEncoded().
 *
 * Usage:
 * <pre>
 *   try (Closeable scope = MockNonCrtProvider.install()) {
 *       // ... assertions
 *   }
 * </pre>
 *
 * Decoding inside the mock uses an explicit
 * {@code KeyFactory.getInstance(alg, "wolfJCE")} lookup, which bypasses
 * Provider priority order and avoids any dependency on JDK-bundled
 * providers (e.g. SunRsaSign) that may not exist on Android.
 */
public final class MockNonCrtProvider extends Provider {

    private static final long serialVersionUID = 1L;

    public static final String NAME = "MockNonCrtProvider";
    static final String WOLFJCE_NAME = "wolfJCE";

    public MockNonCrtProvider() {
        super(NAME, 1.0,
            "Test-only Provider returning degraded KeyFactory output for " +
            "RSA, EC, and DH");
        put("KeyFactory.RSA", MockRsaKeyFactorySpi.class.getName());
        put("KeyFactory.RSASSA-PSS",
            MockRsaKeyFactorySpi.class.getName());
        put("KeyFactory.EC", MockEcKeyFactorySpi.class.getName());
        put("KeyFactory.DH", MockDhKeyFactorySpi.class.getName());
    }

    /**
     * Install the mock provider at priority 1 with wolfJCE re-added at the
     * bottom of the provider list. Returns a Closeable that restores the
     * provider list on close: removes the mock and reinstates wolfJCE at
     * priority 1.
     */
    public static Closeable install() {
        Security.removeProvider(WOLFJCE_NAME);
        Security.removeProvider(NAME);

        Security.insertProviderAt(new MockNonCrtProvider(), 1);
        Security.addProvider(new WolfCryptProvider());

        return new Closeable() {
            @Override
            public void close() {
                Security.removeProvider(NAME);
                Security.removeProvider(WOLFJCE_NAME);
                Security.insertProviderAt(new WolfCryptProvider(), 1);
            }
        };
    }

    /**
     * RSA KeyFactory that returns an RSAPrivateKey which does NOT implement
     * RSAPrivateCrtKey, with null getEncoded(). The PKCS#8 input is decoded
     * via an explicit by-name "wolfJCE" lookup, then unwrapped to drop the
     * CRT parameters and encoding.
     */
    public static final class MockRsaKeyFactorySpi extends KeyFactorySpi {

        @Override
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException {

            if (!(keySpec instanceof PKCS8EncodedKeySpec)) {
                throw new InvalidKeySpecException(
                    "Mock RSA SPI only supports PKCS8EncodedKeySpec");
            }

            try {
                /* Explicit-by-name lookup bypasses provider priority order
                 * and avoids re-entry into this mock. */
                KeyFactory delegate =
                    KeyFactory.getInstance("RSA", WOLFJCE_NAME);
                PrivateKey real = delegate.generatePrivate(keySpec);
                if (!(real instanceof RSAPrivateKey)) {
                    throw new InvalidKeySpecException(
                        "Delegate did not return RSAPrivateKey");
                }
                RSAPrivateKey rsa = (RSAPrivateKey) real;
                final BigInteger n = rsa.getModulus();
                final BigInteger d = rsa.getPrivateExponent();

                return new RSAPrivateKey() {
                    private static final long serialVersionUID = 1L;
                    @Override public BigInteger getModulus() { return n; }
                    @Override public BigInteger getPrivateExponent() {
                        return d;
                    }
                    @Override public String getAlgorithm() { return "RSA"; }
                    @Override public String getFormat() { return null; }
                    @Override public byte[] getEncoded() { return null; }
                };

            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeySpecException(e);
            } catch (NoSuchProviderException e) {
                throw new InvalidKeySpecException(e);
            }
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException {

            if (!(keySpec instanceof X509EncodedKeySpec)) {
                throw new InvalidKeySpecException(
                    "Mock RSA SPI only supports X509EncodedKeySpec");
            }

            try {
                KeyFactory delegate =
                    KeyFactory.getInstance("RSA", WOLFJCE_NAME);
                PublicKey real = delegate.generatePublic(keySpec);
                if (!(real instanceof RSAPublicKey)) {
                    throw new InvalidKeySpecException(
                        "Delegate did not return RSAPublicKey");
                }
                RSAPublicKey rsa = (RSAPublicKey) real;
                final BigInteger n = rsa.getModulus();
                final BigInteger e = rsa.getPublicExponent();

                return new RSAPublicKey() {
                    private static final long serialVersionUID = 1L;
                    @Override public BigInteger getModulus() { return n; }
                    @Override public BigInteger getPublicExponent() {
                        return e;
                    }
                    @Override public String getAlgorithm() { return "RSA"; }
                    @Override public String getFormat() { return null; }
                    @Override public byte[] getEncoded() { return null; }
                };

            } catch (NoSuchAlgorithmException nse) {
                throw new InvalidKeySpecException(nse);
            } catch (NoSuchProviderException nspe) {
                throw new InvalidKeySpecException(nspe);
            }
        }

        @Override
        protected <T extends KeySpec> T engineGetKeySpec(Key k,
            Class<T> spec) throws InvalidKeySpecException {

            throw new InvalidKeySpecException("not used");
        }

        @Override
        protected Key engineTranslateKey(Key k) {
            return k;
        }
    }

    /**
     * Returns degraded EC keys with no encoding and no parameters. wolfJCE
     * should never reach this SPI.
     */
    public static final class MockEcKeyFactorySpi extends KeyFactorySpi {

        @Override
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException {

            return new ECPrivateKey() {
                private static final long serialVersionUID = 1L;
                @Override public BigInteger getS() { return BigInteger.ONE; }
                @Override public ECParameterSpec getParams() { return null; }
                @Override public String getAlgorithm() { return "EC"; }
                @Override public String getFormat() { return null; }
                @Override public byte[] getEncoded() { return null; }
            };
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException {

            return new ECPublicKey() {
                private static final long serialVersionUID = 1L;
                @Override public ECPoint getW() {
                    return ECPoint.POINT_INFINITY;
                }
                @Override public ECParameterSpec getParams() { return null; }
                @Override public String getAlgorithm() { return "EC"; }
                @Override public String getFormat() { return null; }
                @Override public byte[] getEncoded() { return null; }
            };
        }

        @Override
        protected <T extends KeySpec> T engineGetKeySpec(Key k,
            Class<T> spec) throws InvalidKeySpecException {

            throw new InvalidKeySpecException("not used");
        }

        @Override
        protected Key engineTranslateKey(Key k) {
            return k;
        }
    }

    /**
     * Returns degraded DH keys with no parameters. wolfJCE should never
     * reach this SPI.
     */
    public static final class MockDhKeyFactorySpi extends KeyFactorySpi {

        @Override
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
                throws InvalidKeySpecException {

            return new DHPrivateKey() {
                private static final long serialVersionUID = 1L;
                @Override public BigInteger getX() { return BigInteger.ZERO; }
                @Override public DHParameterSpec getParams() { return null; }
                @Override public String getAlgorithm() { return "DH"; }
                @Override public String getFormat() { return null; }
                @Override public byte[] getEncoded() { return null; }
            };
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException {

            return new DHPublicKey() {
                private static final long serialVersionUID = 1L;
                @Override public BigInteger getY() { return BigInteger.ZERO; }
                @Override public DHParameterSpec getParams() { return null; }
                @Override public String getAlgorithm() { return "DH"; }
                @Override public String getFormat() { return null; }
                @Override public byte[] getEncoded() { return null; }
            };
        }

        @Override
        protected <T extends KeySpec> T engineGetKeySpec(Key k,
            Class<T> spec) throws InvalidKeySpecException {

            throw new InvalidKeySpecException("not used");
        }

        @Override
        protected Key engineTranslateKey(Key k) {
            return k;
        }
    }
}
