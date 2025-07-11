/* WolfCryptTestSuite.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

package com.wolfssl.wolfcrypt.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({
    AesTest.class,
    AesGcmTest.class,
    AsnTest.class,
    Des3Test.class,
    ChachaTest.class,
    Md5Test.class,
    ShaTest.class,
    Sha224Test.class,
    Sha256Test.class,
    Sha384Test.class,
    Sha512Test.class,
    Sha3Test.class,
    HmacTest.class,
    RngTest.class,
    RsaTest.class,
    DhTest.class,
    EccTest.class
})
public class WolfCryptTestSuite {

}
