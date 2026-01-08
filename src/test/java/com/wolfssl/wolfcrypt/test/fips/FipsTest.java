/* FipsTest.java
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

package com.wolfssl.wolfcrypt.test.fips;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Fips;

public class FipsTest {

    /* Rule to check if FIPS is enabled, skips tests if not.
     * Inherited by all FIPS test classes that extend FipsTest. */
    @Rule(order = Integer.MIN_VALUE + 2)
    public TestRule fipsEnabledRule = new TestRule() {
        @Override
        public Statement apply(final Statement base,
                               Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    Assume.assumeTrue("FIPS not enabled", Fips.enabled);
                    base.evaluate();
                }
            };
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        System.out.println("JNI FIPS Tests");
    }
}
