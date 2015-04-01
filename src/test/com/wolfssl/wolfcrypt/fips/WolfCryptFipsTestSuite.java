package com.wolfssl.wolfcrypt.fips;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ AesFipsTest.class, Des3FipsTest.class, ShaFipsTest.class,
		Sha256FipsTest.class, Sha384FipsTest.class, Sha512FipsTest.class,
		HmacFipsTest.class, RngFipsTest.class, RsaFipsTest.class })
public class WolfCryptFipsTestSuite {

}
